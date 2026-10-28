package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"

	_ "modernc.org/sqlite" // pure-Go driver "sqlite": no cgo, cross-compiles everywhere

	"github.com/b070nd/cvewatch/app/src/host"
	"github.com/b070nd/cvewatch/app/src/ledger"
	"github.com/b070nd/cvewatch/app/src/model"
)

const schema = `
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS vulns(id TEXT PRIMARY KEY, json TEXT);
CREATE TABLE IF NOT EXISTS findings(key TEXT PRIMARY KEY, json TEXT);
CREATE TABLE IF NOT EXISTS feeds(id TEXT PRIMARY KEY, json TEXT);
CREATE TABLE IF NOT EXISTS digests(channel TEXT PRIMARY KEY, at TEXT);
INSERT OR IGNORE INTO meta(key, value) VALUES ('rev', '0');
`

// sqlite keeps State in a SQLite database. Unlike the file adapter it takes
// no lock: several processes may hold the same database open, SQLite
// serializes their writes, and the compare-and-swap on meta.rev rejects a
// writer whose view is stale.
type sqlite struct {
	db  *sql.DB
	rev int64 // rev as loaded, or as last saved
}

// OpenSQLite opens (creating if needed) the database at path. The parent
// directory and the database file are owner-only.
func OpenSQLite(path string) (Storage, error) {
	if err := host.MkdirPrivate(filepath.Dir(path)); err != nil {
		return nil, err
	}
	// Create the file ourselves so it is 0600; SQLite gives its -wal and -shm
	// files the same mode as the database.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	f.Close()

	// Pragmas live in the DSN so every pooled connection gets them.
	q := url.Values{"_pragma": {
		"journal_mode(WAL)", "busy_timeout(5000)", "foreign_keys(0)", "synchronous(NORMAL)",
	}}
	db, err := sql.Open("sqlite", path+"?"+q.Encode()) // a plain path is opened verbatim, so Windows paths need no URI escaping
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // one writer per handle; other handles and processes go through SQLite's lock
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &sqlite{db: db}, nil
}

func (s *sqlite) Load() (st ledger.State, err error) {
	tx, err := s.db.Begin() // one transaction, so every table comes from the same snapshot
	if err != nil {
		return st, err
	}
	defer tx.Rollback()

	meta := map[string]string{}
	if err := scan(tx, `SELECT key, value FROM meta`, func(k, v string) error { meta[k] = v; return nil }); err != nil {
		return st, err
	}
	if v := meta["rev"]; v != "" {
		if st.Rev, err = strconv.ParseInt(v, 10, 64); err != nil {
			return ledger.State{}, fmt.Errorf("meta rev %q: %w", v, err)
		}
	}
	if v := meta["schema_version"]; v != "" {
		if st.SchemaVersion, err = strconv.Atoi(v); err != nil {
			return ledger.State{}, fmt.Errorf("meta schema_version %q: %w", v, err)
		}
	}

	st.Vulns = map[string]*model.Vulnerability{}
	st.Findings = map[string]*model.Finding{}
	st.Feeds = map[string]model.FeedState{}
	st.Digests = map[string]time.Time{}
	err = errors.Join(
		scanJSON(tx, `SELECT id, json FROM vulns`, st.Vulns),
		scanJSON(tx, `SELECT key, json FROM findings`, st.Findings),
		scanJSON(tx, `SELECT id, json FROM feeds`, st.Feeds),
		scan(tx, `SELECT channel, at FROM digests`, func(ch, at string) error {
			t, err := time.Parse(time.RFC3339Nano, at)
			st.Digests[ch] = t
			return err
		}),
	)
	if err != nil {
		return ledger.State{}, err
	}
	s.rev = st.Rev
	return st, nil
}

func (s *sqlite) Save(st ledger.State) error {
	next := s.rev + 1
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() // no-op after Commit

	// The first statement is the write, so the transaction takes SQLite's write
	// lock before it looks at anything and cannot be working from a stale snapshot.
	res, err := tx.Exec(`UPDATE meta SET value = ? WHERE key = 'rev' AND value = ?`,
		strconv.FormatInt(next, 10), strconv.FormatInt(s.rev, 10))
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n != 1 {
		var stored int64
		tx.QueryRow(`SELECT CAST(value AS INTEGER) FROM meta WHERE key = 'rev'`).Scan(&stored)
		return conflict(s.rev, stored)
	}
	if _, err := tx.Exec(`INSERT OR REPLACE INTO meta(key, value) VALUES ('schema_version', ?)`,
		strconv.Itoa(st.SchemaVersion)); err != nil {
		return err
	}
	for _, t := range []string{"vulns", "findings", "feeds", "digests"} {
		if _, err := tx.Exec(`DELETE FROM ` + t); err != nil {
			return err
		}
	}
	if err := insertJSON(tx, `INSERT INTO vulns(id, json) VALUES (?, ?)`, st.Vulns); err != nil {
		return err
	}
	if err := insertJSON(tx, `INSERT INTO findings(key, json) VALUES (?, ?)`, st.Findings); err != nil {
		return err
	}
	if err := insertJSON(tx, `INSERT INTO feeds(id, json) VALUES (?, ?)`, st.Feeds); err != nil {
		return err
	}
	digests := map[string]string{}
	for ch, at := range st.Digests {
		digests[ch] = at.Format(time.RFC3339Nano)
	}
	if err := insertAll(tx, `INSERT INTO digests(channel, at) VALUES (?, ?)`, digests, func(v string) (string, error) { return v, nil }); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.rev = next
	return nil
}

func (s *sqlite) Close() error { return s.db.Close() }

// scan runs a two-column query.
func scan(tx *sql.Tx, query string, each func(a, b string) error) error {
	rows, err := tx.Query(query)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var a, b string
		if err := rows.Scan(&a, &b); err != nil {
			return err
		}
		if err := each(a, b); err != nil {
			return err
		}
	}
	return rows.Err()
}

// scanJSON decodes a (key, json) query into m.
func scanJSON[V any](tx *sql.Tx, query string, m map[string]V) error {
	return scan(tx, query, func(k, raw string) error {
		var v V
		if err := json.Unmarshal([]byte(raw), &v); err != nil {
			return fmt.Errorf("%s: %w", k, err)
		}
		m[k] = v
		return nil
	})
}

func insertJSON[V any](tx *sql.Tx, query string, m map[string]V) error {
	return insertAll(tx, query, m, func(v V) (string, error) {
		raw, err := json.Marshal(v)
		return string(raw), err
	})
}

func insertAll[V any](tx *sql.Tx, query string, m map[string]V, enc func(V) (string, error)) error {
	stmt, err := tx.Prepare(query)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for k, v := range m {
		val, err := enc(v)
		if err != nil {
			return fmt.Errorf("%s: %w", k, err)
		}
		if _, err := stmt.Exec(k, val); err != nil {
			return err
		}
	}
	return nil
}
