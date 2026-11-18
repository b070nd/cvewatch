package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // pure-Go driver "pgx"

	"github.com/b070nd/cvewatch/app/src/ledger"
	"github.com/b070nd/cvewatch/app/src/model"
)

// pgSchema is the PostgreSQL schema cvewatch keeps its tables in, so a
// database shared with other applications stays tidy.
const pgSchema = "cvewatch"

// pgTimeout bounds every statement: a database that does not answer must not
// hang a cycle.
const pgTimeout = 2 * time.Minute

var pgName = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)

// postgres keeps State in PostgreSQL: one row per vulnerability, finding and
// feed (as JSON, so they can be queried with SQL), and the rest of the state
// in meta. Like the SQLite adapter it takes no lock: several processes may use
// the database, and the compare-and-swap on meta.rev rejects a writer whose
// view is stale. Unlike it, a save writes only the rows that changed since
// this handle loaded or saved them.
type postgres struct {
	db     *sql.DB
	schema string
	rev    int64
	// seen is a digest of every row as loaded or last saved, per table, so a
	// save can tell what changed. nil until the first Load.
	seen map[string]map[string][sha256.Size]byte
}

// OpenPostgres connects to the database of the DSN (a postgres:// URL or a
// key=value string) and creates the cvewatch schema and tables if needed.
func OpenPostgres(dsn string) (Storage, error) { return openPostgres(dsn, pgSchema) }

func openPostgres(dsn, schema string) (*postgres, error) {
	if dsn == "" {
		return nil, errors.New("the postgres backend needs a DSN: set the environment variable named by storage.dsn_env (default CVEWATCH_DSN)")
	}
	if !pgName.MatchString(schema) {
		return nil, fmt.Errorf("invalid schema name %q", schema)
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, errors.New("postgres: the DSN cannot be parsed") // the DSN may hold a password: never echo it
	}
	db.SetMaxOpenConns(2)
	p := &postgres{db: db, schema: schema}
	ctx, cancel := context.WithTimeout(context.Background(), pgTimeout)
	defer cancel()
	ddl := `CREATE SCHEMA IF NOT EXISTS ` + schema + `;
CREATE TABLE IF NOT EXISTS ` + p.t("meta") + `(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS ` + p.t("vulns") + `(id TEXT PRIMARY KEY, json JSONB NOT NULL);
CREATE TABLE IF NOT EXISTS ` + p.t("findings") + `(key TEXT PRIMARY KEY, json JSONB NOT NULL);
CREATE TABLE IF NOT EXISTS ` + p.t("feeds") + `(id TEXT PRIMARY KEY, json JSONB NOT NULL);
INSERT INTO ` + p.t("meta") + `(key, value) VALUES ('rev', '0') ON CONFLICT (key) DO NOTHING;`
	if _, err := db.ExecContext(ctx, ddl); err != nil {
		db.Close()
		return nil, fmt.Errorf("postgres: %w", scrub(err))
	}
	return p, nil
}

// t is a table name with its schema.
func (p *postgres) t(name string) string { return p.schema + "." + name }

// scrub keeps connection details out of an error: drivers may quote the DSN.
func scrub(err error) error {
	var pgErr interface{ SQLState() string }
	if errors.As(err, &pgErr) {
		return err // a server error names the problem, not the connection
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return errors.New("the database did not answer in time")
	}
	return errors.New("cannot reach the database (check the DSN, and that the server runs and accepts this user)")
}

// rest is the part of State that is not kept row by row.
type rest struct {
	SchemaVersion int                            `json:"schema_version"`
	Digests       map[string]time.Time           `json:"digests,omitempty"`
	Judged        *model.Judging                 `json:"judged,omitempty"`
	Updated       map[string]time.Time           `json:"updated,omitempty"`
	Cycles        []model.CycleRecord            `json:"cycles,omitempty"`
	Sources       map[string]model.SourceHealth  `json:"sources,omitempty"`
	Channels      map[string]model.ChannelHealth `json:"channels,omitempty"`
	Heartbeat     *model.Heartbeat               `json:"heartbeat,omitempty"`
}

func (p *postgres) Load() (st ledger.State, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), pgTimeout)
	defer cancel()
	// One repeatable-read transaction, so every table comes from the same snapshot.
	tx, err := p.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return st, scrub(err)
	}
	defer tx.Rollback()

	meta := map[string]string{}
	if err := pgScan(ctx, tx, `SELECT key, value FROM `+p.t("meta"), func(k, v string) error { meta[k] = v; return nil }); err != nil {
		return st, scrub(err)
	}
	if st.Rev, err = strconv.ParseInt(meta["rev"], 10, 64); err != nil {
		return ledger.State{}, fmt.Errorf("meta rev %q: %w", meta["rev"], err)
	}
	var r rest
	if raw := meta["rest"]; raw != "" {
		if err := json.Unmarshal([]byte(raw), &r); err != nil {
			return ledger.State{}, fmt.Errorf("meta rest: %w", err)
		}
	}
	st.SchemaVersion, st.Digests, st.Judged, st.Updated = r.SchemaVersion, r.Digests, r.Judged, r.Updated
	st.Cycles, st.Sources, st.Channels, st.Heartbeat = r.Cycles, r.Sources, r.Channels, r.Heartbeat
	st.Vulns = map[string]*model.Vulnerability{}
	st.Findings = map[string]*model.Finding{}
	st.Feeds = map[string]model.FeedState{}

	seen := map[string]map[string][sha256.Size]byte{}
	err = errors.Join(
		pgRows(ctx, tx, p.t("vulns"), "id", st.Vulns),
		pgRows(ctx, tx, p.t("findings"), "key", st.Findings),
		pgRows(ctx, tx, p.t("feeds"), "id", st.Feeds),
	)
	if err != nil {
		return ledger.State{}, scrub(err)
	}
	// Digest what a save of this very state would write, so the next Save
	// sends only what the caller changed.
	seen["vulns"], _ = digests(st.Vulns)
	seen["findings"], _ = digests(st.Findings)
	seen["feeds"], _ = digests(st.Feeds)
	p.rev, p.seen = st.Rev, seen
	return st, nil
}

func (p *postgres) Save(st ledger.State) error {
	ctx, cancel := context.WithTimeout(context.Background(), pgTimeout)
	defer cancel()
	next := p.rev + 1
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return scrub(err)
	}
	defer tx.Rollback() // no-op after Commit

	// The first statement is the compare-and-swap. It locks the rev row, so a
	// second writer waits here and then sees that the rev moved on.
	res, err := tx.ExecContext(ctx, `UPDATE `+p.t("meta")+` SET value = $1 WHERE key = 'rev' AND value = $2`,
		strconv.FormatInt(next, 10), strconv.FormatInt(p.rev, 10))
	if err != nil {
		return scrub(err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return scrub(err)
	} else if n != 1 {
		var stored int64
		tx.QueryRowContext(ctx, `SELECT value::bigint FROM `+p.t("meta")+` WHERE key = 'rev'`).Scan(&stored)
		return conflict(p.rev, stored)
	}

	raw, err := json.Marshal(rest{SchemaVersion: st.SchemaVersion, Digests: st.Digests, Judged: st.Judged, Updated: st.Updated,
		Cycles: st.Cycles, Sources: st.Sources, Channels: st.Channels, Heartbeat: st.Heartbeat})
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO `+p.t("meta")+`(key, value) VALUES ('rest', $1)
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`, string(raw)); err != nil {
		return scrub(err)
	}

	seen := map[string]map[string][sha256.Size]byte{}
	if seen["vulns"], err = pgSync(ctx, tx, p.t("vulns"), "id", st.Vulns, p.seen["vulns"]); err != nil {
		return err
	}
	if seen["findings"], err = pgSync(ctx, tx, p.t("findings"), "key", st.Findings, p.seen["findings"]); err != nil {
		return err
	}
	if seen["feeds"], err = pgSync(ctx, tx, p.t("feeds"), "id", st.Feeds, p.seen["feeds"]); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return scrub(err)
	}
	p.rev, p.seen = next, seen
	return nil
}

func (p *postgres) Close() error { return p.db.Close() }

// digests encodes every value and returns the digest of each encoding.
func digests[V any](m map[string]V) (map[string][sha256.Size]byte, map[string][]byte) {
	sums, raws := make(map[string][sha256.Size]byte, len(m)), make(map[string][]byte, len(m))
	for k, v := range m {
		raw, err := json.Marshal(v)
		if err != nil {
			continue // cannot happen for these types; a missing digest only means the row is written again
		}
		sums[k], raws[k] = sha256.Sum256(raw), raw
	}
	return sums, raws
}

// pgBatch is how many rows one statement carries.
const pgBatch = 2000

// pgSync makes a table hold exactly m: rows whose encoding differs from what
// was seen are written, rows that are gone are deleted. Without a seen map
// (a store never loaded through this handle) the table is replaced. Keys are
// handled in sorted order, so two savers always lock rows in the same order.
func pgSync[V any](ctx context.Context, tx *sql.Tx, table, key string, m map[string]V, seen map[string][sha256.Size]byte) (map[string][sha256.Size]byte, error) {
	sums, raws := digests(m)
	if len(sums) != len(m) {
		return nil, fmt.Errorf("%s: a row could not be encoded", table)
	}
	var changed, gone []string
	if seen == nil {
		if _, err := tx.ExecContext(ctx, `DELETE FROM `+table); err != nil {
			return nil, scrub(err)
		}
	}
	for k := range m {
		if old, ok := seen[k]; !ok || old != sums[k] {
			changed = append(changed, k)
		}
	}
	for k := range seen {
		if _, ok := m[k]; !ok {
			gone = append(gone, k)
		}
	}
	slices.Sort(changed)
	slices.Sort(gone)
	for part := range slices.Chunk(changed, pgBatch) {
		vals := make([]string, len(part))
		for i, k := range part {
			vals[i] = string(raws[k])
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO `+table+`(`+key+`, json)
SELECT k, v::jsonb FROM unnest($1::text[], $2::text[]) AS t(k, v)
ON CONFLICT (`+key+`) DO UPDATE SET json = EXCLUDED.json`, part, vals); err != nil {
			return nil, scrub(err)
		}
	}
	for part := range slices.Chunk(gone, pgBatch) {
		if _, err := tx.ExecContext(ctx, `DELETE FROM `+table+` WHERE `+key+` = ANY($1::text[])`, part); err != nil {
			return nil, scrub(err)
		}
	}
	return sums, nil
}

func pgScan(ctx context.Context, tx *sql.Tx, query string, each func(a, b string) error) error {
	rows, err := tx.QueryContext(ctx, query)
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

// pgRows decodes a (key, json) table into m.
func pgRows[V any](ctx context.Context, tx *sql.Tx, table, key string, m map[string]V) error {
	return pgScan(ctx, tx, `SELECT `+key+`, json::text FROM `+table, func(k, raw string) error {
		var v V
		if err := json.Unmarshal([]byte(raw), &v); err != nil {
			return fmt.Errorf("%s %s: %w", table, k, err)
		}
		m[k] = v
		return nil
	})
}
