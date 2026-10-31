// Package audit keeps an append-only, tamper-evident record of what the
// monitor detected, alerted and changed, and who changed it.
//
// Each line is JSON and carries the SHA-256 of the previous line, so editing
// or deleting a line in the middle is detected by Verify. Truncating the end
// or rewriting the whole file is not; ship the log to a system you do not
// administer if you need that guarantee.
package audit

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/b070nd/cvewatch/app/src/host"
)

// Event is one audit record. Actor is a person or system name; with
// personal data in mind it defaults to the OS user and can be overridden by
// CVEWATCH_ACTOR (use a pseudonym such as a team name).
type Event struct {
	Time    time.Time `json:"time"`
	Actor   string    `json:"actor"`
	Action  string    `json:"action"` // detected | alerted | status | assign | evidence | inventory | unified | digest | project | settings | revalidate
	Vuln    string    `json:"vuln,omitempty"`
	Project string    `json:"project,omitempty"`
	To      string    `json:"to,omitempty"` // the new name of a project rename; Project holds the old one
	Env     string    `json:"env,omitempty"`
	Status  string    `json:"status,omitempty"`
	Note    string    `json:"note,omitempty"`
	URL     string    `json:"url,omitempty"` // link attached as evidence
	Prev    string    `json:"prev"`          // hash of the previous line; empty on the first
}

// Log is a file in the data directory. A nil *Log discards events, which
// keeps callers free of nil checks in tests.
type Log struct{ path string }

func Open(dir string) *Log { return &Log{path: filepath.Join(dir, "audit.log")} }

// Actor names who is acting, for status changes.
func Actor() string {
	if a := os.Getenv("CVEWATCH_ACTOR"); a != "" {
		return a
	}
	return host.CurrentUser()
}

// Append adds events in order. The caller must hold the store lock, which
// makes this the only writer.
func (l *Log) Append(events ...Event) error {
	if l == nil || len(events) == 0 {
		return nil
	}
	prev, err := lastHash(l.path)
	if err != nil {
		return err
	}
	f, err := host.OpenAppend(l.path)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, e := range events {
		e.Prev = prev
		line, err := json.Marshal(e)
		if err != nil {
			return err
		}
		if _, err := f.Write(append(line, '\n')); err != nil {
			return err
		}
		prev = hash(line)
	}
	return f.Sync()
}

// Verify walks the chain and returns the number of records, or the first
// line whose link is broken.
func (l *Log) Verify() (int, error) {
	f, err := os.Open(l.path)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	prev, n := "", 0
	for sc.Scan() {
		n++
		var e Event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return n, fmt.Errorf("line %d: not valid JSON", n)
		}
		if e.Prev != prev {
			return n, fmt.Errorf("line %d: chain broken, a record before it was changed or removed", n)
		}
		prev = hash(sc.Bytes())
	}
	return n, sc.Err()
}

func hash(line []byte) string {
	sum := sha256.Sum256(line)
	return hex.EncodeToString(sum[:])
}

// lastHash returns the hash of the final line, or "" for a new file.
func lastHash(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	raw = bytes.TrimRight(raw, "\n")
	if len(raw) == 0 {
		return "", nil
	}
	if i := bytes.LastIndexByte(raw, '\n'); i >= 0 {
		raw = raw[i+1:]
	}
	return hash(raw), nil
}

// Events returns every record in order after checking the chain. On a broken
// chain it returns the records read so far together with the error, so
// callers can show what they have and say it is not trustworthy.
func (l *Log) Events() ([]Event, error) {
	f, err := os.Open(l.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	var out []Event
	prev := ""
	for sc.Scan() {
		var e Event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return out, fmt.Errorf("line %d: not valid JSON", len(out)+1)
		}
		if e.Prev != prev {
			return out, fmt.Errorf("line %d: chain broken, a record before it was changed or removed", len(out)+1)
		}
		prev = hash(sc.Bytes())
		out = append(out, e)
	}
	return out, sc.Err()
}

// Rename is a project rename found in the log. At is the position of its
// record: a record before it that names From belongs to the project now
// called To.
type Rename struct {
	From, To string
	At       int
}

// oldRenameNote reads the target name from the note of a rename recorded
// before the To field existed.
var oldRenameNote = regexp.MustCompile(`^renamed project to (.+): \d+ findings moved`)

// Renames lists the project renames of a log, oldest first. A rename that was
// recorded and then failed (a "project-failed" record with the same time and
// project follows it) did not happen and is left out. The log is never
// changed; renames are read from it.
func Renames(events []Event) []Rename {
	var out []Rename
	for i, e := range events {
		if e.Action != "project" || e.Project == "" {
			continue
		}
		to := e.To
		if to == "" {
			if m := oldRenameNote.FindStringSubmatch(e.Note); m != nil {
				to = m[1]
			}
		}
		if to == "" || to == e.Project || strings.Contains(e.Project, ",") {
			continue
		}
		failed := false
		for _, f := range events[i+1:] {
			if f.Action == "project-failed" && f.Project == e.Project && f.Time.Equal(e.Time) {
				failed = true
				break
			}
		}
		if !failed {
			out = append(out, Rename{From: e.Project, To: to, At: i})
		}
	}
	return out
}

// CurrentName follows the renames after position at from a name used there to
// the name the project has now (A to B to C). A project that was never renamed
// after that point keeps its name, so a later project that reuses an old name
// does not inherit the history of the renamed one.
func CurrentName(renames []Rename, name string, at int) string {
	for _, r := range renames {
		if r.At > at && r.From == name {
			name, at = r.To, r.At
		}
	}
	return name
}
