// Package store persists the ledger's State. Callers depend on Storage, so
// where the data lives is one decision: a JSON file (default), a SQLite
// database, or memory in tests. Open picks the backend by name.
//
// Concurrency. Every adapter is optimistic: Load remembers State.Rev, and Save
// fails with ErrConflict if the stored Rev has moved on, otherwise it stores
// the state with Rev+1. The adapter sets Rev itself; callers need not touch
// it. After ErrConflict, Load again, redo the change and Save. The file adapter
// also holds an exclusive lock, so only one process has it open at a time. The
// SQLite adapter has no such lock: several processes may open the same
// database, and SQLite's own locking plus the Rev check keep them honest.
//
// Known ceiling. Save replaces the whole State (SQLite: delete and re-insert
// every row in one transaction), so its cost grows with the total data, not
// with the change, and two writers touching different records still conflict.
// That is fine for thousands of records. The upgrade path is row-level
// writes: have Ledger report which vulns, findings, feeds and digests changed
// and have the SQLite adapter upsert just those, keeping the Rev check on the
// transaction. Storage stays as it is.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/b070nd/cvewatch/app/src/host"
	"github.com/b070nd/cvewatch/app/src/ledger"
)

// Storage loads and saves the whole State. Save must be atomic: a crash
// leaves either the old or the new state, never a mix. Close releases any
// exclusive hold on the data.
type Storage interface {
	Load() (ledger.State, error)
	Save(ledger.State) error
	Close() error
}

// ErrConflict means the stored state moved on since it was loaded. Load again,
// redo the change and Save. Test with errors.Is.
var ErrConflict = errors.New("state changed since it was loaded")

// ErrBusy means another cvewatch process holds the data.
var ErrBusy = errors.New("another cvewatch process is using the data directory")

// Open returns the adapter for a backend name: "" or "file" keeps
// dir/state.json, "sqlite" keeps dir/state.db.
func Open(backend, dir string) (Storage, error) {
	switch backend {
	case "", "file":
		return OpenFile(dir)
	case "sqlite":
		return OpenSQLite(filepath.Join(dir, "state.db"))
	}
	return nil, fmt.Errorf("unknown storage backend %q: valid backends are \"file\" and \"sqlite\"", backend)
}

// storedRev reads just the rev out of serialized state; empty means a new
// store, and data written before rev existed counts as 0.
func storedRev(raw []byte) (int64, error) {
	if raw == nil {
		return 0, nil
	}
	var r struct {
		Rev int64 `json:"rev"`
	}
	err := json.Unmarshal(raw, &r)
	return r.Rev, err
}

func conflict(loaded, stored int64) error {
	return fmt.Errorf("%w (loaded rev %d, stored rev %d)", ErrConflict, loaded, stored)
}

// file keeps State as dir/state.json under an exclusive lock on dir/state.lock.
//
// One JSON file stays diffable and is plenty for thousands of records. The
// lock already serializes processes, so the rev check only catches a file
// changed behind the lock's back.
type file struct {
	path   string
	unlock func() error
	rev    int64 // rev as loaded, or as last saved
}

// OpenFile locks the directory and returns the file adapter. It fails fast if
// another process holds the lock, so two writers can never corrupt each other.
func OpenFile(dir string) (Storage, error) {
	if err := host.MkdirPrivate(dir); err != nil {
		return nil, err
	}
	unlock, err := host.Lock(filepath.Join(dir, "state.lock"))
	if errors.Is(err, host.ErrLocked) {
		return nil, ErrBusy
	}
	if err != nil {
		return nil, err
	}
	return &file{path: filepath.Join(dir, "state.json"), unlock: unlock}, nil
}

func (f *file) read() ([]byte, error) {
	raw, err := os.ReadFile(f.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return raw, err
}

func (f *file) Load() (ledger.State, error) {
	var s ledger.State
	raw, err := f.read()
	if err != nil || raw == nil {
		f.rev = 0
		return s, err
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return ledger.State{}, fmt.Errorf("%s is corrupt: %w", f.path, err)
	}
	f.rev = s.Rev
	return s, nil
}

func (f *file) Save(s ledger.State) error {
	raw, err := f.read()
	if err != nil {
		return err
	}
	stored, err := storedRev(raw)
	if err != nil {
		return fmt.Errorf("%s is corrupt: %w", f.path, err)
	}
	if stored != f.rev {
		return conflict(f.rev, stored)
	}
	s.Rev = f.rev + 1
	out, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := host.WriteFileAtomic(f.path, out); err != nil {
		return err
	}
	f.rev = s.Rev
	return nil
}

func (f *file) Close() error { return f.unlock() }

// memory is for tests. It round-trips through JSON so it has the same
// serialization behaviour as the file adapter. One value is one store, so it
// cannot be shared and never sees a conflict from outside.
type memory struct {
	raw []byte
	rev int64
}

func NewMemory() Storage { return &memory{} }

func (m *memory) Load() (ledger.State, error) {
	var s ledger.State
	if m.raw == nil {
		m.rev = 0
		return s, nil
	}
	if err := json.Unmarshal(m.raw, &s); err != nil {
		return ledger.State{}, err
	}
	m.rev = s.Rev
	return s, nil
}

func (m *memory) Save(s ledger.State) error {
	stored, err := storedRev(m.raw)
	if err != nil {
		return err
	}
	if stored != m.rev {
		return conflict(m.rev, stored)
	}
	s.Rev = m.rev + 1
	raw, err := json.Marshal(s)
	if err != nil {
		return err
	}
	m.raw, m.rev = raw, s.Rev
	return nil
}

func (m *memory) Close() error { return nil }
