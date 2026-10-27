// Package store persists the ledger's State. Callers depend on Storage, so
// where the data lives is one decision: a JSON file in production, memory in
// tests, and a database later if several people ever write at once.
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

// ErrBusy means another cvewatch process holds the data.
var ErrBusy = errors.New("another cvewatch process is using the data directory")

// file keeps State as dir/state.json under an exclusive lock on dir/state.lock.
//
// One JSON file stays diffable and is plenty for thousands of records.
// Switch to a database adapter if this ever needs concurrent writers.
type file struct {
	path   string
	unlock func() error
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

func (f *file) Load() (ledger.State, error) {
	var s ledger.State
	raw, err := os.ReadFile(f.path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return s, fmt.Errorf("%s is corrupt: %w", f.path, err)
	}
	return s, nil
}

func (f *file) Save(s ledger.State) error {
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return host.WriteFileAtomic(f.path, raw)
}

func (f *file) Close() error { return f.unlock() }

// memory is the second adapter, for tests. It round-trips through JSON so it
// has the same serialization behaviour as the file adapter.
type memory struct{ raw []byte }

func NewMemory() Storage { return &memory{} }

func (m *memory) Load() (ledger.State, error) {
	var s ledger.State
	if m.raw == nil {
		return s, nil
	}
	return s, json.Unmarshal(m.raw, &s)
}

func (m *memory) Save(s ledger.State) (err error) {
	m.raw, err = json.Marshal(s)
	return err
}

func (m *memory) Close() error { return nil }
