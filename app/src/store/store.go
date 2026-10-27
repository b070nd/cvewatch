// Package store keeps all monitor state in one JSON file: seen vulnerabilities,
// per-environment fix status and feed cursors.
//
// A file is plenty for thousands of records and stays diffable. Switch to
// SQLite if this ever needs concurrent writers or millions of rows.
// A lock file makes sure only one process writes at a time. The Store
// itself is not safe for concurrent use inside one process.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"time"

	"cvewatch/src/fsx"
	"cvewatch/src/model"
)

type data struct {
	Vulns    map[string]*model.Vulnerability `json:"vulns"`
	Findings map[string]*model.Finding       `json:"findings"`
	Feeds    map[string]model.FeedState      `json:"feeds"`
}

type Store struct {
	path  string
	lock  *os.File
	d     data
	byKey map[string]string // any id or alias -> primary vulnerability id
}

// Open locks and loads dir/state.json. It fails fast if another process holds the lock.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(filepath.Join(dir, "state.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, errors.New("another cvewatch process is using the data directory")
	}

	s := &Store{path: filepath.Join(dir, "state.json"), lock: lock, byKey: map[string]string{}}
	raw, err := os.ReadFile(s.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		s.Close()
		return nil, err
	default:
		if err := json.Unmarshal(raw, &s.d); err != nil {
			s.Close()
			return nil, fmt.Errorf("%s is corrupt: %w", s.path, err)
		}
	}
	if s.d.Vulns == nil {
		s.d.Vulns = map[string]*model.Vulnerability{}
	}
	if s.d.Findings == nil {
		s.d.Findings = map[string]*model.Finding{}
	}
	if s.d.Feeds == nil {
		s.d.Feeds = map[string]model.FeedState{}
	}
	for _, v := range s.d.Vulns {
		s.index(v)
	}
	return s, nil
}

func (s *Store) Close() error { return s.lock.Close() } // closing releases the flock

func (s *Store) Save() error {
	raw, err := json.MarshalIndent(s.d, "", "  ")
	if err != nil {
		return err
	}
	return fsx.WriteAtomic(s.path, raw)
}

func (s *Store) index(v *model.Vulnerability) {
	for _, k := range v.Keys() {
		s.byKey[k] = v.ID
	}
}

// Lookup returns the known vulnerability matching any of the keys, or nil.
func (s *Store) Lookup(keys []string) *model.Vulnerability {
	for _, k := range keys {
		if id, ok := s.byKey[k]; ok {
			return s.d.Vulns[id]
		}
	}
	return nil
}

func (s *Store) Vuln(id string) *model.Vulnerability { return s.d.Vulns[id] }

func (s *Store) AddVuln(v *model.Vulnerability) {
	s.d.Vulns[v.ID] = v
	s.index(v)
}

// AddAliases makes extra ids resolve to an existing vulnerability.
func (s *Store) AddAliases(v *model.Vulnerability, ids []string) {
	for _, id := range ids {
		if _, known := s.byKey[id]; !known {
			v.Aliases = append(v.Aliases, id)
		}
	}
	s.index(v)
}

// AddFinding inserts a finding unless it already exists, so reruns never
// reset a status. It reports whether the finding is new.
func (s *Store) AddFinding(f model.Finding) bool {
	if _, ok := s.d.Findings[f.Key()]; ok {
		return false
	}
	s.d.Findings[f.Key()] = &f
	return true
}

// Findings returns copies ordered by project, vulnerability, then promotion order of the env.
func (s *Store) Findings() []model.Finding {
	out := make([]model.Finding, 0, len(s.d.Findings))
	for _, f := range s.d.Findings {
		out = append(out, *f)
	}
	slices.SortFunc(out, func(a, b model.Finding) int {
		if a.Project != b.Project {
			return cmpStr(a.Project, b.Project)
		}
		if a.VulnID != b.VulnID {
			return cmpStr(a.VulnID, b.VulnID)
		}
		return slices.Index(model.AllEnvs, a.Env) - slices.Index(model.AllEnvs, b.Env)
	})
	return out
}

func cmpStr(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// Relevant returns vulnerabilities that have at least one finding, ordered by id.
func (s *Store) Relevant() []*model.Vulnerability {
	seen := map[string]bool{}
	var out []*model.Vulnerability
	for _, f := range s.d.Findings {
		if v := s.d.Vulns[f.VulnID]; v != nil && !seen[v.ID] {
			seen[v.ID] = true
			out = append(out, v)
		}
	}
	slices.SortFunc(out, func(a, b *model.Vulnerability) int { return cmpStr(a.ID, b.ID) })
	return out
}

// Prune forgets vulnerabilities that never produced a finding and were first
// seen before the cutoff. Findings and what they refer to are kept for good.
// It returns how many records were dropped.
func (s *Store) Prune(before time.Time) int {
	keep := map[string]bool{}
	for _, f := range s.d.Findings {
		keep[f.VulnID] = true
	}
	n := 0
	for id, v := range s.d.Vulns {
		if keep[id] || !v.FirstSeen.Before(before) {
			continue
		}
		for _, k := range v.Keys() {
			delete(s.byKey, k)
		}
		delete(s.d.Vulns, id)
		n++
	}
	return n
}

func (s *Store) FindingsOf(vulnID string) []model.Finding {
	return slices.DeleteFunc(s.Findings(), func(f model.Finding) bool { return f.VulnID != vulnID })
}

// SetStatus updates findings of one vulnerability in a project; an empty env
// means every environment. It returns how many findings changed.
func (s *Store) SetStatus(vulnID, project string, env model.Env, st model.Status, note string, now time.Time) (int, error) {
	n := 0
	for _, f := range s.d.Findings {
		if f.VulnID != vulnID || f.Project != project || (env != "" && f.Env != env) {
			continue
		}
		f.Status, f.Note, f.Updated = st, note, now
		n++
	}
	if n == 0 {
		return 0, fmt.Errorf("no finding for %s in project %q env %q", vulnID, project, env)
	}
	return n, nil
}

// MarkAlerted records that a finding reached the notifier.
func (s *Store) MarkAlerted(key string, at time.Time) {
	if f := s.d.Findings[key]; f != nil {
		f.AlertedAt = at
	}
}

func (s *Store) Feed(id string) model.FeedState       { return s.d.Feeds[id] }
func (s *Store) SetFeed(id string, f model.FeedState) { s.d.Feeds[id] = f }
