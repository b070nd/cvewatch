package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/b070nd/cvewatch/app/src/host"
	"github.com/b070nd/cvewatch/app/src/ledger"
	"github.com/b070nd/cvewatch/app/src/model"
)

// adapter opens one store; reopen closes nothing and opens the same data again.
type adapter struct {
	name string
	open func(t *testing.T) (st Storage, reopen func() Storage)
}

func adapters() []adapter {
	return []adapter{
		{"file", func(t *testing.T) (Storage, func() Storage) {
			dir := t.TempDir()
			open := func() Storage {
				st, err := OpenFile(dir)
				if err != nil {
					t.Fatal(err)
				}
				return st
			}
			return open(), open
		}},
		{"memory", func(t *testing.T) (Storage, func() Storage) {
			m := NewMemory()
			return m, func() Storage { return m }
		}},
		{"sqlite", func(t *testing.T) (Storage, func() Storage) {
			path := filepath.Join(t.TempDir(), "sub", "state.db")
			open := func() Storage {
				st, err := OpenSQLite(path)
				if err != nil {
					t.Fatal(err)
				}
				return st
			}
			return open(), open
		}},
	}
}

func load(t *testing.T, st Storage) ledger.State {
	t.Helper()
	s, err := st.Load()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestContract is what every adapter must meet.
func TestContract(t *testing.T) {
	for _, a := range adapters() {
		t.Run(a.name, func(t *testing.T) {
			t.Run("round trip", func(t *testing.T) { roundTrip(t, a) })
			t.Run("rev", func(t *testing.T) { revs(t, a) })
		})
	}
}

func roundTrip(t *testing.T, a adapter) {
	st, reopen := a.open(t)
	s := load(t, st)
	if s.Rev != 0 {
		t.Fatalf("new store must have rev 0, got %d", s.Rev)
	}
	now := time.Date(2026, 3, 4, 5, 6, 7, 123456789, time.UTC)
	l := ledger.New(s)
	v := l.Create(model.Item{Title: "PHP bug", URL: "https://a.test/1", IDs: []string{"CVE-2026-1", "GHSA-AAAA-BBBB-CCCC"}}, now, []string{"php"})
	l.AddFinding(model.Finding{VulnID: v.ID, Project: "shop", Env: model.EnvProd, Status: model.StatusOpen})
	if _, err := l.SetStatus(v.ID, "shop", model.EnvProd, model.StatusFixed, "patched", now); err != nil {
		t.Fatal(err)
	}
	want := l.State()
	want.Digests = map[string]time.Time{"slack": now}
	if want.SchemaVersion == 0 {
		t.Fatal("ledger must stamp a schema version")
	}
	if err := st.Save(want); err != nil {
		t.Fatal(err)
	}
	st.Close()

	st = reopen()
	defer st.Close()
	s = load(t, st)
	if s.Rev != 1 || s.SchemaVersion != want.SchemaVersion {
		t.Fatalf("rev %d schema %d, want 1 and %d", s.Rev, s.SchemaVersion, want.SchemaVersion)
	}
	if got := s.Digests["slack"]; !got.Equal(now) || len(s.Digests) != 1 {
		t.Fatalf("digests lost: %v", s.Digests)
	}
	re := ledger.New(s)
	if re.Lookup([]string{"GHSA-AAAA-BBBB-CCCC"}) == nil {
		t.Fatal("alias must resolve after reload")
	}
	if got := re.Findings()[0]; got.Status != model.StatusFixed || got.Note != "patched" {
		t.Fatalf("status lost: %+v", got)
	}
	a1, _ := json.Marshal(want.Vulns)
	b1, _ := json.Marshal(s.Vulns)
	if string(a1) != string(b1) {
		t.Fatalf("vulns differ:\n%s\n%s", a1, b1)
	}
}

func revs(t *testing.T, a adapter) {
	st, reopen := a.open(t)
	s := load(t, st)
	// The adapter owns Rev: the caller's value, right or wrong, is ignored,
	// and saving without reloading in between is fine.
	stale := s
	for want := int64(1); want <= 3; want++ {
		stale.Rev = 99
		if err := st.Save(stale); err != nil {
			t.Fatalf("save %d: %v", want, err)
		}
		if got := load(t, st).Rev; got != want {
			t.Fatalf("after save %d rev is %d", want, got)
		}
	}
	st.Close()
	st = reopen()
	defer st.Close()
	s = load(t, st)
	if s.Rev != 3 {
		t.Fatalf("rev must persist, got %d", s.Rev)
	}
	if err := st.Save(s); err != nil {
		t.Fatal(err)
	}
	if got := load(t, st).Rev; got != 4 {
		t.Fatalf("rev %d, want 4", got)
	}
}

func TestFileLocked(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenFile(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := OpenFile(dir); !errors.Is(err, ErrBusy) {
		t.Fatalf("second open must fail while locked, got %v", err)
	}
}

func TestFileConflict(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenFile(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	s := load(t, st)
	if err := st.Save(s); err != nil { // rev 1
		t.Fatal(err)
	}
	s = load(t, st)

	// The flock keeps other cvewatch processes out, so play one that got
	// around it: someone rewrites the file with a higher rev.
	path := filepath.Join(dir, "state.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":1,"rev":7,"vulns":{},"findings":{},"feeds":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := st.Save(s); !errors.Is(err, ErrConflict) {
		t.Fatalf("want ErrConflict, got %v", err)
	}
	if raw, _ := os.ReadFile(path); !strings.Contains(string(raw), `"rev":7`) {
		t.Fatalf("conflicting save must not touch the file: %s", raw)
	}
	s = load(t, st) // reload, then it works again
	if s.Rev != 7 {
		t.Fatalf("rev %d, want 7", s.Rev)
	}
	if err := st.Save(s); err != nil {
		t.Fatal(err)
	}
	if got := load(t, st).Rev; got != 8 {
		t.Fatalf("rev %d, want 8", got)
	}
}

func TestSQLiteConflict(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	open := func() Storage {
		st, err := OpenSQLite(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { st.Close() })
		return st
	}
	a, b := open(), open() // no lock: both may be open at once
	sa, sb := load(t, a), load(t, b)

	la := ledger.New(sa)
	la.Create(model.Item{Title: "from a", IDs: []string{"CVE-2026-10"}}, time.Now(), nil)
	if err := a.Save(la.State()); err != nil {
		t.Fatal(err)
	}
	lb := ledger.New(sb)
	lb.Create(model.Item{Title: "from b", IDs: []string{"CVE-2026-20"}}, time.Now(), nil)
	err := b.Save(lb.State())
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("want ErrConflict, got %v", err)
	}

	// Nothing of b's write got in; reload, redo, save.
	sb = load(t, b)
	if sb.Rev != 1 || sb.Vulns["CVE-2026-10"] == nil || sb.Vulns["CVE-2026-20"] != nil {
		t.Fatalf("b must see a's state only: rev %d vulns %v", sb.Rev, sb.Vulns)
	}
	lb = ledger.New(sb)
	lb.Create(model.Item{Title: "from b", IDs: []string{"CVE-2026-20"}}, time.Now(), nil)
	if err := b.Save(lb.State()); err != nil {
		t.Fatal(err)
	}
	// And now a is the stale one.
	if err := a.Save(la.State()); !errors.Is(err, ErrConflict) {
		t.Fatalf("a is stale now, got %v", err)
	}
	if got := load(t, a); got.Rev != 2 || len(got.Vulns) != 2 {
		t.Fatalf("rev %d vulns %d, want 2 and 2", got.Rev, len(got.Vulns))
	}
}

func TestMemoryNotShared(t *testing.T) {
	a, b := NewMemory(), NewMemory()
	if err := a.Save(load(t, a)); err != nil {
		t.Fatal(err)
	}
	if got := load(t, b); got.Rev != 0 {
		t.Fatalf("separate memory stores must not share state, got rev %d", got.Rev)
	}
}

func TestOpenFactory(t *testing.T) {
	dir := t.TempDir()
	for backend, file := range map[string]string{"": "state.json", "file": "state.json", "sqlite": "state.db"} {
		sub := filepath.Join(dir, "b-"+backend)
		st, err := Open(backend, sub)
		if err != nil {
			t.Fatalf("backend %q: %v", backend, err)
		}
		if err := st.Save(load(t, st)); err != nil {
			t.Fatal(err)
		}
		st.Close()
		if _, err := os.Stat(filepath.Join(sub, file)); err != nil {
			t.Fatalf("backend %q: %v", backend, err)
		}
	}
	_, err := Open("postgres", dir)
	if err == nil || !strings.Contains(err.Error(), `"postgres"`) ||
		!strings.Contains(err.Error(), "file") || !strings.Contains(err.Error(), "sqlite") {
		t.Fatalf("error must name the bad backend and the valid ones: %v", err)
	}
}

func TestSQLiteFilePrivate(t *testing.T) {
	if !host.Private() {
		t.Skip("owner-only modes are not enforced on this platform")
	}
	dir := filepath.Join(t.TempDir(), "data")
	st, err := OpenSQLite(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Save(load(t, st)); err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	for _, p := range []string{dir, filepath.Join(dir, "state.db")} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm()&0o077 != 0 {
			t.Fatalf("%s is %v, want owner-only", p, fi.Mode().Perm())
		}
	}
	if matches, _ := filepath.Glob(filepath.Join(dir, "state.db-*")); len(matches) > 0 {
		for _, p := range matches {
			if fi, err := os.Stat(p); err == nil && fi.Mode().Perm()&0o077 != 0 {
				t.Fatalf("%s is %v, want owner-only", p, fi.Mode().Perm())
			}
		}
	}
}

func TestLegacyFileLoads(t *testing.T) {
	dir := t.TempDir()
	legacy := `{"vulns":{"CVE-2026-5":{"id":"CVE-2026-5","title":"old"}},"findings":{},"feeds":{}}`
	if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := OpenFile(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	s := load(t, st)
	if s.Rev != 0 || s.SchemaVersion != 0 || s.Vulns["CVE-2026-5"] == nil {
		t.Fatalf("legacy file misread: %+v", s)
	}
	if err := st.Save(s); err != nil {
		t.Fatal(err)
	}
	if got := load(t, st); got.Rev != 1 || got.Vulns["CVE-2026-5"] == nil {
		t.Fatalf("after save: %+v", got)
	}
}
