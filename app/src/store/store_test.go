package store

import (
	"errors"
	"testing"
	"time"

	"github.com/b070nd/cvewatch/app/src/ledger"
	"github.com/b070nd/cvewatch/app/src/model"
)

// roundTrip is the contract every adapter must meet.
func roundTrip(t *testing.T, st Storage, reopen func() Storage) {
	t.Helper()
	s, err := st.Load()
	if err != nil {
		t.Fatal(err)
	}
	l := ledger.New(s)
	v := l.Create(model.Item{Title: "PHP bug", URL: "https://a.test/1", IDs: []string{"CVE-2026-1", "GHSA-AAAA-BBBB-CCCC"}}, time.Now(), []string{"php"})
	l.AddFinding(model.Finding{VulnID: v.ID, Project: "shop", Env: model.EnvProd, Status: model.StatusOpen})
	if _, err := l.SetStatus(v.ID, "shop", model.EnvProd, model.StatusFixed, "patched", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := st.Save(l.State()); err != nil {
		t.Fatal(err)
	}
	st.Close()

	st = reopen()
	defer st.Close()
	s, err = st.Load()
	if err != nil {
		t.Fatal(err)
	}
	re := ledger.New(s)
	if re.Lookup([]string{"GHSA-AAAA-BBBB-CCCC"}) == nil {
		t.Fatal("alias must resolve after reload")
	}
	if got := re.Findings()[0]; got.Status != model.StatusFixed || got.Note != "patched" {
		t.Fatalf("status lost: %+v", got)
	}
}

func TestFileAdapter(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenFile(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFile(dir); !errors.Is(err, ErrBusy) {
		t.Fatalf("second open must fail while locked, got %v", err)
	}
	roundTrip(t, st, func() Storage {
		again, err := OpenFile(dir)
		if err != nil {
			t.Fatal(err)
		}
		return again
	})
}

func TestMemoryAdapter(t *testing.T) {
	m := NewMemory()
	roundTrip(t, m, func() Storage { return m })
}
