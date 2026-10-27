package store

import (
	"testing"
	"time"

	"cvewatch/src/model"
)

func TestPersistenceAndStatus(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); err == nil {
		t.Fatal("second Open must fail while locked")
	}

	v := &model.Vulnerability{ID: "CVE-2026-1", Aliases: []string{"GHSA-aaaa-bbbb-cccc"}}
	s.AddVuln(v)
	f := model.Finding{VulnID: v.ID, Project: "shop", Env: model.EnvProd, Status: model.StatusOpen}
	if !s.AddFinding(f) || s.AddFinding(f) {
		t.Fatal("AddFinding must insert once")
	}
	if _, err := s.SetStatus(v.ID, "shop", model.EnvProd, model.StatusFixed, "patched", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	s.Close()

	s, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.Lookup([]string{"GHSA-aaaa-bbbb-cccc"}) == nil {
		t.Fatal("alias must resolve after reload")
	}
	if got := s.Findings()[0]; got.Status != model.StatusFixed || got.Note != "patched" {
		t.Fatalf("status lost: %+v", got)
	}
	if s.AddFinding(f) || s.Findings()[0].Status != model.StatusFixed {
		t.Fatal("rerun must not reset a fixed finding")
	}
	if _, err := s.SetStatus("CVE-nope", "shop", "", model.StatusFixed, "", time.Now()); err == nil {
		t.Fatal("unknown finding must error")
	}
}

func TestPruneKeepsFindingsAndDropsOldNoise(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now()
	s.AddVuln(&model.Vulnerability{ID: "OLD-NOISE", FirstSeen: now.AddDate(0, 0, -400)})
	s.AddVuln(&model.Vulnerability{ID: "NEW-NOISE", FirstSeen: now})
	s.AddVuln(&model.Vulnerability{ID: "OLD-REAL", FirstSeen: now.AddDate(0, 0, -400)})
	s.AddFinding(model.Finding{VulnID: "OLD-REAL", Project: "p", Env: model.EnvProd, Status: model.StatusOpen})
	if n := s.Prune(now.AddDate(0, 0, -180)); n != 1 {
		t.Fatalf("pruned %d", n)
	}
	if s.Vuln("OLD-NOISE") != nil || s.Lookup([]string{"OLD-NOISE"}) != nil || s.Vuln("OLD-REAL") == nil || s.Vuln("NEW-NOISE") == nil {
		t.Fatal("wrong records pruned")
	}
}
