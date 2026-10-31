package ops

import (
	"testing"

	"github.com/b070nd/cvewatch/app/src/audit"
	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/evidence"
	"github.com/b070nd/cvewatch/app/src/query"
)

func rename(t *testing.T, s *Session, from, to string) {
	t.Helper()
	if _, err := s.ProjectLifecycle(LifecycleRequest{Verb: VerbRename, Project: from, NewName: to, Apply: true, Confirm: true}); err != nil {
		t.Fatalf("rename %s to %s: %v", from, to, err)
	}
}

// auditProjects lists the projects of the audit entries of a pack.
func auditProjects(p evidence.Pack) []string {
	var out []string
	for _, e := range timelineOf(p, "audit") {
		out = append(out, e.Project)
	}
	return out
}

func historyHas(h []query.HistoryEntry, project string) bool {
	for _, e := range h {
		if e.Source == "audit" && e.Project == project {
			return true
		}
	}
	return false
}

func seedShopHistory(t *testing.T, s *Session) {
	t.Helper()
	seedAudit(t, s.Cfg.DataDir,
		auditAt(1, audit.Event{Actor: "cvewatch", Action: "detected", Project: "shop", Env: "prod"}),
		auditAt(2, audit.Event{Actor: "cvewatch", Action: "detected", Project: "mw", Env: "prod"}),
	)
}

func TestEvidenceKeepsDetectionsOfFormerProjectNames(t *testing.T) {
	s, _ := lcSession(t, "root", false)
	seedShopHistory(t, s)
	rename(t, s, "shop", "webshop")

	p, err := s.EvidenceIn("CVE-2026-1", query.Filter{Project: "webshop"})
	if err != nil {
		t.Fatal(err)
	}
	if got := auditProjects(p); len(got) != 1 || got[0] != "shop" {
		t.Fatalf("one rename: the detection under the old name is part of the pack: %v", got)
	}
	if d, err := s.IssueDetailIn("CVE-2026-1", query.Filter{Project: "webshop"}); err != nil || !historyHas(d.History, "shop") {
		t.Fatalf("issue history: %+v %v", d.History, err)
	}

	rename(t, s, "webshop", "store")
	if p, _ = s.EvidenceIn("CVE-2026-1", query.Filter{Project: "store"}); len(auditProjects(p)) != 1 {
		t.Fatalf("two renames: %v", auditProjects(p))
	}
	if p, _ = s.EvidenceIn("CVE-2026-1", query.Filter{Project: "mw"}); len(auditProjects(p)) != 1 || auditProjects(p)[0] != "mw" {
		t.Fatalf("another project keeps its own: %v", auditProjects(p))
	}
	if p, _ = s.EvidenceIn("CVE-2026-1", query.Filter{Project: "shop"}); len(auditProjects(p)) != 1 {
		t.Fatalf("the recorded name itself still matches: %v", auditProjects(p))
	}

	raw, err := s.Audit.Events()
	if err != nil || raw[0].Project != "shop" || raw[0].Action != "detected" {
		t.Fatalf("the log is never rewritten: %+v %v", raw, err)
	}
	if n, err := s.Audit.Verify(); err != nil || n != len(raw) {
		t.Fatalf("chain: %d %v", n, err)
	}
}

func TestRestrictedReaderSeesDetectionsOfFormerNameOfItsProject(t *testing.T) {
	s, st := lcSession(t, "root", true)
	seedShopHistory(t, s)
	rename(t, s, "shop", "webshop")

	// the rename rewrote bob's rule to webshop; a reader of the new name sees the old detections
	s.Cfg.Projects[0].Name = "webshop" // what a reload after the rename would hold
	s.Cfg.Access = map[string]config.Grant{"bob": {Projects: []string{"webshop"}}, "olga": {Projects: []string{"shop"}}}
	bob := open(t, s.Cfg, st, "bob")
	p, err := bob.Evidence("CVE-2026-1")
	if err != nil {
		t.Fatal(err)
	}
	if got := auditProjects(p); len(got) != 1 || got[0] != "shop" {
		t.Fatalf("bob: %v", got)
	}
	if d, err := bob.IssueDetail("CVE-2026-1"); err != nil || !historyHas(d.History, "shop") {
		t.Fatalf("bob history: %+v %v", d.History, err)
	}

	// a reader scoped to the old name only gets nothing of the new name
	seedAudit(t, s.Cfg.DataDir, auditAt(60, audit.Event{Actor: "cvewatch", Action: "detected", Project: "webshop", Env: "prod"}))
	olga := open(t, s.Cfg, st, "olga")
	p, err = olga.Evidence("CVE-2026-1") // no finding of hers is left under the old name, so the issue is not hers to see
	if err == nil {
		t.Fatalf("olga: %v", auditProjects(p))
	}
	evs, _ := s.Audit.Events()
	for _, e := range narrowEvents(evs, query.Filter{Projects: []string{"shop"}}) {
		if e.Project == "webshop" {
			t.Fatalf("a reader of the old name sees the new one: %+v", e)
		}
	}
	if p, _ = bob.Evidence("CVE-2026-1"); len(auditProjects(p)) != 2 {
		t.Fatalf("bob sees both names: %v", auditProjects(p))
	}
}

func TestProjectReusingAnOldNameDoesNotInheritItsHistory(t *testing.T) {
	s, _ := lcSession(t, "root", false)
	seedShopHistory(t, s)
	rename(t, s, "shop", "webshop")
	// a new project is later created under the old name and detects something
	seedAudit(t, s.Cfg.DataDir, auditAt(100, audit.Event{Actor: "cvewatch", Action: "detected", Project: "shop", Env: "prod"}))

	p, err := s.EvidenceIn("CVE-2026-1", query.Filter{Project: "webshop"})
	if err != nil {
		t.Fatal(err)
	}
	var times []string
	for _, e := range timelineOf(p, "audit") {
		times = append(times, e.Time.Format("15"))
	}
	if len(times) != 1 {
		t.Fatalf("webshop owns the detection before the rename only: %v", times)
	}
	evs, _ := s.Audit.Events()
	if got := audit.CurrentName(audit.Renames(evs), "shop", len(evs)-1); got != "shop" {
		t.Fatalf("the later shop is its own project: %s", got)
	}
}
