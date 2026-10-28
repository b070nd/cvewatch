package ops

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/b070nd/cvewatch/app/src/audit"
	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/ledger"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/query"
	"github.com/b070nd/cvewatch/app/src/store"
)

var day = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func bundle(t *testing.T, access map[string]config.Grant) *config.Bundle {
	t.Helper()
	dir := t.TempDir()
	return &config.Bundle{
		Settings: config.Settings{DataDir: filepath.Join(dir, "data"), AlertsDir: filepath.Join(dir, "alerts"), Access: access},
		Techs:    []model.Tech{{Name: "php"}},
		Projects: []model.Project{
			{Name: "shop", Techs: []model.ProjectTech{{Name: "php", Version: "8.2"}}},
			{Name: "mw", Envs: []model.Env{model.EnvProd}},
		},
	}
}

// seeded returns a shared memory store holding one tracked and one irrelevant record.
func seeded(t *testing.T) store.Storage {
	t.Helper()
	st := store.NewMemory()
	l := ledger.New(ledger.State{})
	v := l.Create(model.Item{Title: "Tracked PHP bug", URL: "https://a.test/1", IDs: []string{"CVE-2026-1"}, Severity: model.SevHigh,
		Published: day, SourceID: "hn", SourceType: "hn"}, day, []string{"php"})
	l.Create(model.Item{Title: "Late PHP-FPM flaw", URL: "https://a.test/2", IDs: []string{"CVE-2026-2"}, Published: day, SourceID: "hn", SourceType: "hn"}, day, nil)
	for _, p := range []string{"shop", "mw"} {
		l.AddFinding(model.Finding{VulnID: v.ID, Project: p, Env: model.EnvProd, Status: model.StatusOpen, Applies: model.AppUnknown})
	}
	if err := st.Save(l.State()); err != nil {
		t.Fatal(err)
	}
	return st
}

func open(t *testing.T, cfg *config.Bundle, st store.Storage, actor string) *Session {
	t.Helper()
	s, err := OpenWith(cfg, st, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err != nil {
		t.Fatal(err)
	}
	s.Actor, s.Now = actor, func() time.Time { return day.Add(48 * time.Hour) }
	return s
}

func TestResolveValidatesAuditsAndPersists(t *testing.T) {
	cfg, st := bundle(t, nil), seeded(t)
	s := open(t, cfg, st, "alice")
	for name, c := range map[string]Change{
		"status":  {ID: "CVE-2026-1", Project: "shop", Status: "done"},
		"env":     {ID: "CVE-2026-1", Project: "shop", Env: "qa", Status: model.StatusFixed},
		"project": {ID: "CVE-2026-1", Project: "nope", Status: model.StatusFixed},
		"id":      {ID: "CVE-0", Project: "shop", Status: model.StatusFixed},
	} {
		if _, err := s.Resolve(c); err == nil {
			t.Errorf("%s must be rejected", name)
		}
	}
	if n, err := s.Resolve(Change{ID: "cve-2026-1", Project: "shop", Env: model.EnvProd, Status: model.StatusFixed, Note: "MR 1"}); err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if n, err := audit.Open(cfg.DataDir).Verify(); err != nil || n != 1 {
		t.Fatalf("exactly one audit record expected, got n=%d err=%v", n, err)
	}
	if _, err := os.Stat(filepath.Join(cfg.AlertsDir, "2026")); err != nil {
		t.Fatalf("report not written: %v", err)
	}
	re := open(t, cfg, st, "alice") // a fresh session over the same storage sees the change
	issues, err := re.List(query.Filter{})
	if err != nil || len(issues) != 1 || len(issues[0].Targets) != 1 || issues[0].Targets[0].Project != "mw" {
		t.Fatalf("fixed finding must drop out of the open list: %+v %v", issues, err)
	}
}

func TestAccessRules(t *testing.T) {
	cfg := bundle(t, map[string]config.Grant{
		"alice": {Projects: []string{"shop"}, Write: true},
		"bob":   {Projects: []string{"*"}},
	})
	st := seeded(t)

	alice := open(t, cfg, st, "alice")
	issues, err := alice.List(query.Filter{})
	if err != nil || len(issues) != 1 || len(issues[0].Targets) != 1 || issues[0].Targets[0].Project != "shop" {
		t.Fatalf("alice must see only shop: %+v %v", issues, err)
	}
	if _, err := alice.Resolve(Change{ID: "CVE-2026-1", Project: "mw", Status: model.StatusFixed}); !errors.Is(err, ErrDenied) {
		t.Fatalf("alice has no write access to mw: %v", err)
	}
	if _, err := alice.Resolve(Change{ID: "CVE-2026-1", Project: "shop", Status: model.StatusIgnored}); err != nil {
		t.Fatalf("alice may write shop: %v", err)
	}
	if _, err := alice.Refresh(nil); !errors.Is(err, ErrDenied) {
		t.Fatalf("refresh needs access to every project: %v", err)
	}

	bob := open(t, cfg, st, "mcp:bob") // adapter prefix must not break the lookup
	if issues, _ := bob.List(query.Filter{}); len(issues) != 1 {
		t.Fatal("bob reads everything")
	}
	if _, err := bob.Resolve(Change{ID: "CVE-2026-1", Project: "mw", Status: model.StatusFixed}); !errors.Is(err, ErrDenied) {
		t.Fatalf("bob is read-only: %v", err)
	}
	if _, err := open(t, cfg, st, "mallory").List(query.Filter{}); !errors.Is(err, ErrDenied) {
		t.Fatalf("unlisted actors get nothing: %v", err)
	}
	if _, _, err := alice.Show("CVE-2026-1"); err != nil {
		t.Fatal(err)
	}
}

func TestRescanAddsFindingsOnlyWhenAsked(t *testing.T) {
	cfg, st := bundle(t, nil), seeded(t)
	s := open(t, cfg, st, "alice")

	dry, err := s.Rescan(false)
	if err != nil || len(dry.Candidates) != 1 || dry.Candidates[0].ID != "CVE-2026-2" || dry.Applied {
		t.Fatalf("dry run: %+v %v", dry, err)
	}
	if got := len(s.Ledger.FindingsOf("CVE-2026-2")); got != 0 {
		t.Fatalf("dry run must not create findings, got %d", got)
	}
	done, err := s.Rescan(true)
	if err != nil || !done.Applied || len(s.Ledger.FindingsOf("CVE-2026-2")) != 4 { // shop x4 envs + mw prod
		t.Fatalf("apply: %+v %v findings=%d", done, err, len(s.Ledger.FindingsOf("CVE-2026-2")))
	}
	if again, _ := open(t, cfg, st, "alice").Rescan(false); len(again.Candidates) != 0 {
		t.Fatalf("rescan must be idempotent and persisted: %+v", again)
	}
}

func TestExplainAndCalendar(t *testing.T) {
	cfg, st := bundle(t, nil), seeded(t)
	s := open(t, cfg, st, "alice")
	ex, err := s.Explain("CVE-2026-1")
	if err != nil || len(ex.Stored) != 2 || !ex.Relevant || len(ex.Today) == 0 {
		t.Fatalf("explain: %+v %v", ex, err)
	}
	month := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	entries, err := s.Calendar(month, query.Filter{})
	if err != nil || len(entries) != 1 || entries[0].ID != "CVE-2026-1" {
		t.Fatalf("calendar: %+v %v", entries, err)
	}
	path, err := s.WriteCalendar(month, query.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), "CVE-2026-1") || strings.Contains(string(raw), "<script") {
		t.Fatalf("calendar page: %s", raw)
	}
	if other, _ := s.Calendar(month.AddDate(0, 1, 0), query.Filter{}); len(other) != 0 {
		t.Fatal("other months must be empty")
	}
}

func TestNotAffectedStatementNeedsAReason(t *testing.T) {
	cfg, st := bundle(t, nil), seeded(t)
	s := open(t, cfg, st, "alice")
	c := Change{ID: "CVE-2026-1", Project: "shop", Env: model.EnvProd, Status: model.StatusNotAffected}
	if _, err := s.Resolve(c); err == nil {
		t.Fatal("a VEX-style statement without a reason must be rejected")
	}
	c.Note = "feature disabled in prod"
	if _, err := s.Resolve(c); err != nil {
		t.Fatal(err)
	}
	f := s.Ledger.FindingsOf("CVE-2026-1")[1] // order: mw, shop
	if f.Status != model.StatusNotAffected || f.Note != "feature disabled in prod" || f.History[0].Actor != "alice" {
		t.Fatalf("reason, actor and time must be recorded: %+v", f)
	}
	events, _ := s.Audit.Events()
	if len(events) != 1 || events[0].Status != "not_affected" || events[0].Note != "feature disabled in prod" {
		t.Fatalf("audit: %+v", events)
	}
}

func TestAssignAndAttachEvidence(t *testing.T) {
	cfg, st := bundle(t, nil), seeded(t)
	s := open(t, cfg, st, "alice")
	a := Assignment{ID: "CVE-2026-1", Project: "shop", Env: model.EnvProd, Owner: "bob", Due: "2026-11-30", Ticket: "https://tickets.test/1"}
	if n, err := s.Assign(a); err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	f := s.Ledger.FindingsOf("CVE-2026-1")[1] // order: mw, shop
	if f.Owner != "bob" || f.Due.Format("2006-01-02") != "2026-11-30" || f.Ticket != "https://tickets.test/1" {
		t.Fatalf("assignment: %+v", f)
	}
	for name, bad := range map[string]Assignment{
		"due":     {ID: "CVE-2026-1", Project: "shop", Due: "next week"},
		"nothing": {ID: "CVE-2026-1", Project: "shop"},
		"project": {ID: "CVE-2026-1", Project: "nope", Owner: "x"},
	} {
		if _, err := s.Assign(bad); err == nil {
			t.Errorf("%s must be rejected", name)
		}
	}
	if _, err := s.Assign(Assignment{ID: "CVE-2026-1", Project: "shop", Env: model.EnvProd, Owner: "-", Due: "none"}); err != nil {
		t.Fatal(err)
	}
	if f := s.Ledger.FindingsOf("CVE-2026-1")[1]; f.Owner != "" || !f.Due.IsZero() || f.Ticket != "https://tickets.test/1" {
		t.Fatalf("clearing owner and due must leave the ticket: %+v", f)
	}

	if _, err := s.Attach(Attachment{ID: "CVE-2026-1", Project: "shop", URL: "javascript:alert(1)"}); err == nil {
		t.Fatal("evidence links must be plain http(s)")
	}
	if _, err := s.Attach(Attachment{ID: "CVE-2026-1", Project: "shop"}); err == nil {
		t.Fatal("empty evidence must be rejected")
	}
	if n, err := s.Attach(Attachment{ID: "CVE-2026-1", Project: "shop", Env: model.EnvProd, Note: "deployed in release 42\nsecond line", URL: "https://ci.test/run/42"}); err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	f = s.Ledger.FindingsOf("CVE-2026-1")[1]
	if len(f.Evidence) != 1 || f.Evidence[0].Actor != "alice" || strings.Contains(f.Evidence[0].Note, "\n") {
		t.Fatalf("evidence: %+v", f.Evidence)
	}
	if n, err := s.Audit.Verify(); err != nil || n != 3 { // assign, assign, evidence
		t.Fatalf("every change must be audited in one intact chain: n=%d err=%v", n, err)
	}
}

func TestPolicyViolationsAndOverdue(t *testing.T) {
	cfg, st := bundle(t, nil), seeded(t)
	cfg.Policy.Rules = []config.PolicyRule{{Name: "owner-fast", Env: model.EnvProd, OwnerWithin: time.Hour}}
	s := open(t, cfg, st, "alice")
	v, err := s.Violations()
	if err != nil || len(v) != 2 || v[0].Rule != "owner-fast" {
		t.Fatalf("both prod findings have no owner after 48h: %+v %v", v, err)
	}
	if _, err := s.Assign(Assignment{ID: "CVE-2026-1", Project: "shop", Owner: "bob", Due: "2026-10-02"}); err != nil {
		t.Fatal(err)
	}
	v, _ = s.Violations()
	reasons := map[string]bool{}
	for _, x := range v {
		reasons[x.Subject.Project+": "+x.Reason] = true
	}
	if len(v) != 2 || !reasons["mw: no owner within 1h"] || !reasons["shop: past its due date 2026-10-02"] {
		t.Fatalf("shop has an owner but missed its due date, mw still has none: %v", reasons)
	}
}

func TestExportListsEveryEnvironmentOfOpenIssues(t *testing.T) {
	cfg, st := bundle(t, nil), seeded(t)
	s := open(t, cfg, st, "alice")
	if _, err := s.Resolve(Change{ID: "CVE-2026-1", Project: "shop", Env: model.EnvProd, Status: model.StatusFixed}); err != nil {
		t.Fatal(err)
	}
	doc, err := s.Export(query.Filter{})
	if err != nil || doc.SchemaVersion != 1 || doc.Count != 1 || len(doc.Issues[0].Targets) != 2 {
		t.Fatalf("an issue still open in mw lists shop's fixed environment too: %+v %v", doc, err)
	}
	status := map[string]model.Status{}
	for _, tg := range doc.Issues[0].Targets {
		status[tg.Project] = tg.Status
	}
	if status["shop"] != model.StatusFixed || status["mw"] != model.StatusOpen {
		t.Fatalf("per-environment truth: %v", status)
	}
}

func TestEvidencePackFollowsTheAuditTrail(t *testing.T) {
	cfg, st := bundle(t, nil), seeded(t)
	s := open(t, cfg, st, "alice")
	if _, err := s.Resolve(Change{ID: "CVE-2026-1", Project: "shop", Env: model.EnvProd, Status: model.StatusFixed, Note: "MR 9"}); err != nil {
		t.Fatal(err)
	}
	pack, err := s.Evidence("cve-2026-1")
	if err != nil || !pack.AuditIntact || len(pack.Matrix) != 2 {
		t.Fatalf("pack: %+v %v", pack, err)
	}
	found := false
	for _, e := range pack.Timeline {
		found = found || (e.Kind == "status" && e.Actor == "alice" && strings.Contains(e.Detail, "MR 9"))
	}
	if !found {
		t.Fatalf("the status change must be on the timeline: %+v", pack.Timeline)
	}
	scoped := bundle(t, map[string]config.Grant{"carol": {Projects: []string{"mw"}}})
	scoped.DataDir = cfg.DataDir
	cs := open(t, scoped, st, "carol")
	p2, err := cs.Evidence("CVE-2026-1")
	if err != nil || len(p2.Matrix) != 1 || p2.Matrix[0].Project != "mw" {
		t.Fatalf("an actor limited to mw must not see shop: %+v %v", p2.Matrix, err)
	}
	for _, e := range p2.Timeline {
		if strings.Contains(e.Detail, "shop") {
			t.Fatalf("audit records of other projects must be hidden: %+v", e)
		}
	}
}

func TestDigestAndInventoryViews(t *testing.T) {
	cfg, st := bundle(t, nil), seeded(t)
	s := open(t, cfg, st, "alice")
	d, err := s.Digest()
	if err != nil || d.Open != 1 || d.BySeverity[model.SevHigh] != 1 || d.Items[0].ID != "CVE-2026-1" {
		t.Fatalf("digest: %+v %v", d, err)
	}
	inv, err := s.Inventory("shop")
	if err != nil || len(inv.Targets) != 4 || inv.Targets[0].Project != "shop" {
		t.Fatalf("shop runs in four environments: %+v %v", inv.Targets, err)
	}
}
