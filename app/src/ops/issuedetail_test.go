package ops

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/ledger"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/query"
	"github.com/b070nd/cvewatch/app/src/store"
)

var detailUpdate = flag.Bool("update-detail", false, "rewrite the golden files")

func detailGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *detailUpdate {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.ReplaceAll(string(want), "\r\n", "\n") != got { // a checkout may have turned the line ends into CRLF
		t.Errorf("%s differs from the golden file (run with -update-detail to accept):\n%s", name, got)
	}
}

// richStore holds one vulnerability with every kind of fact, open in shop/prod and mw/prod.
func richStore(t *testing.T) store.Storage {
	t.Helper()
	l := ledger.New(ledger.State{})
	v := l.Create(model.Item{Title: "Remote code execution in Example", Summary: "An attacker can run code.", URL: "https://news.test/1",
		IDs: []string{"CVE-2026-0100", "GHSA-AAAA-BBBB-CCCC"}, Severity: model.SevCritical, CVSS: 9.8, Published: day, SourceID: "hn", SourceType: "hn"}, day, []string{"php"})
	v.Refs = append(v.Refs, model.Ref{Source: "nvd", Kind: model.RefAdvisory, URL: "https://nvd.test/CVE-2026-0100"},
		model.Ref{Source: "evil", Kind: model.RefAdvisory, URL: "javascript:alert(1)"})
	v.Fixes = []model.Fix{{Kind: model.FixVersion, Detail: "8.2.30", Source: "ghsa", Official: true, URL: "https://fix.test/8.2.30"}}
	v.Affected = []model.Affected{{Ecosystem: "composer", Name: "example/framework", Ranges: []model.Range{{Min: "8.0", Max: "8.2.30", MaxExcl: true}}, Fixed: "8.2.30"}}
	v.KEV = &model.KEV{DateAdded: day.Add(24 * time.Hour), DueDate: day.Add(96 * time.Hour), Ransomware: true, Action: "Apply updates."}
	v.EPSS = &model.EPSS{Score: 0.5, Percentile: 0.97}
	l.AddFinding(model.Finding{VulnID: v.ID, Project: "shop", Env: model.EnvProd, Status: model.StatusOpen, Applies: model.AppAffected,
		Matched: []string{"php@8.2.10"}, Installed: []model.Installed{{Name: "php", Version: "8.2.10", Via: "tech"}}})
	l.AddFinding(model.Finding{VulnID: v.ID, Project: "mw", Env: model.EnvProd, Status: model.StatusOpen, Applies: model.AppUnknown})
	st := store.NewMemory()
	if err := st.Save(l.State()); err != nil {
		t.Fatal(err)
	}
	return st
}

func TestIssueDetailGathersEveryFact(t *testing.T) {
	cfg, st := bundle(t, nil), richStore(t)
	s := open(t, cfg, st, "alice")
	if _, err := s.Attach(Attachment{ID: "CVE-2026-0100", Project: "shop", Env: model.EnvProd, Note: "deployed", URL: "https://ci.test/run/42"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Resolve(Change{ID: "CVE-2026-0100", Project: "shop", Env: model.EnvProd, Status: model.StatusFixed, Note: "MR 9"}); err != nil {
		t.Fatal(err)
	}
	d, err := s.IssueDetail("ghsa-aaaa-bbbb-cccc") // an alias works
	if err != nil {
		t.Fatal(err)
	}
	if d.Issue.ID != "CVE-2026-0100" || d.Issue.KEV == nil || !d.Issue.KEV.Ransomware || d.Issue.EPSS.Percentile != 0.97 || d.Issue.CVSS != 9.8 {
		t.Fatalf("facts: %+v", d.Issue)
	}
	if len(d.Affected) != 1 || d.Affected[0].Fixed != "8.2.30" {
		t.Fatalf("affected: %+v", d.Affected)
	}
	var urls []string
	for _, l := range d.Links {
		urls = append(urls, l.Kind+" "+l.URL)
	}
	want := []string{"advisory https://nvd.test/CVE-2026-0100", "fix https://fix.test/8.2.30", "article https://news.test/1", "evidence https://ci.test/run/42"}
	if !reflect.DeepEqual(urls, want) {
		t.Fatalf("links (the javascript: one must not be listed): %v", urls)
	}
	if got := d.TargetOf("shop", model.EnvProd); len(got.Installed) != 1 || got.Installed[0].Label() != "php@8.2.10" || len(got.Evidence) != 1 || got.Evidence[0].Actor != "alice" {
		t.Fatalf("shop/prod: %+v", got)
	}
	var kinds []string
	for _, h := range d.History {
		kinds = append(kinds, h.Kind+" "+h.Source)
		if h.Source != "audit" && h.Kind != "first-seen" {
			t.Errorf("history entry from %s: %+v", h.Source, h)
		}
	}
	if !reflect.DeepEqual(kinds, []string{"first-seen ledger", "evidence audit", "status audit"}) {
		t.Fatalf("history comes from the audit trail: %v", kinds)
	}
	for _, w := range []string{"## History", "shop/prod set to fixed: MR 9", "**Installed:**", "php@8.2.10 (tech)", "`>=8.0, <8.2.30`", "https://ci.test/run/42"} {
		if !strings.Contains(d.Markdown, w) {
			t.Errorf("markdown lacks %q:\n%s", w, d.Markdown)
		}
	}
	if strings.Contains(d.Markdown, "javascript:") {
		t.Error("an unsafe advisory link must not reach the report")
	}
}

func TestShowIsTheIssueDetail(t *testing.T) {
	cfg, st := bundle(t, nil), richStore(t)
	s := open(t, cfg, st, "alice")
	is, md, err := s.Show("CVE-2026-0100")
	if err != nil {
		t.Fatal(err)
	}
	d, _ := s.IssueDetail("CVE-2026-0100")
	if md != d.Markdown || !reflect.DeepEqual(is, d.Issue) {
		t.Fatal("Show and IssueDetail must say the same")
	}
	f, _ := s.scope(query.Filter{})
	one, err := query.One(s.Ledger, "CVE-2026-0100", f, s.Now())
	if err != nil || !reflect.DeepEqual(one, is) {
		t.Fatalf("the JSON contract is the Issue query.One builds:\n%+v\n%+v", one, is)
	}
	if len(is.Priority) != 0 {
		t.Fatalf("show -json must not gain a priority field: %v", is.Priority)
	}
	if _, _, err := s.Show("CVE-0000-0"); err == nil {
		t.Fatal("an unknown id must fail")
	}
}

func TestIssueDetailHidesWhatTheActorMayNotSee(t *testing.T) {
	cfg, st := bundle(t, nil), richStore(t)
	s := open(t, cfg, st, "alice")
	if _, err := s.Attach(Attachment{ID: "CVE-2026-0100", Project: "shop", Env: model.EnvProd, Note: "secret shop note", URL: "https://ci.test/shop"}); err != nil {
		t.Fatal(err)
	}
	scoped := bundle(t, map[string]config.Grant{"carol": {Projects: []string{"mw"}}})
	scoped.DataDir = cfg.DataDir
	d, err := open(t, scoped, st, "carol").IssueDetail("CVE-2026-0100")
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Issue.Targets) != 1 || d.Issue.Targets[0].Project != "mw" || len(d.Targets) != 1 {
		t.Fatalf("targets: %+v", d.Issue.Targets)
	}
	all, _ := json.Marshal(d)
	for _, w := range []string{"secret shop note", "ci.test/shop", "php@8.2.10"} {
		if strings.Contains(string(all), w) {
			t.Errorf("carol sees %q of a project she has no access to: %s", w, all)
		}
	}
}

func TestIssueDetailGolden(t *testing.T) {
	cfg, st := bundle(t, nil), richStore(t)
	s := open(t, cfg, st, "alice")
	if _, err := s.Attach(Attachment{ID: "CVE-2026-0100", Project: "shop", Env: model.EnvProd, Note: "deployed", URL: "https://ci.test/run/42"}); err != nil {
		t.Fatal(err)
	}
	d, err := s.IssueDetail("CVE-2026-0100")
	if err != nil {
		t.Fatal(err)
	}
	rel, err := filepath.Rel(cfg.AlertsDir, d.Issue.Report) // the temp dir is different every run
	if err != nil {
		t.Fatal(err)
	}
	d.Issue.Report = filepath.ToSlash(rel)
	js, err := json.MarshalIndent(d.Detail, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	detailGolden(t, "issuedetail.json", string(js)+"\n")
	detailGolden(t, "issuedetail.md", d.Markdown)
}
