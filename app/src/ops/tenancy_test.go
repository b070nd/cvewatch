package ops

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/b070nd/cvewatch/app/src/audit"
	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/ledger"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/projectfile"
	"github.com/b070nd/cvewatch/app/src/query"
	"github.com/b070nd/cvewatch/app/src/store"
)

// tenantBundle has shop and crm of the vendor acme, wiki of globex and blog with none.
func tenantBundle(t *testing.T, access map[string]config.Grant) *config.Bundle {
	t.Helper()
	cfg := bundle(t, access)
	envs := []model.Env{model.EnvDev, model.EnvProd}
	cfg.Projects = []model.Project{
		{Name: "shop", Vendor: "acme", Envs: envs}, {Name: "crm", Vendor: "acme", Envs: envs},
		{Name: "wiki", Vendor: "globex", Envs: envs}, {Name: "blog", Envs: envs},
	}
	return cfg
}

func tenantStore(t *testing.T) store.Storage {
	t.Helper()
	st := store.NewMemory()
	l := ledger.New(ledger.State{})
	v := l.Create(model.Item{Title: "PHP bug", URL: "https://a.test/1", IDs: []string{"CVE-2026-1"}, Severity: model.SevHigh,
		Published: day, SourceID: "hn", SourceType: "hn"}, day, []string{"php"})
	for _, f := range []struct {
		project string
		env     model.Env
	}{{"shop", model.EnvProd}, {"shop", model.EnvDev}, {"crm", model.EnvDev}, {"wiki", model.EnvProd}, {"blog", model.EnvProd}} {
		l.AddFinding(model.Finding{VulnID: v.ID, Project: f.project, Env: f.env, Status: model.StatusOpen, Applies: model.AppAffected, Owner: "o-" + f.project})
	}
	if err := st.Save(l.State()); err != nil {
		t.Fatal(err)
	}
	return st
}

func rows(is []query.Issue) string {
	var out []string
	for _, i := range is {
		for _, t := range i.Targets {
			out = append(out, t.Vendor+"/"+t.Project+"/"+string(t.Env))
		}
	}
	slices.Sort(out)
	return strings.Join(out, ",")
}

func TestListFiltersByVendorAndKeepsTheRowsApart(t *testing.T) {
	s := open(t, tenantBundle(t, nil), tenantStore(t), "alice")
	for _, c := range []struct {
		vendor, project, want string
	}{
		{"", "", "/blog/prod,acme/crm/dev,acme/shop/dev,acme/shop/prod,globex/wiki/prod"},
		{"acme", "", "acme/crm/dev,acme/shop/dev,acme/shop/prod"},
		{"globex", "", "globex/wiki/prod"},
		{"-", "", "/blog/prod"},
		{"acme", "shop", "acme/shop/dev,acme/shop/prod"},
		{"acme", "wiki", ""},
		{"", "crm", "acme/crm/dev"},
	} {
		f, err := ParseTenantFilter("", c.vendor, c.project, "")
		if err != nil {
			t.Fatal(err)
		}
		got, err := s.List(f)
		if err != nil {
			t.Fatal(err)
		}
		if rows(got) != c.want {
			t.Errorf("vendor %q project %q: %s, want %s", c.vendor, c.project, rows(got), c.want)
		}
	}
	if _, err := ParseTenantFilter("", "Bad Vendor", "", ""); err == nil {
		t.Error("a bad vendor must be refused")
	}
}

func TestSearchHoldsEveryNamedFieldOnTheSameRow(t *testing.T) {
	s := open(t, tenantBundle(t, nil), tenantStore(t), "alice")
	search := func(text string, f query.Filter) string {
		t.Helper()
		got, err := s.Search(text, f, false)
		if err != nil {
			t.Fatal(err)
		}
		return rows(got)
	}
	for text, want := range map[string]string{
		"project:crm env:prod":     "", // crm has no prod row; shop and wiki do
		"project:crm env:dev":      "acme/crm/dev",
		"project:shop owner:o-crm": "",
		"vendor:acme env:prod":     "acme/shop/prod",
		"vendor:acme -env:dev":     "acme/shop/prod",
		"vendor:-":                 "/blog/prod",
		"vendor:globex,-":          "/blog/prod,globex/wiki/prod",
		"env:prod status:open":     "/blog/prod,acme/shop/prod,globex/wiki/prod",
	} {
		if got := search(text, query.Filter{}); got != want {
			t.Errorf("%q: %s, want %s", text, got, want)
		}
	}
	if got := search("env:prod", query.Filter{Vendor: "acme"}); got != "acme/shop/prod" {
		t.Errorf("a filter and a query hold on the same row: %s", got)
	}
	if got := search("project:wiki", query.Filter{Vendor: "acme"}); got != "" {
		t.Errorf("%s", got)
	}
}

func TestVendorGrantLimitsAnActorToTheProjectsOfTheVendor(t *testing.T) {
	cfg := tenantBundle(t, map[string]config.Grant{
		"ann":  {Projects: []string{"vendor:acme"}},
		"carl": {Projects: []string{"vendor:acme", "blog"}, Write: true},
		"root": {Projects: []string{"*"}, Write: true},
	})
	st := tenantStore(t)

	ann := open(t, cfg, st, "ann")
	got, err := ann.List(query.Filter{})
	if err != nil || rows(got) != "acme/crm/dev,acme/shop/dev,acme/shop/prod" {
		t.Fatalf("ann: %s %v", rows(got), err)
	}
	if got, _ = ann.List(query.Filter{Vendor: "globex"}); len(got) != 0 {
		t.Errorf("a vendor filter cannot widen the grant: %s", rows(got))
	}
	if got, _ = ann.List(query.Filter{Project: "wiki"}); len(got) != 0 {
		t.Errorf("a project filter cannot widen the grant: %s", rows(got))
	}
	if got, err = ann.Search("project:wiki OR vendor:globex OR php", query.Filter{}, false); err != nil || rows(got) != "acme/crm/dev,acme/shop/dev,acme/shop/prod" {
		t.Errorf("search: %s %v", rows(got), err)
	}
	if err := ann.mayWrite("shop"); !errors.Is(err, ErrDenied) {
		t.Errorf("a read grant does not write: %v", err)
	}
	d, err := ann.IssueDetail("CVE-2026-1")
	if err != nil || len(d.Issue.Targets) != 3 {
		t.Fatalf("detail: %+v %v", d.Issue.Targets, err)
	}
	p, err := ann.Evidence("CVE-2026-1")
	if err != nil || len(p.Matrix) != 3 || p.Matrix[0].Vendor != "acme" {
		t.Fatalf("evidence: %+v %v", p.Matrix, err)
	}
	ex, err := ann.Explain("CVE-2026-1")
	if err != nil || len(ex.Stored) != 3 {
		t.Fatalf("explain: %+v %v", ex.Stored, err)
	}

	carl := open(t, cfg, st, "carl")
	if got, _ = carl.List(query.Filter{}); rows(got) != "/blog/prod,acme/crm/dev,acme/shop/dev,acme/shop/prod" {
		t.Errorf("carl: %s", rows(got))
	}
	if err := carl.mayWrite("crm"); err != nil {
		t.Errorf("carl may write the vendor's projects: %v", err)
	}
	if err := carl.mayWrite("wiki"); !errors.Is(err, ErrDenied) {
		t.Errorf("carl may not write another vendor's project: %v", err)
	}

	// a project that joins the vendor is covered by the next request, with no change to the rule
	cfg.Projects = append(cfg.Projects, model.Project{Name: "erp", Vendor: "acme"})
	if err := open(t, cfg, st, "carl").mayWrite("erp"); err != nil {
		t.Errorf("a new project of the vendor: %v", err)
	}
	if got, err := open(t, cfg, st, "root").List(query.Filter{}); err != nil || len(got) != 1 {
		t.Errorf("root: %v %v", got, err)
	}
}

func TestIssueDetailAndEvidenceKeepToTheContext(t *testing.T) {
	cfg, st := tenantBundle(t, nil), tenantStore(t)
	seedAudit(t, cfg.DataDir,
		auditAt(1, audit.Event{Actor: "cvewatch", Action: "detected", Project: "shop", Env: "prod"}),
		auditAt(2, audit.Event{Actor: "cvewatch", Action: "detected", Project: "wiki", Env: "prod"}),
		auditAt(3, audit.Event{Actor: "ann", Action: "assign", Project: "shop,wiki", Env: ""}),
	)
	s := open(t, cfg, st, "alice")

	d, err := s.IssueDetailIn("CVE-2026-1", query.Filter{Project: "wiki"})
	if err != nil || rows([]query.Issue{d.Issue}) != "globex/wiki/prod" || len(d.Targets) != 1 || len(d.Issue.Targets) != 1 {
		t.Fatalf("detail: %+v %v", d.Issue.Targets, err)
	}
	for _, h := range d.History {
		if strings.Contains(h.Project, "shop") || strings.Contains(h.Detail, "shop") {
			t.Errorf("history of another project: %+v", h)
		}
	}
	if strings.Contains(d.Markdown, "shop") || strings.Contains(d.Markdown, "crm") {
		t.Errorf("the report names another project:\n%s", d.Markdown)
	}

	p, err := s.EvidenceIn("CVE-2026-1", query.Filter{Vendor: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range p.Matrix {
		if r.Vendor != "acme" {
			t.Errorf("matrix row of another vendor: %+v", r)
		}
	}
	if len(p.Matrix) != 3 {
		t.Errorf("matrix: %+v", p.Matrix)
	}
	for _, e := range p.Timeline {
		if e.Source == "audit" && (strings.Contains(e.Project, "wiki") || strings.Contains(e.Detail, "wiki")) {
			t.Errorf("audit record of another vendor: %+v", e)
		}
	}
	if p.AuditNote != "" && !p.AuditIntact {
		t.Errorf("narrowing is not a broken chain: %q", p.AuditNote)
	}

	all, err := s.IssueDetail("CVE-2026-1")
	if err != nil || len(all.Issue.Targets) != 5 {
		t.Fatalf("no filter lists everything: %v", err)
	}
	if none, err := s.IssueDetailIn("CVE-2026-1", query.Filter{Vendor: "nobody"}); err != nil || len(none.Issue.Targets) != 0 {
		t.Errorf("a context with no row of the issue shows none: %+v %v", none.Issue.Targets, err)
	}
}

func TestProjectViewAndSetVendorNeedFullAccess(t *testing.T) {
	root := t.TempDir()
	put := func(rel, body string) {
		t.Helper()
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	put("config/techs.yaml", "techs: [{name: php}]\n")
	put("config/projects/shop.yaml", "name: shop\nvendor: acme\nenvs: [dev]\n")
	put("config/projects/blog.yaml", "name: blog\nenvs: [dev]\n")
	put("config/config.yaml", "access:\n  ann: {projects: ['vendor:acme'], write: true}\n  root: {projects: ['*'], write: true}\n")

	set := func(actor, project, vendor string) (ProjectPreview, error) {
		t.Helper()
		s, err := Open(root, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		s.Actor = actor
		return s.EditProject(ProjectChange{Project: project, Ops: []projectfile.Op{{Kind: "set_vendor", Vendor: vendor}}, Save: true})
	}

	prev, err := set("ann", "shop", "other")
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("a vendor grant may not move its project to another vendor: %v", err)
	}
	if prev.Result.Vendor != "other" {
		t.Errorf("the preview still shows the result: %+v", prev.Result)
	}
	if b, _ := os.ReadFile(filepath.Join(root, "config", "projects", "shop.yaml")); !strings.Contains(string(b), "vendor: acme") {
		t.Fatalf("the file changed:\n%s", b)
	}
	if _, err := set("root", "blog", "acme"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(root, "config", "projects", "blog.yaml")); !strings.Contains(string(b), "name: blog\nvendor: acme\n") {
		t.Fatalf("file:\n%s", b)
	}
	if _, err := set("root", "blog", "Not A Slug"); err == nil {
		t.Error("a bad vendor must be refused")
	}
	if _, err := set("ann", "blog", ""); !errors.Is(err, ErrDenied) {
		t.Errorf("blog joined acme, so ann's grant covers it, but she may not change its vendor: %v", err)
	}
}

func TestViewOfShowsTheVendor(t *testing.T) {
	if v := ViewOf(model.Project{Name: "shop", Vendor: "acme"}); v.Vendor != "acme" {
		t.Errorf("%+v", v)
	}
	if v := ViewOf(model.Project{Name: "shop"}); v.Vendor != "" {
		t.Errorf("%+v", v)
	}
}
