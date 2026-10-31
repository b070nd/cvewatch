package tui

import (
	"context"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/b070nd/cvewatch/app/src/ledger"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/ops"
	"github.com/b070nd/cvewatch/app/src/pipeline"
)

// scopeTo moves the context to a project, or to all projects when it is empty.
func scopeTo(d *driver, project string) {
	d.m.(*app).setTenant(tenant{project: project}, false)
	d.send(tea_window(120, 40))
}

// seeInside fails when the screen names the project as a word, which it never
// does for a project outside the context.
func neverNames(t *testing.T, d *driver, project string) {
	t.Helper()
	if regexp.MustCompile(`(^|[^A-Za-z0-9_-])` + regexp.QuoteMeta(project) + `([^A-Za-z0-9_-]|$)`).MatchString(d.view()) {
		t.Errorf("the screen names %q, which is outside the context:\n%s", project, d.view())
	}
}

func lineWith(d *driver, part string) string {
	for _, l := range strings.Split(d.view(), "\n") {
		if strings.Contains(l, part) {
			return l
		}
	}
	return ""
}

func overdueSeed(t *testing.T) *driver {
	t.Helper()
	st := seed(t, func(l *ledger.Ledger) {
		due := tNow.Add(-72 * time.Hour)
		l.Update(l.Lookup([]string{"CVE-2026-3"}).ID, "shop", model.EnvDev, ledger.Update{Due: &due}, t0)
		l.Update(l.Lookup([]string{"CVE-2026-4"}).ID, "shop", model.EnvStaging, ledger.Update{Due: &due}, t0)
		l.Update(l.Lookup([]string{"CVE-2026-1"}).ID, "mw", model.EnvProd, ledger.Update{Due: &due}, t0)
	})
	return start(t, newFake(t, st), Options{})
}

func TestContextNarrowsOverviewFindingsAndCounts(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	d.want("context: shop", "open issues 3", "open findings 3", "3 of 3 open issues", "[F]indings (3)")
	neverNames(t, d, "mw")

	scopeTo(d, "mw")
	d.want("context: mw", "open issues 1", "open findings 1", "in prod 1", "1 of 1 open issues", "CVE-2026-1", "[F]indings (1)")
	d.wantNot("CVE-2026-3", "CVE-2026-4", "shop")
	v := d.view()
	for _, re := range []string{`high 1\s`, `critical 0\s`, `low 0\s`, `prod 1\s`} {
		if !regexp.MustCompile(re).MatchString(v) {
			t.Errorf("the bars lack %q:\n%s", re, v)
		}
	}

	d.screen("findings")
	d.want("1 of 1 open issues", "CVE-2026-1", "context: mw")
	d.wantNot("shop", "CVE-2026-3", "CVE-2026-4")
	if line := crumbLineOf(d); !strings.Contains(line, "context: mw") {
		t.Fatalf("the chip is on the breadcrumb line of every screen: %q", line)
	}
	d.screen("projects")
	d.want("context: mw")

	scopeTo(d, "shop")
	d.screen("findings")
	d.want("3 of 3 open issues", "shop:prod")
	neverNames(t, d, "mw")
	d.screen("overview")
	d.want("open issues 3", "open findings 3")
	neverNames(t, d, "mw")
}

func TestNoRowOfAnotherProjectIsOnAnyScreenOfAContext(t *testing.T) {
	for _, c := range []struct{ in, out, id string }{{"shop", "mw", "CVE-2026-3"}, {"mw", "shop", "CVE-2026-1"}} {
		d := startIn(t, newFake(t, nil), Options{}, tenant{project: c.in})
		for _, sc := range []string{"overview", "findings"} {
			d.screen(sc)
			neverNames(t, d, c.out)
		}
		d.screen("findings")
		d.press("enter")
		d.want("Environments")
		neverNames(t, d, c.out)
		d.press("a")
		d.want("Assign")
		neverNames(t, d, c.out)
		d.press("esc")
		d.press("+")
		d.want("Add evidence")
		neverNames(t, d, c.out)
		d.press("esc", "esc")

		d.press(":")
		d.typ("CVE")
		if c.in == "mw" {
			d.wantNot("CVE-2026-3", "CVE-2026-4")
		} else {
			d.wantNot("mw")
		}
		d.press("esc")
	}
}

func TestContextSearchAndSeverityWorkInsideIt(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	d.press("/")
	d.typ("severity:high")
	d.press("enter")
	d.want("1 of 3 open issues", "CVE-2026-1")
	d.wantNot("CVE-2026-3")
	d.press("esc", "/")
	d.typ("project:mw") // the issues of mw are not in this context
	d.press("enter")
	d.want("0 of 3 open issues", "No issue matches the filter")
	d.press("esc")
	d.screen("findings")
	d.press("s")
	d.want("min severity: low+", "3 of 3 open issues")
	d.press("s", "s", "s")
	d.want("min severity: critical+", "1 of 3 open issues")
	d.press("/")
	d.typ("mw")
	d.want("0 of 3 open issues")
}

func TestContextNarrowsPolicyViolations(t *testing.T) {
	d := overdueSeed(t)
	d.want("policy violations 2") // the two of shop
	scopeTo(d, "")
	d.want("policy violations 3", "context: all projects")
	scopeTo(d, "mw")
	d.want("policy violations 1")
	d.press("v")
	d.want("CVE-2026-1")
	d.wantNot("CVE-2026-3")
}

func TestViolationOfAnotherProjectOpensInThatProject(t *testing.T) {
	d := overdueSeed(t)
	scopeTo(d, "")
	d.press("v")
	d.press("enter") // the first violation is the one of mw
	d.want("Environments", "CVE-2026-1", "context: mw")
	if d.app().tenant != (tenant{project: "mw"}) {
		t.Fatalf("context %+v", d.app().tenant)
	}
	neverNames(t, d, "shop")
}

func TestContextPickerSetsTheContextAndEscKeepsIt(t *testing.T) {
	d := startAll(t, newFake(t, nil), Options{})
	a := d.app()
	d.want("context: all projects")
	d.press("C")
	d.want("Choose the context", "all projects", "shop", "mw")
	d.press("esc")
	d.wantNot("Choose the context")
	if !a.tenant.all() {
		t.Fatalf("esc changed the context to %+v", a.tenant)
	}

	d.press("C", "down", "enter")
	if a.tenant != (tenant{project: "shop"}) {
		t.Fatalf("context %+v", a.tenant)
	}
	d.want("ok: context: shop", "open issues 3")
	d.press("C")
	d.want("Choose the context")
	if got := a.chs.vp.at(); got != 1 {
		t.Fatalf("the cursor is on the current context, row %d", got)
	}
	d.press("down", "enter")
	d.want("context: mw", "open issues 1")
	d.wantNot("context: shop")
	d.press("C", "home", "enter")
	d.want("context: all projects")
	d.wantNot("context: mw")
}

func TestContextIsChosenOnTheProjectsScreen(t *testing.T) {
	d := startAll(t, newFake(t, nil), Options{})
	d.screen("projects")
	d.press("down", "enter")
	d.want("Projects › mw", "Security issues")
	if got := d.app().tenant; got != (tenant{project: "mw"}) {
		t.Fatalf("entering a project sets the context: %+v", got)
	}
	d.want("context: mw")
}

func TestOnePortfolioProjectIsTheContextAutomatically(t *testing.T) {
	b := newFake(t, nil)
	b.cfg.Projects = b.cfg.Projects[:1]
	d := startAll(t, b, Options{})
	a := d.app()
	if a.tenant != (tenant{project: "shop"}) || !a.tenantAuto {
		t.Fatalf("context %+v auto %v", a.tenant, a.tenantAuto)
	}
	d.want("context: shop", "3 of 3 open issues")
	d.screen("findings")
	d.want("3 of 3 open issues")
	d.wantNot("all projects")
}

func TestAllProjectsShowsOneSectionPerProjectNeverMergedRows(t *testing.T) {
	d := startAll(t, newFake(t, nil), Options{})
	d.want("context: all projects", "shop", "3 open issues", "mw", "1 open issue")
	n := 0
	for _, l := range strings.Split(d.view(), "\n") {
		if !strings.Contains(l, "CVE-2026-1") {
			continue
		}
		n++
		if strings.Contains(l, "shop") == strings.Contains(l, " mw ") {
			t.Errorf("a row belongs to one project: %q", l)
		}
	}
	if n != 2 {
		t.Fatalf("CVE-2026-1 is one row in each project, got %d:\n%s", n, d.view())
	}
	d.screen("findings")
	d.want("[F]indings (4)", "4 of 4 open issues")
}

func TestOpeningAnIssueOfAllProjectsEntersItsProject(t *testing.T) {
	d := startAll(t, newFake(t, nil), Options{})
	a := d.app()
	d.press("down", "down", "down") // the section of mw: CVE-2026-1
	d.press("enter")
	d.want("Environments", "CVE-2026-1", "context: mw")
	if a.tenant != (tenant{project: "mw"}) {
		t.Fatalf("context %+v", a.tenant)
	}
	neverNames(t, d, "shop")

	d = startAll(t, newFake(t, nil), Options{})
	a = d.app()
	d.screen("findings")
	d.press("enter")
	d.want("Environments", "CVE-2026-3", "context: shop")
	if a.tenant != (tenant{project: "shop"}) {
		t.Fatalf("context %+v", a.tenant)
	}
	neverNames(t, d, "mw")
}

// vendorFake has shop and blog under acme and mw under globex; CVE-2026-1 is open in all three.
func vendorFake(t *testing.T) *fake {
	t.Helper()
	st := seed(t, func(l *ledger.Ledger) {
		l.AddFinding(model.Finding{VulnID: l.Lookup([]string{"CVE-2026-1"}).ID, Project: "blog", Env: model.EnvProd, Status: model.StatusOpen, Applies: model.AppUnknown})
	})
	b := newFake(t, st)
	b.cfg.Projects[0].Vendor = "acme"
	b.cfg.Projects[1].Vendor = "globex"
	b.cfg.Projects = append(b.cfg.Projects, model.Project{Name: "blog", Vendor: "acme", Envs: []model.Env{model.EnvProd}})
	markJudged(t, b.cfg, st)
	return b
}

func TestVendorContextGroupsItsProjectsAndNeverMergesRows(t *testing.T) {
	d := startAll(t, vendorFake(t), Options{})
	a := d.app()
	d.press("C")
	d.want("Choose the context", "acme"+arrow+"all projects", "acme"+arrow+"shop", "acme"+arrow+"blog", "globex"+arrow+"mw")
	d.press("down", "enter") // acme ▸ all projects
	if a.tenant != (tenant{vendor: "acme"}) {
		t.Fatalf("context %+v", a.tenant)
	}
	d.want("context: acme"+arrow+"all projects", "shop", "blog")
	neverNames(t, d, "mw")
	d.wantNot("globex")
	n := 0
	for _, l := range strings.Split(d.view(), "\n") {
		if strings.Contains(l, "CVE-2026-1") {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("CVE-2026-1 is one row in shop and one in blog, got %d:\n%s", n, d.view())
	}
	d.screen("findings")
	d.want("4 of 4 open issues")
	neverNames(t, d, "mw")

	d.press("down", "down", "down")
	d.press("enter") // the row of blog
	if a.tenant != (tenant{vendor: "acme"}) {
		t.Fatalf("the vendor stays the context, got %+v", a.tenant)
	}
	d.want("Environments", "CVE-2026-1", "blog:prod", "context: acme"+arrow+"all projects")
	neverNames(t, d, "shop")
	neverNames(t, d, "mw")
	d.press("esc")
	d.want("4 of 4 open issues")
}

func TestVendorOfAProjectIsInTheChipOnlyWhenSomeProjectHasOne(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	d.want("context: shop")
	d.wantNot(arrow)
	d = startIn(t, vendorFake(t), Options{}, tenant{project: "shop"})
	d.want("context: acme" + arrow + "shop")
}

func TestContextSurvivesARefreshAndFollowsNewData(t *testing.T) {
	b := newFake(t, nil)
	d := start(t, b, Options{})
	scopeTo(d, "mw")
	d.press("r")
	d.want("context: mw", "open issues 1")

	if err := b.Write(func(s *ops.Session) error {
		_, err := s.Resolve(ops.Change{ID: "CVE-2026-1", Project: "mw", Status: model.StatusFixed})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	d.press("r")
	d.want("context: mw", "open issues 0", "Nothing open in mw")
	scopeTo(d, "shop")
	d.want("open issues 3", "open findings 3") // it is still open in shop
}

func TestContextIsDroppedWhenItsProjectIsGone(t *testing.T) {
	b := newFake(t, nil)
	d := startAll(t, b, Options{})
	scopeTo(d, "mw")
	d.screen("findings")
	d.want("1 of 1 open issues")

	b.backfillFn = func(context.Context, func(ops.RefreshProgress)) (pipeline.Result, error) {
		return pipeline.Result{}, nil
	}
	b.cfg.Projects = b.cfg.Projects[:1] // mw is deleted
	d.press("r")
	a := d.app()
	if a.tenant != (tenant{project: "shop"}) || !a.tenantAuto {
		t.Fatalf("context %+v for a project that is gone", a.tenant)
	}
	d.want("3 of 3 open issues")
	d.wantNot("context: mw")
	d.screen("overview")
	d.want("open issues 3")
}

func TestSetTenantRefusesAnUnknownProjectAndVendor(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	a := d.app()
	a.setTenant(tenant{project: "nowhere"}, false)
	if a.tenant != (tenant{project: "shop"}) || !a.flashErr {
		t.Fatalf("context %+v, flash %q", a.tenant, a.flash)
	}
	a.setTenant(tenant{vendor: "nobody"}, false)
	if a.tenant != (tenant{project: "shop"}) || !a.flashErr {
		t.Fatalf("context %+v, flash %q", a.tenant, a.flash)
	}
}

func TestContextKeepsTheCursorOnItsIssueAndPrunesTheSelection(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	d.screen("findings")
	d.press("down", "down") // CVE-2026-4
	d.press(" ")
	a := d.app()
	if len(a.fnd.sel) != 1 {
		t.Fatalf("selection %v", a.fnd.sel)
	}
	scopeTo(d, "mw")
	if len(a.fnd.sel) != 0 {
		t.Fatalf("a selected issue left the list: %v", a.fnd.sel)
	}
	scopeTo(d, "shop")
	d.screen("findings")
	d.want("3 of 3 open issues")
}

func TestIssuePageOfAContextHasOnlyItsProjectRows(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	d.press("down", "enter")
	d.want("Environments", "CVE-2026-1", "shop:prod")
	neverNames(t, d, "mw")
	d.press("a")
	d.want("Assign CVE-2026-1 in shop/prod")
	d.wantNot("outside")
}

func TestZeroClearsOnlyTheTimeFilterAndTheContextChipOpensThePicker(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	d.press("0")
	d.wantNot("time filter cleared")
	if d.app().tenant != (tenant{project: "shop"}) {
		t.Fatal("0 does not touch the context")
	}
	line := crumbLineOf(d)
	d.click(width(line[:strings.Index(line, "context: shop")])+2, 1)
	d.want("Choose the context")
	d.press("esc")
	d.click(2, 1) // the rest of the breadcrumb line is not the chip
	d.wantNot("Choose the context")
}

func TestMidTruncKeepsTheTail(t *testing.T) {
	for _, tc := range []struct {
		in   string
		w    int
		want string
	}{
		{"shop", 14, "shop"},
		{"astra-low-php-exact", 14, "astr…php-exact"},
		{"astra", 3, "as…"},
	} {
		if got := midTrunc(tc.in, tc.w); got != tc.want || width(got) > tc.w {
			t.Errorf("midTrunc(%q, %d) = %q, want %q", tc.in, tc.w, got, tc.want)
		}
	}
	a, b := midTrunc("astra-low-php-exact", 14), midTrunc("astra-low-php-loose", 14)
	if a == b {
		t.Errorf("names that differ in the tail stay different: %q %q", a, b)
	}
}

func TestProjectsScreenShowsTheVendorColumnOnlyWhenAProjectHasOne(t *testing.T) {
	d := startAll(t, newFake(t, nil), Options{})
	d.screen("projects")
	d.wantNot("VENDOR")

	d = startAll(t, vendorFake(t), Options{})
	d.screen("projects")
	d.want("VENDOR", "acme", "globex", "vendor: acme")
}
