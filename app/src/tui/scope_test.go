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
	"github.com/b070nd/cvewatch/app/src/query"
)

// scopeTo sets the scope the way a screen does and lets the model lay out again.
func scopeTo(d *driver, project string) {
	d.m.(*app).setScope(project)
	d.send(tea_window(120, 40))
}

func overdueSeed(t *testing.T) *driver {
	t.Helper()
	st := seed(t, func(l *ledger.Ledger) {
		due := tNow.Add(-72 * time.Hour)
		l.Update(l.Lookup([]string{"CVE-2026-3"}).ID, "shop", model.EnvDev, ledger.Update{Due: &due}, t0)
		l.Update(l.Lookup([]string{"CVE-2026-1"}).ID, "mw", model.EnvProd, ledger.Update{Due: &due}, t0)
	})
	return start(t, newFake(t, st), Options{})
}

func TestNarrowKeepsTheTargetsOfTheProjectAndWhatFollowsThem(t *testing.T) {
	issues := []query.Issue{
		{ID: "A", ProdOpen: true, Applies: model.AppAffected, Targets: []query.Target{
			{Project: "shop", Env: model.EnvDev, Status: model.StatusOpen, Applies: model.AppUnknown},
			{Project: "mw", Env: model.EnvProd, Status: model.StatusOpen, Applies: model.AppAffected},
		}},
		{ID: "B", Targets: []query.Target{{Project: "mw", Env: model.EnvDev, Status: model.StatusOpen}}},
	}
	got := narrow(issues, "shop")
	if len(got) != 1 || got[0].ID != "A" || len(got[0].Targets) != 1 || got[0].Targets[0].Project != "shop" {
		t.Fatalf("narrowed %+v", got)
	}
	if got[0].ProdOpen || got[0].Applies != model.AppUnknown {
		t.Fatalf("what follows the targets was kept from the other project: %+v", got[0])
	}
	if len(issues[0].Targets) != 2 || !issues[0].ProdOpen {
		t.Fatal("narrowing changed the snapshot")
	}
	if got := narrow(issues, "none"); len(got) != 0 {
		t.Fatalf("an unknown project has no issues: %+v", got)
	}
}

func TestScopeNarrowsOverviewFindingsAndCounts(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	d.want("open issues 3", "open findings 4", "3 of 3 open issues")
	d.wantNot("scope:")
	scopeTo(d, "mw")

	d.want("scope: mw", "open issues 1", "open findings 1", "in prod 1", "1 of 1 open issues", "CVE-2026-1", "all projects")
	d.wantNot("CVE-2026-3", "CVE-2026-4")
	v := d.view()
	for _, re := range []string{`high 1\s`, `critical 0\s`, `low 0\s`, `prod 1\s`} {
		if !regexp.MustCompile(re).MatchString(v) {
			t.Errorf("the bars lack %q:\n%s", re, v)
		}
	}
	if regexp.MustCompile(`staging \d`).MatchString(v) {
		t.Errorf("the bars list an environment the scoped project does not run in:\n%s", v)
	}
	d.want("2 Findings (1)")

	d.press("2")
	d.want("1 of 1 open issues", "CVE-2026-1")
	d.wantNot("shop", "CVE-2026-3", "CVE-2026-4") // mw runs in prod only, so the row names the project alone
	if line := strings.Split(d.view(), "\n")[1]; !strings.Contains(line, "scope: mw") {
		t.Fatalf("the chip is on the breadcrumb line of every screen: %q", line)
	}
	d.press("3")
	d.want("scope: mw")

	scopeTo(d, "shop")
	d.press("2")
	d.want("3 of 3 open issues", "shop:prod")
	d.wantNot("mw") // only the targets of the project are shown
	d.press("1")
	d.want("open issues 3", "open findings 3")
}

func TestScopeNarrowsPolicyViolations(t *testing.T) {
	d := overdueSeed(t)
	d.want("policy violations 2")
	scopeTo(d, "mw")
	d.want("policy violations 1")
	d.press("v")
	d.want("CVE-2026-1")
	d.wantNot("CVE-2026-3")
}

func TestSearchAndSeverityWorkWithinTheScope(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	scopeTo(d, "shop")
	d.press("/")
	d.typ("severity:high")
	d.press("enter")
	d.want("1 of 3 open issues", "CVE-2026-1")
	d.wantNot("CVE-2026-3")
	d.press("esc", "/")
	d.typ("project:mw") // the issues of mw are not in this scope
	d.press("enter")
	d.want("0 of 3 open issues", "No issue matches the filter")
	d.press("esc")
	d.press("2", "s")
	d.want("min severity: low+", "3 of 3 open issues")
	d.press("s", "s", "s")
	d.want("min severity: critical+", "1 of 3 open issues")
	d.press("/")
	d.typ("mw")
	d.want("0 of 3 open issues")
}

func TestScopeIsClearedByKeyAndByClickingTheChip(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	d.press("0") // nothing to clear: the key does nothing
	d.wantNot("scope cleared")
	a := d.m.(*app)

	scopeTo(d, "mw")
	d.want("0 all projects") // the footer tells how to leave the scope
	d.press("0")
	if a.scope != "" {
		t.Fatalf("scope %q after 0", a.scope)
	}
	d.want("scope cleared", "open issues 3")
	d.wantNot("scope: mw", "0 all projects")

	scopeTo(d, "mw")
	line := strings.Split(d.view(), "\n")[1]
	d.click(width(line[:strings.Index(line, "scope: mw")])+2, 1)
	if a.scope != "" {
		t.Fatalf("a click on the chip left the scope %q", a.scope)
	}
	d.want("open issues 3", "3 of 3 open issues")

	scopeTo(d, "mw")
	d.click(2, 1) // the rest of the breadcrumb line is not the chip
	if a.scope != "mw" {
		t.Fatal("a click beside the chip cleared the scope")
	}
	d.press("?")
	d.want("show all projects again")
}

func TestScopeSurvivesARefreshAndFollowsNewData(t *testing.T) {
	b := newFake(t, nil)
	d := start(t, b, Options{})
	scopeTo(d, "mw")
	d.press("r")
	d.want("scope: mw", "open issues 1")

	if err := b.Write(func(s *ops.Session) error {
		_, err := s.Resolve(ops.Change{ID: "CVE-2026-1", Project: "mw", Status: model.StatusFixed})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	d.press("r")
	d.want("scope: mw", "open issues 0", "Nothing open in project mw")
	d.press("0")
	d.want("open issues 3", "open findings 3") // it is still open in shop
}

func TestScopeIsDroppedWhenItsProjectIsGone(t *testing.T) {
	b := newFake(t, nil)
	d := start(t, b, Options{})
	scopeTo(d, "mw")
	d.press("2")
	d.want("1 of 1 open issues")

	b.backfillFn = func(context.Context, func(ops.RefreshProgress)) (pipeline.Result, error) {
		return pipeline.Result{}, nil
	}
	b.cfg.Projects = b.cfg.Projects[:1] // mw is deleted
	d.press("r")
	a := d.m.(*app)
	if a.scope != "" {
		t.Fatalf("scope %q for a project that is gone", a.scope)
	}
	d.want("scope cleared: project mw is gone", "3 of 3 open issues")
	d.wantNot("scope: mw")
	d.press("1")
	d.want("open issues 3")
}

func TestSetScopeRefusesAnUnknownProject(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	a := d.m.(*app)
	a.setScope("nowhere")
	if a.scope != "" || !a.flashErr {
		t.Fatalf("scope %q, flash %q", a.scope, a.flash)
	}
	a.setScope("")
	a.clearScope()
	if a.scope != "" {
		t.Fatal("an empty project is no scope")
	}
}

func TestScopeKeepsTheCursorOnItsIssueAndPrunesTheSelection(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	d.press("2", "down", "down") // CVE-2026-4
	d.press(" ")
	a := d.m.(*app)
	if !a.fnd.sel["CVE-2026-4"] {
		t.Fatalf("selection %v", a.fnd.sel)
	}
	scopeTo(d, "mw")
	if len(a.fnd.sel) != 0 {
		t.Fatalf("a selected issue left the list: %v", a.fnd.sel)
	}
	scopeTo(d, "shop")
	d.press("2")
	d.want("3 of 3 open issues")
}
