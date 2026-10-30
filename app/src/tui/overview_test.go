package tui

import (
	"strings"
	"testing"
)

func TestOverviewListsEveryLoadedIssueBelowTheSummary(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	d.want("Status", "last cycle:", "open issues 3", "by severity", "by environment",
		"3 of 3 open issues", "SEVERITY", "> critical", "CVE-2026-3", "Critical nginx bug", "CVE-2026-1", "CVE-2026-4", "Minor thing",
		"enter open", "/ filter", "s severity", "v violations")
	v := d.view()
	if strings.Index(v, "open issues 3") > strings.Index(v, "CVE-2026-3") {
		t.Errorf("the summary comes first:\n%s", v)
	}
	a := d.m.(*app)
	d.press("down")
	if a.ovw.vp.at() != 1 || a.fnd.vp.at() != 0 {
		t.Fatalf("the overview moves its own cursor: %d, findings %d", a.ovw.vp.at(), a.fnd.vp.at())
	}
	d.press("end")
	d.want("> low")
	d.press("home")
	d.want("> critical")
}

func TestOverviewSearchSelectOpenAndBack(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	a := d.m.(*app)
	d.press("/")
	d.want("filter: ")
	d.typ("tracked")
	d.want("1 of 3 open issues", "Tracked PHP bug")
	d.wantNot("Critical nginx bug")
	d.press("enter")
	d.want("filter: tracked")
	if a.fnd.text != "" || len(a.fnd.vis) != 3 {
		t.Fatalf("the overview search must not narrow the findings: %q, %d", a.fnd.text, len(a.fnd.vis))
	}

	d.press("enter") // opens the issue
	d.want("[2 Findings (3)]", "Environments")
	if a.fnd.det == nil || a.fnd.det.id != "CVE-2026-1" {
		t.Fatalf("opened %+v", a.fnd.det)
	}
	if got := crumbsText(d); !strings.HasPrefix(got, "Findings > CVE-2026-1") {
		t.Fatalf("crumbs %q", got)
	}
	d.press("esc") // back where the issue was opened from
	d.want("[1 Overview]", "filter: tracked", "1 of 3 open issues")
	d.wantNot("Environments")

	d.press("esc") // the first esc clears the filter
	d.want("3 of 3 open issues")
	d.wantNot("filter: tracked")
	d.press("down", "down", "enter")
	if a.fnd.det == nil || a.fnd.det.id != "CVE-2026-4" {
		t.Fatalf("the selected row opens: %+v", a.fnd.det)
	}
	d.press("left")
	d.want("[1 Overview]")
}

func TestOverviewSearchSyntaxAndSeverityMatchTheFindings(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	for _, q := range []string{"severity:high", "env:dev", "project:mw", "CVE-2026-4", "bug -severity:critical"} {
		d.press("/")
		d.typ(q)
		d.press("enter")
		overview := len(d.m.(*app).ovw.vis)
		d.press("esc", "2", "/")
		d.typ(q)
		d.press("enter")
		if findings := len(d.m.(*app).fnd.vis); findings != overview || overview == 0 {
			t.Errorf("%q: overview %d, findings %d", q, overview, findings)
		}
		d.press("esc", "1")
	}
	d.press("s")
	d.want("min severity: low+")
	d.press("s", "s", "s")
	d.want("1 of 3 open issues", "Critical nginx bug")
	d.press("s")
	d.want("3 of 3 open issues")
	d.press("/")
	d.typ("zzz")
	d.press("enter")
	d.want("No issue matches the filter")
}

func TestOverviewPolicyViolationsStayReachable(t *testing.T) {
	d := overdueSeed(t)
	a := d.m.(*app)
	d.want("policy violations 2", "v violations")
	d.press("v")
	d.want("[1 Overview]", "Policy violations", "> - due date", "enter open", "back")
	d.wantNot("SEVERITY") // the list gives way to the violations
	d.press("down", "up", "enter")
	d.want("[2 Findings (3)]", "Environments")
	d.press("esc")
	d.want("[1 Overview]", "Policy violations")
	d.press("esc")
	d.want("3 of 3 open issues")
	d.wantNot("> - due date")
	if a.ovw.viol {
		t.Fatal("esc closes the violations")
	}
	d.press("v", "q")
	d.want("3 of 3 open issues")
	d.press("v")
	d.click(2, 1) // the breadcrumb: Overview
	d.want("3 of 3 open issues")
}

func TestOverviewWithoutViolationsSaysSo(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	d.press("v")
	d.want("Policy violations", "none")
	d.press("enter") // nothing to open
	d.want("[1 Overview]")
}

func TestOverviewRowsRespondToTheMouseOnTheList(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	a := d.m.(*app)
	rows := func(i int) int { return bodyTop + a.ovw.top + 2 + i } // the count line and the column heads come first
	d.click(10, rows(1))
	if a.ovw.vp.at() != 1 || a.fnd.det != nil {
		t.Fatalf("a click selects: at %d", a.ovw.vp.at())
	}
	d.click(10, rows(1))
	if a.fnd.det == nil || a.fnd.det.id != "CVE-2026-1" || a.scr != scrFindings {
		t.Fatalf("a second click opens: screen %d, %+v", a.scr, a.fnd.det)
	}
	d.press("esc")
	d.click(10, rows(5)) // below the rows
	d.click(10, rows(-1))
	if a.ovw.vp.at() != 1 {
		t.Fatalf("a click outside the rows moved the cursor to %d", a.ovw.vp.at())
	}
	d.wheel(false, 10, rows(0))
	if a.ovw.vp.at() != 2 {
		t.Fatalf("the wheel moves the cursor: %d", a.ovw.vp.at())
	}
}

func TestOverviewKeepsTheListWhenTheScreenIsShort(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	for _, h := range []int{9, 12, 16, 24} {
		d.send(tea_window(80, h))
		d.want("Status", "3 of 3 open issues")
		if lines := strings.Count(d.view(), "\n") + 1; lines > h {
			t.Errorf("height %d: %d lines", h, lines)
		}
	}
	d.send(tea_window(80, 12))
	d.want("> critical", "CVE-2026-3")
	d.press("end")
	d.want("> low", "CVE-2026-4")
	d.wantNot("by environment") // the less important blocks go first
	d.send(tea_window(80, 40))
	d.want("by severity", "by environment", "last cycle:")
	d.send(tea_window(30, 12))
	for _, l := range strings.Split(d.view(), "\n") {
		if width(l) > 30 {
			t.Errorf("a line of %d cells at width 30: %q", width(l), l)
		}
	}
}

func TestOverviewShowsWarnings(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	a := d.m.(*app)
	a.data.Warnings = []string{"policy: boom", "project files: two"}
	d.send(tea_window(120, 40))
	d.want("! policy: boom", "and 1 more")
	d.press("v")
	d.want("Warnings", "! policy: boom", "! project files: two")
}
