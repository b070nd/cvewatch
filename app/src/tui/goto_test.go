package tui

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/b070nd/cvewatch/app/src/ledger"
	"github.com/b070nd/cvewatch/app/src/model"
)

func crumbsText(d *driver) string {
	var out []string
	for _, c := range d.m.(*app).crumbs() {
		out = append(out, c.label)
	}
	return strings.Join(out, " > ")
}

func TestDetailGoesToItsProjectAndBackWithEsc(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	d.screen("findings")
	d.press("down", "enter") // CVE-2026-1: the page starts on shop/prod
	d.want("> shop", "p to project")
	d.press("p")
	d.want("▸[P]rojects", "> shop")
	if got := crumbsText(d); got != "Projects" {
		t.Fatalf("crumbs %q", got)
	}
	d.want("esc back")
	d.press("esc")
	d.want("▸[F]indings (3)", "CVE-2026-1", "Environments", "> shop")
	if got := crumbsText(d); got != "Findings > CVE-2026-1 > shop:prod" {
		t.Fatalf("crumbs %q", got)
	}

	d.press("p")
	d.want("▸[P]rojects", "> shop")
	d.press("backspace")
	d.want("Environments", "> shop") // the environment row comes back too
	d.press("esc")
	d.want("3 of 3 open issues") // the way back is used up: esc is the plain back again
	d.press("esc")
	d.want("3 of 3 open issues")
}

func TestJumpBackIsForgottenWhenTheScreenChanges(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	d.screen("findings")
	d.press("enter", "p")
	d.want("▸[P]rojects")
	d.press("tab")
	d.screen("projects")
	if d.m.(*app).ret != nil {
		t.Fatal("the way back survived a change of screen")
	}
	d.press("esc")
	d.want("▸[P]rojects")
}

func TestProjectGoesToItsFindingsInItsContext(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	d.screen("projects")
	d.press("down") // mw
	d.want("> mw", "i issues")
	d.press("i")
	d.want("▸[F]indings (1)", "1 of 1 open issues", "context: mw", "CVE-2026-1")
	d.wantNot("CVE-2026-3", "CVE-2026-4")
	d.press("esc") // back to the project; the context stays
	d.want("▸[P]rojects", "> mw", "context: mw")
	d.screen("findings")
	d.want("1 of 1 open issues")

	scopeTo(d, "shop")
	d.screen("projects")
	d.press("up", "enter", "i") // from inside the project too
	d.want("▸[F]indings (3)", "context: shop", "3 of 3")
	d.press("/")
	d.typ("env:prod")
	d.press("enter")
	d.want("filter: env:prod", "1 of 3")
	d.press("esc") // a filter typed afterwards is cleared first
	d.wantNot("filter:")
	d.want("▸[F]indings (3)")
	d.press("esc") // back inside the project it came from
	d.want("▸[P]rojects")
	if got := crumbOf(d); got != "Projects › shop" {
		t.Fatalf("crumb %q", got)
	}
}

func TestOverviewViolationsAreSelectableAndOpenTheirIssue(t *testing.T) {
	st := seed(t, func(l *ledger.Ledger) {
		due := tNow.Add(-72 * time.Hour)
		l.Update(l.Lookup([]string{"CVE-2026-3"}).ID, "shop", model.EnvDev, ledger.Update{Due: &due}, t0)
		l.Update(l.Lookup([]string{"CVE-2026-4"}).ID, "shop", model.EnvStaging, ledger.Update{Due: &due}, t0)
	})
	d := start(t, newFake(t, st), Options{})
	d.want("policy violations 2", "v violations")
	d.press("v")
	d.want("Policy violations", "> - due date", "enter open")
	if got := crumbsText(d); got != "Overview > Policy violations" {
		t.Fatalf("crumbs %q", got)
	}
	a := d.m.(*app)
	first := a.pageSel[scrOverview].id()
	d.press("down")
	if a.pageSel[scrOverview].id() == first {
		t.Fatal("down must select the next violation")
	}
	d.press("up", "enter")
	d.want("▸[F]indings (3)", "Environments")
	id := a.fnd.det.id
	if id != "CVE-2026-3" && id != "CVE-2026-4" {
		t.Fatalf("opened %q", id)
	}
	if got := crumbsText(d); !strings.HasPrefix(got, "Findings > CVE-2026-") {
		t.Fatalf("crumbs %q", got)
	}
	d.press("esc") // the jump came from the overview: back returns there
	d.want("▸[O]verview", "Policy violations")
	d.press("pgdown", "home")
	if a.pageSel[scrOverview].id() == "" {
		t.Fatal("scrolling keeps the selection")
	}
}

func TestStatusErrorsOpenDetailsOrTheProjectTheyName(t *testing.T) {
	st := seed(t, func(l *ledger.Ledger) {
		l.SourceOutcome("hn", "hn", tNow, 0, errors.New("could not read the inventory of project mw: boom"))
	})
	d := start(t, newFake(t, st), Options{})
	d.screen("health")
	d.want("error: could not read", "enter details")
	d.press("enter") // the first row is the problem of the feed, which names the project
	d.want("▸[P]rojects", "> mw")

	st = seed(t, func(l *ledger.Ledger) { l.SourceOutcome("hn", "hn", tNow, 0, errors.New("dial tcp: no route")) })
	d = start(t, newFake(t, st), Options{})
	d.screen("health")
	d.press("enter")
	d.want("▸[H]ealth", "feed hn had a failed fetch", "dial tcp: no route", "enter or esc: close")
	d.press("esc")
	d.wantNot("enter or esc: close")
	d.want("▸[H]ealth")
}

func jumpLabels(d *driver) string {
	var out []string
	for _, it := range d.m.(*app).jmp.items {
		out = append(out, it.label)
	}
	return strings.Join(out, ",")
}

func TestJumpBoxFindsAnIssueAndAProject(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	d.press(":")
	d.want("Go to an issue or a project", "CVE-2026-3", "CVE-2026-1", "shop", "mw", "project")
	d.typ("cve-2026-4")
	d.want("> CVE-2026-4", "low Minor thing")
	if got := jumpLabels(d); got != "CVE-2026-4" { // the list under the box is the overview's, not the box's
		t.Fatalf("suggestions %q", got)
	}
	d.press("enter")
	d.want("▸[F]indings (3)", "Minor thing", "Environments")
	if got := crumbsText(d); got != "Findings > CVE-2026-4 > shop:staging" {
		t.Fatalf("crumbs %q", got)
	}
	d.press("esc") // the jump came from the overview
	d.want("▸[O]verview")

	d.press("ctrl+g")
	d.typ("sh")
	d.want("> shop")
	if got := jumpLabels(d); !strings.HasPrefix(got, "shop") || strings.Contains(got, "CVE") {
		t.Fatalf("suggestions %q", got)
	}
	d.press("enter")
	d.want("▸[P]rojects", "> shop")
	d.press("esc")
	d.want("▸[O]verview")
	d.screen("findings")

	d.press(":", "esc")
	d.wantNot("Go to an issue")

	d.press(":")
	d.typ("zzz")
	d.want("no issue or project matches")
	d.press("enter")
	d.want("error: nothing matches zzz")
	d.want("Go to an issue") // the box stays open
	d.press("ctrl+u")
	d.typ("CVE-2000-9") // not an open issue: tried as an id
	d.press("enter")
	d.want("Findings", "CVE-2000-9")
	d.wantNot("Go to an issue")
}

func TestJumpBoxSuggestsWhatStartsWithTheTextFirst(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	a := d.m.(*app)
	a.data.Projects = append(a.data.Projects[:0:0], projectRow{}, projectRow{}, projectRow{})
	a.data.Projects[0].Name, a.data.Projects[1].Name, a.data.Projects[2].Name = "a-shop", "shop", "shopify"
	var got []string
	for _, it := range a.suggestions("shop") {
		got = append(got, it.label)
	}
	if strings.Join(got, ",") != "shop,shopify,a-shop" {
		t.Fatalf("suggestions %v", got)
	}
	if n := len(a.suggestions("")); n != 6 {
		t.Fatalf("empty text lists everything: %d", n)
	}
	if n := len(a.suggestions("2026-3")); n != 1 {
		t.Fatalf("an id is found by a part of it: %d", n)
	}
}

func TestJumpKeysAreTypedIntoTextFields(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	d.screen("findings")
	d.press("/")
	d.typ(":")
	d.want("filter: :")
	d.wantNot("Go to an issue")
	d.press("esc")
	d.screen("findings")
	d.press("enter", "f")
	d.typ(":")
	d.wantNot("Go to an issue")
}

func TestJumpIsInTheFooterAndTheHelp(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	for _, key := range []string{"O", "F", "H"} { // the projects footer is full: the least important hints go first
		d.press(key)
		d.want(": jump")
	}
	d.press("?")
	d.want("jump to an issue by id or a project by name")
}

func TestOverviewRowsRespondToTheMouse(t *testing.T) {
	st := seed(t, func(l *ledger.Ledger) {
		due := tNow.Add(-72 * time.Hour)
		l.Update(l.Lookup([]string{"CVE-2026-3"}).ID, "shop", model.EnvDev, ledger.Update{Due: &due}, t0)
		l.Update(l.Lookup([]string{"CVE-2026-4"}).ID, "shop", model.EnvStaging, ledger.Update{Due: &due}, t0)
	})
	d := start(t, newFake(t, st), Options{})
	d.press("v")
	a := d.m.(*app)
	rows := a.page(scrOverview, 120).rows
	if len(rows) != 2 {
		t.Fatalf("rows %+v", rows)
	}
	y := bodyTop + a.ovw.top + rows[1].at - a.txt[scrOverview].at()
	d.click(10, y)
	if a.pageSel[scrOverview].at() != 1 {
		t.Fatal("a click selects the row")
	}
	d.wheel(false, 10, 10) // the wheel scrolls the page, not the selection
	if a.pageSel[scrOverview].at() != 1 {
		t.Fatal("the wheel moved the selection")
	}
	y = bodyTop + a.ovw.top + rows[1].at - a.txt[scrOverview].at()
	d.click(10, y) // a second click opens
	if a.scr != scrFindings || a.fnd.det == nil || a.fnd.det.id != rows[1].tgt.issue {
		t.Fatalf("screen %d, page %+v, want %s", a.scr, a.fnd.det, rows[1].tgt.issue)
	}
}
