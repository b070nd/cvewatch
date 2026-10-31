package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/ops"
)

func TestNextAndPreviousIssueKeepTheDetailOpen(t *testing.T) {
	b := newFake(t, nil)
	d := start(t, b, Options{})
	d.screen("findings")
	d.press("enter")
	d.want("CVE-2026-3", "Critical nginx bug", "] next", "[ prev")
	d.press("[")
	d.want("CVE-2026-3", "ok: this is the first issue of the list")
	d.press("]")
	d.want("CVE-2026-1", "Tracked PHP bug")
	if got := crumbsText(d); got != "Findings > CVE-2026-1 > mw:prod" {
		t.Fatalf("the breadcrumb follows: %q", got)
	}
	d.press("]")
	d.want("CVE-2026-4", "Minor thing")
	d.press("]")
	d.want("CVE-2026-4", "this is the last issue of the list")
	d.press("[")
	d.want("CVE-2026-1")
	d.press("K")
	d.want("CVE-2026-3")
	d.press("J", "J")
	d.want("CVE-2026-4")
	d.press("esc")
	d.want("3 of 3 open issues")
	if a := d.m.(*app); a.fnd.vis[a.fnd.vp.at()].ID != "CVE-2026-4" {
		t.Fatal("the list cursor follows the page")
	}
	if a := d.m.(*app); a.pend.count() != 0 {
		t.Fatalf("loads end: %d", a.pend.count())
	}
}

func TestSteppingFollowsTheFilteredListAndShowsLoading(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	d.screen("findings")
	d.press("s", "s", "s") // high+: critical and high
	d.press("enter")
	d.want("CVE-2026-3")
	d.press("]")
	d.want("CVE-2026-1")
	d.press("]")
	d.want("this is the last issue") // CVE-2026-4 is below the filter
	a := d.m.(*app)
	cmd := a.stepIssue(-1)
	if a.pend.count() != 1 || !strings.Contains(a.pend.status(), "loading CVE-2026-3") {
		t.Fatalf("the load is a pending operation: %q", a.pend.status())
	}
	d.run(cmd)
	d.want("CVE-2026-3")
}

func TestAfterAStatusChangeOneKeyGoesOn(t *testing.T) {
	b := newFake(t, nil)
	d := start(t, b, Options{})
	d.screen("findings")
	d.press("enter", "f", "enter") // CVE-2026-3 has one environment: closing it leaves the list
	d.want("ok: CVE-2026-3 marked fixed in shop/dev")
	if a := d.m.(*app); len(a.fnd.vis) != 2 {
		t.Fatalf("the list must lose the issue: %d", len(a.fnd.vis))
	}
	d.press("]")
	d.want("CVE-2026-1", "Tracked PHP bug")
	d.press("[")
	d.want("CVE-2026-1", "this is the first issue") // CVE-2026-3 is gone: nothing before

	// closing the last issue: the next one is the one before
	d.press("]", "f", "enter")
	d.want("CVE-2026-4", "marked fixed in shop/staging")
	d.press("]")
	d.want("this is the last issue")
	d.press("[")
	d.want("CVE-2026-1")
}

func TestStatusPromptSavesWithoutANote(t *testing.T) {
	b := newFake(t, nil)
	d := start(t, b, Options{})
	d.screen("findings")
	d.press("enter", "i")
	d.want("Note (optional)", "enter saves now")
	d.press("enter")
	d.want("ok: CVE-2026-3 ignored in shop/dev")
	d.press("]", "n")
	d.want("Reason (required)", "say why it does not apply here")
}

func TestSpaceSelectsAndStatusKeysApplyToTheSelection(t *testing.T) {
	b := newFake(t, nil)
	d := start(t, b, Options{})
	d.screen("findings")
	d.press(" ", " ") // CVE-2026-3 and CVE-2026-1; the cursor moves on
	d.want("2 selected", "*  critical", "*  high", " > low", "f/i/n/o mark selected", "esc clear selection")
	d.press("f")
	d.want("2 issues, 3 findings: marked fixed", "Note (optional)")
	d.typ("MR 7")
	d.press("enter")
	d.want("ok: marked fixed: 3 findings in 2 issues", "1 of 1 open issues")
	d.wantNot("selected", "CVE-2026-3")
	if b.writes != 1 {
		t.Fatalf("one write session for the whole selection, got %d", b.writes)
	}
	if a := d.m.(*app); len(a.fnd.sel) != 0 || a.prm != nil {
		t.Fatalf("selection %v prompt %v", a.fnd.sel, a.prm)
	}
	read(t, b, func(s *ops.Session) {
		for _, id := range []string{"CVE-2026-3", "CVE-2026-1"} {
			is, _, err := s.Show(id)
			if err != nil {
				t.Fatal(err)
			}
			for _, tg := range is.Targets {
				if tg.Status != model.StatusFixed || tg.Note != "MR 7" {
					t.Errorf("%s %s/%s = %s %q", id, tg.Project, tg.Env, tg.Status, tg.Note)
				}
			}
		}
	})
	log, _ := os.ReadFile(filepath.Join(b.cfg.DataDir, "audit.log"))
	if n := strings.Count(string(log), `"status":"fixed"`); n != 3 || !strings.Contains(string(log), `"actor":"tui:`) {
		t.Fatalf("every change is in the audit log by a tui actor (%d):\n%s", n, log)
	}
}

func TestBulkNotAffectedNeedsAReasonAndKeepsThePrompt(t *testing.T) {
	b := newFake(t, nil)
	d := start(t, b, Options{})
	d.screen("findings")
	d.press("ctrl+a")
	d.want("3 selected")
	d.press("n", "enter")
	d.want("Reason (required)", "problem: a not-affected statement needs a reason")
	a := d.m.(*app)
	if len(a.fnd.sel) != 3 || a.prm == nil {
		t.Fatal("a refusal keeps the selection and the prompt")
	}
	d.typ("internal only")
	d.press("enter")
	d.want("ok: marked not affected: 4 findings in 3 issues", "Nothing open")
	if b.writes != 2 {
		t.Fatalf("writes %d", b.writes)
	}
}

func TestBulkStopsAtTheFirstRefusalAndKeepsWhatLanded(t *testing.T) {
	b := newFake(t, nil)
	d := start(t, b, Options{})
	d.screen("findings")
	d.press("ctrl+a", "o")
	d.want("nothing to change in the selected issues") // every target is open already
	d.press("f")
	a := d.m.(*app)
	cs := a.bulkChanges(model.StatusFixed, "")
	if len(cs) != 4 {
		t.Fatalf("changes %+v", cs)
	}
	// ops refuses the change of a project that does not exist any more
	cs[2].Project = "gone"
	msg := bulkCmd(b, cs)().(bulkMsg)
	if msg.err == nil || !strings.Contains(msg.err.Error(), "2 of 4 changes written") {
		t.Fatalf("msg %+v", msg)
	}
	if len(msg.done) == 0 || len(msg.done) == 3 {
		t.Fatalf("the issues that are done are %v", msg.done)
	}
}

func TestSelectionKeysAndFilterInteraction(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	a := d.m.(*app)
	d.screen("findings")
	d.press("ctrl+a")
	d.want("3 selected")
	d.press("ctrl+a")
	d.wantNot("selected")
	d.press("ctrl+a", "esc")
	d.wantNot("selected")
	if len(a.fnd.sel) != 0 {
		t.Fatal("esc clears the selection")
	}
	d.press(" ")
	d.press("/")
	d.typ("severity:high")
	d.press("enter")
	d.wantNot("selected") // CVE-2026-3 is not in the list any more: only what is visible stays selected
	d.press(" ")
	d.want("1 selected")
	d.press("esc") // the selection goes first, the filter next
	d.wantNot("selected")
	d.want("filter: severity:high")
	d.press("esc")
	d.wantNot("filter: severity:high")
}

func TestStatusKeysDoNothingWithoutASelectionOnTheList(t *testing.T) {
	b := newFake(t, nil)
	d := start(t, b, Options{})
	d.screen("findings")
	d.press("f", "i", "n", "o")
	if d.m.(*app).prm != nil || b.writes != 0 {
		t.Fatal("f i n o need a selection or an open issue")
	}
}
