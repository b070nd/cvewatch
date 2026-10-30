package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/ops"
)

// hold sends a message and returns the command without running it, so a test
// can leave an operation in flight.
func (d *driver) hold(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	d.m, cmd = d.m.Update(msg)
	return cmd
}

// finish runs a held command and feeds its results back.
func (d *driver) finish(cmd tea.Cmd) {
	d.t.Helper()
	for _, msg := range collect(cmd) {
		d.send(msg)
	}
}

func collect(cmd tea.Cmd) []tea.Msg {
	if cmd == nil {
		return nil
	}
	switch m := cmd().(type) {
	case nil:
		return nil
	case tea.BatchMsg:
		var out []tea.Msg
		for _, c := range m {
			out = append(out, collect(c)...)
		}
		return out
	default:
		return []tea.Msg{m}
	}
}

func (d *driver) app() *app { return d.m.(*app) }

func TestPendingCountsAndRefusesTheSameKey(t *testing.T) {
	var p pending
	a, ok := p.begin("saving...", "status X", reList)
	if !ok || a == 0 {
		t.Fatal("first begin must be accepted")
	}
	if _, ok := p.begin("saving...", "status X", reList); ok {
		t.Fatal("the same key twice must be refused")
	}
	b, _ := p.begin("scanning...", "", 0)
	if _, ok := p.begin("scanning...", "", 0); !ok {
		t.Fatal("operations without a key never collide")
	}
	p.end(b)
	if p.count() != 2 || p.status() != "saving... +1" {
		t.Fatalf("count %d status %q", p.count(), p.status())
	}
	if op, ok := p.end(a); !ok || op.after != reList {
		t.Fatalf("end gave %+v %v", op, ok)
	}
	if _, ok := p.end(a); ok {
		t.Fatal("an operation ends once")
	}
	if _, ok := p.begin("saving...", "status X", reList); !ok {
		t.Fatal("a finished key can start again")
	}
}

func TestPromptKeepsItsValuesWhenOpsRefuses(t *testing.T) {
	b := newFake(t, nil)
	d := start(t, b, Options{})
	d.press("2", "down", "enter", "down", "a")
	d.typ("bob")
	d.press("tab")
	d.typ("tomorrow")
	d.press("enter", "enter")
	p := d.app().prm
	if p == nil || p.submitting || p.problem == "" {
		t.Fatalf("the prompt must be back with the reason: %+v", p)
	}
	if p.fields[0].in.String() != "bob" || p.fields[1].in.String() != "tomorrow" {
		t.Fatalf("typed values lost: %q %q", p.fields[0].in.String(), p.fields[1].in.String())
	}
	d.want("problem: due must look like", "error: due must look like")

	d.press("esc", "n") // close the prompt, then ask for not-affected without a reason
	d.press("enter")
	p = d.app().prm
	if p == nil || !strings.Contains(p.problem, "needs a reason") {
		t.Fatalf("the reason must be asked again: %+v", p)
	}
	d.typ("internal only")
	d.press("enter")
	if d.app().prm != nil {
		t.Fatal("the prompt closes when the write succeeded")
	}
	d.want("ok: CVE-2026-1 marked not affected")
	if d.app().pend.count() != 0 {
		t.Fatalf("nothing may be left pending: %+v", d.app().pend.ops)
	}
}

func TestSubmittingPromptIgnoresInputAndDoubleSubmit(t *testing.T) {
	b := newFake(t, nil)
	d := start(t, b, Options{})
	d.press("2", "down", "enter", "i")
	d.typ("MR 1")
	cmd := d.hold(key("enter"))
	if cmd == nil || !d.app().prm.submitting {
		t.Fatal("enter must start the write and keep the prompt open")
	}
	d.want("working...", "Note (optional)")
	if again := d.hold(key("enter")); again != nil {
		t.Fatal("a second enter must not start a second write")
	}
	d.hold(key("x"))
	if got := d.app().prm.fields[0].in.String(); got != "MR 1" {
		t.Fatalf("input must be ignored while submitting, note is %q", got)
	}
	if d.app().pend.count() != 1 {
		t.Fatalf("one operation in flight, have %d", d.app().pend.count())
	}
	d.finish(cmd)
	if b.writes != 1 {
		t.Fatalf("one write expected, got %d", b.writes)
	}
	if d.app().prm != nil {
		t.Fatal("the prompt closes with the result")
	}
}

func TestResultAfterTheSubmittingPromptWasClosedIsDropped(t *testing.T) {
	b := newFake(t, nil)
	d := start(t, b, Options{})
	d.press("2", "down", "enter", "n") // not affected, and no reason
	cmd := d.hold(key("enter"))
	d.press("esc")
	if d.app().prm != nil {
		t.Fatal("esc closes the prompt even while it submits")
	}
	d.finish(cmd)
	if d.app().prm != nil {
		t.Fatal("a late refusal must not bring a closed prompt back")
	}
	d.want("error: a not-affected statement needs a reason") // but the user still hears of it
	if d.app().pend.count() != 0 {
		t.Fatal("the operation ended")
	}
}

func TestBusyCountsOverlappingWritesAndEachEndsAlone(t *testing.T) {
	b := newFake(t, nil)
	d := start(t, b, Options{})
	d.press("2", "enter", "i") // CVE-2026-3
	first := d.hold(key("enter"))
	d.press("esc", "esc", "down", "enter", "i") // CVE-2026-1
	second := d.hold(key("enter"))
	if d.app().pend.count() != 2 {
		t.Fatalf("two writes in flight, have %d", d.app().pend.count())
	}
	d.want("saving... +1")

	d.finish(first)
	if d.app().pend.count() != 1 {
		t.Fatalf("a finished write must leave the other pending, have %d", d.app().pend.count())
	}
	d.want("saving...")
	d.wantNot("saving... +1")
	d.finish(second)
	if d.app().pend.count() != 0 {
		t.Fatal("both ended")
	}
	d.wantNot("saving...")
	if b.writes != 2 {
		t.Fatalf("writes = %d", b.writes)
	}
}

func TestTickAndRefreshReloadTheOpenIssue(t *testing.T) {
	b := newFake(t, nil)
	d := start(t, b, Options{})
	d.press("2", "down", "enter", "down") // CVE-2026-1, shop selected
	d.want("> shop")
	resolve := func(project string, st model.Status) {
		t.Helper()
		if err := b.Write(func(s *ops.Session) error {
			_, err := s.Resolve(ops.Change{ID: "CVE-2026-1", Project: project, Env: model.EnvProd, Status: st, Note: "by someone else"})
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	resolve("mw", model.StatusIgnored)
	d.wantNot("ignored")
	d.send(tickMsg{})
	d.want("ignored", "by someone else", "> shop") // the page and the selected row both held

	resolve("shop", model.StatusFixed)
	d.press("r")
	d.want("fixed", "> shop")
}

func TestIssueThatLeavesTheListStaysOpenInDetail(t *testing.T) {
	b := newFake(t, nil)
	d := start(t, b, Options{})
	d.press("2", "/")
	d.typ("nginx")
	d.press("enter", "enter", "f") // CVE-2026-3 is the only match
	d.typ("MR 9")
	d.press("enter")
	d.want("ok: CVE-2026-3 marked fixed", "CVE-2026-3", "fixed", "MR 9")
	if d.app().fnd.det == nil || d.app().fnd.det.id != "CVE-2026-3" {
		t.Fatal("the detail must stay on the same issue")
	}
	d.press("down", "up", "esc")
	d.want("0 of 2 open issues", "No issue matches the filter")
}

func TestErrorIsStickyThroughMovementButNotAnAction(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	d.press("3", "x")
	d.want("error: no problems to fix here")
	d.press("down", "up", "pgdown", "home", "end", "g", "G", "2", "tab", "shift+tab", "3", "?")
	d.press("?") // closes the help again
	d.want("error: no problems to fix here")
	d.press("esc")
	d.wantNot("no problems to fix here")

	d.press("x")
	d.want("error: no problems to fix here")
	d.press("r")
	d.wantNot("no problems to fix here")
}

func TestSuccessNoteExpiresByItsTimer(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	d.press("2", "s")
	d.want("ok: minimum severity: low+")
	if len(d.timers) != 1 {
		t.Fatalf("one timer for the note, got %v", d.timers)
	}
	old := d.timers[0]
	d.press("down", "up")
	d.want("ok: minimum severity: low+") // moving does not clear it
	d.press("s")
	d.want("ok: minimum severity: medium+")
	d.send(old) // the timer of the first note must leave the second alone
	d.want("ok: minimum severity: medium+")
	d.send(d.timers[len(d.timers)-1])
	d.wantNot("ok: ")
}

func TestErrorIsNotClearedByATimer(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	d.press("2", "s")
	timer := d.timers[0]
	d.press("3", "x")
	d.want("error: no problems to fix here")
	d.send(timer)
	d.send(flashExpiredMsg{seq: d.app().flashSeq})
	d.want("error: no problems to fix here")
}
