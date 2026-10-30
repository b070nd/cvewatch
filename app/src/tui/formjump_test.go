package tui

import (
	"strings"
	"testing"
)

// toReview fills a new project's form up to the review step.
func toReview(d *driver) {
	d.press("3", "n", "ctrl+u")
	d.typ("blog")
	d.press("enter", "enter") // name, technologies (none)
	d.typ("php")
	d.press("enter", "enter") // add php, done adding
	d.typ("8.2")
	d.press("enter", "enter") // version, environments
	d.want("Save this project?")
}

func TestReviewListsTheStepsAndReturnsAfterOneAnswer(t *testing.T) {
	b := newFake(t, nil)
	d := start(t, b, Options{})
	toReview(d)
	d.want("e edit step")
	d.press("e")
	d.want("Go back to which step?", "> Project name", "Technologies", "Add technologies by name", "Versions", "Environments", "enter go")
	d.press("esc")
	d.want("Save this project?")
	d.wantNot("Go back to which step?")

	d.press("e", "end", "enter") // Environments
	d.want("Environments", "[x] local", "[ ] dev", "other...")
	d.press("down", " ") // tick dev
	d.press("enter")
	d.want("Save this project?", "envs: [local, dev]") // the review again, not the steps after
	if a := d.m.(*app); a.frm == nil || a.frm.step.ID != "review" {
		t.Fatal("not at the review")
	}

	d.press("e", "down", "down", "down", "enter") // Versions
	d.want("Version of PHP")
	d.press("ctrl+u")
	d.typ("8.3")
	d.press("enter")
	d.want("Save this project?", `version: "8.3"`)

	d.press("e", "enter") // the name
	d.want("Project name", "> blog")
	d.press("esc") // back goes to the review, not to the step before
	d.want("Save this project?")
	d.press("y")
	d.want("ok: created project blog")
	f := projectFile(t, b, "blog")
	if !strings.Contains(f, "8.3") || !strings.Contains(f, "envs: [local, dev]") {
		t.Fatalf("project file:\n%s", f)
	}
	if b.writes != 1 {
		t.Fatalf("writes %d", b.writes)
	}
}

func TestReviewStepListSurvivesSmallTerminals(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	toReview(d)
	d.send(tea_window(40, 10))
	d.press("e", "end")
	d.want("> Environments")
	d.press("enter")
	d.want("Environments")
}

func TestEscOnTheFirstStepAsksOnceSomethingWasTyped(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	d.press("3", "n")
	d.press("esc") // nothing typed yet: leaves at once
	d.want("cancelled")
	d.press("n", "ctrl+u")
	d.typ("blog")
	d.press("esc")
	d.want("Discard what you entered?")
	d.press("y")
	d.want("cancelled", "PROJECT")
}

func TestClickingAStepInTheReviewList(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	toReview(d)
	d.press("e")
	a := d.m.(*app)
	head, _, _ := a.frm.frame(120, a.bodyH())
	y := bodyTop + len(head) + 1 // the hint line comes first
	d.click(5, y+1)
	if a.frm.pick == nil || a.frm.pick.vp.at() != 1 {
		t.Fatalf("a click selects: %+v", a.frm.pick)
	}
	d.click(5, y+1)
	d.want("Technologies", "[x] PHP")
}
