package tui

import (
	"strings"
	"testing"

	"github.com/b070nd/cvewatch/app/src/projectfile"
	"time"
)

func TestAnEditedSettingIsSavedAndShownForThatProjectOnly(t *testing.T) {
	b, root := diskFake(t, nil)
	d := start(t, b, Options{})
	d.screen("projects")

	week, _ := projectfile.ParseSince("7d", time.Now())
	weekDay := projectfile.FormatSince(week)

	// shop: Since to the past week
	d.press("down", "c")
	d.toField(4)
	d.press("enter")
	d.pickTo("Past week")
	d.press("enter", "y")
	d.want("ok: saved shop")
	d.want("Edit fields of shop", "Since", weekDay)
	if got := fileAt(t, root, "config/projects/shop.yaml"); !strings.Contains(got, "since: "+weekDay) {
		t.Fatalf("shop's file holds the new since:\n%s", got)
	}

	// mw has no since of its own, and shop's is not shown there
	d.press("esc", "esc", "up")
	d.press("c")
	d.want("Edit fields of mw")
	d.wantNot(weekDay)
	d.toField(4)
	d.press("enter")
	d.pickTo("Custom")
	d.press("enter", "ctrl+u")
	d.typ("2026-02-02")
	d.press("enter", "y")
	d.want("ok: saved mw")
	d.want("Edit fields of mw", "2026-02-02")
	if got := fileAt(t, root, "config/projects/mw.yaml"); !strings.Contains(got, "since: 2026-02-02") {
		t.Fatalf("mw's file holds its own since:\n%s", got)
	}
	if got := fileAt(t, root, "config/projects/shop.yaml"); !strings.Contains(got, "since: "+weekDay) || strings.Contains(got, "2026-02-02") {
		t.Fatalf("shop's file is untouched by the edit of mw:\n%s", got)
	}

	// back in shop the list shows what was saved there
	d.press("esc", "esc", "down")
	d.press("c")
	d.want("Edit fields of shop", weekDay)
	d.wantNot("2026-02-02")
}
