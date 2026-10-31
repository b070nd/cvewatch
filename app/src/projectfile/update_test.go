package projectfile

import (
	"strings"
	"testing"
	"time"

	"github.com/b070nd/cvewatch/app/src/model"
)

func boolp(b bool) *bool { return &b }

func TestUpdateBlockIsReadInBothSpellings(t *testing.T) {
	for name, src := range map[string]string{
		"when@":        "name: shop\nenvs: [dev, prod]\nupdate:\n  every: 90m\n  auto: false\nwhen@prod:\n  image: shop:1\n",
		"environments": "name: shop\nenvs: [dev, prod]\nupdate: {every: 90m, auto: false}\nenvironments:\n  prod: {image: shop:1}\n",
	} {
		t.Run(name, func(t *testing.T) {
			p := mustParse(t, src).Project()
			if p.Update.Every != 90*time.Minute || p.AutoUpdate() || p.Every(4*time.Hour) != 90*time.Minute {
				t.Fatalf("update = %+v", p.Update)
			}
			if p.Environments[model.EnvProd].Image != "shop:1" {
				t.Errorf("the differences are untouched: %+v", p.Environments)
			}
		})
	}
	p := mustParse(t, "name: shop\n").Project()
	if !p.AutoUpdate() || p.Every(4*time.Hour) != 4*time.Hour {
		t.Fatalf("no block means auto on and the global interval: %+v", p.Update)
	}
	if _, err := Parse([]byte("name: shop\nupdate:\n  evry: 1h\n")); err == nil {
		t.Fatal("an unknown key of the block is an error")
	}
	if _, err := Parse([]byte("name: shop\nupdate:\n  every: soon\n")); err == nil {
		t.Fatal("a period that is no duration is an error")
	}
}

func TestSetUpdateWritesKeepsAndRemoves(t *testing.T) {
	src := "# the shop\nname: shop\nenvs: [dev, prod]\ntechs: []\nsince: 2026-01-01 # from then\nlockfiles: []\nwhen@prod:\n  image: shop:1\n"
	got := mustApply(t, src, Op{Kind: "set_update", Every: "1h", Auto: boolp(false)})
	for _, want := range []string{"update:\n  every: 1h\n  auto: false\n", "# from then", "# the shop"} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q:\n%s", want, got)
		}
	}
	if strings.Index(got, "update:") < strings.Index(got, "lockfiles:") || strings.Index(got, "update:") > strings.Index(got, "when@prod:") {
		t.Errorf("the block goes after the inventory and before the differences:\n%s", got)
	}
	p := mustParse(t, got).Project()
	if p.Update.Every != time.Hour || p.AutoUpdate() {
		t.Fatalf("round trip: %+v", p.Update)
	}

	// one field at a time; days become hours, the file only knows durations
	got2 := mustApply(t, got, Op{Kind: "set_update", Every: "2d"})
	if p := mustParse(t, got2).Project(); p.Update.Every != 48*time.Hour || p.AutoUpdate() {
		t.Fatalf("every changes, auto stays: %+v\n%s", p.Update, got2)
	}
	if !strings.Contains(got2, "every: 48h") {
		t.Errorf("days are written as hours:\n%s", got2)
	}

	// the defaults are not written: true removes auto, default removes every, an empty block goes
	got3 := mustApply(t, got2, Op{Kind: "set_update", Auto: boolp(true)})
	if strings.Contains(got3, "auto:") || !strings.Contains(got3, "every: 48h") {
		t.Errorf("auto: true is the default and is removed:\n%s", got3)
	}
	got4 := mustApply(t, got3, Op{Kind: "set_update", Every: "default"})
	if strings.Contains(got4, "update") || got4 != src {
		t.Errorf("an empty block is removed and the rest is as it was:\n%s", got4)
	}
	if again := mustApply(t, src, Op{Kind: "set_update", Every: "default", Auto: boolp(true)}); again != src {
		t.Errorf("setting the defaults on a file without a block changes nothing:\n%s", again)
	}
}

func TestSetUpdateKeepsCommentsOfAnExistingBlock(t *testing.T) {
	src := "name: shop\nupdate:\n  every: 1h # hourly\n  auto: false # paused for the migration\n"
	got := mustApply(t, src, Op{Kind: "set_update", Every: "30m"})
	if !strings.Contains(got, "every: 30m # hourly") || !strings.Contains(got, "# paused for the migration") {
		t.Errorf("comments lost:\n%s", got)
	}
	empty := mustApply(t, "name: shop\nupdate:\ntechs: []\n", Op{Kind: "set_update", Every: "1h"})
	if p := mustParse(t, empty).Project(); p.Update.Every != time.Hour {
		t.Errorf("an empty update: key is filled in:\n%s", empty)
	}
}

func TestSetUpdateErrors(t *testing.T) {
	for name, op := range map[string]Op{
		"nothing":  {Kind: "set_update"},
		"too fast": {Kind: "set_update", Every: "4m"},
		"zero":     {Kind: "set_update", Every: "0s"},
		"negative": {Kind: "set_update", Every: "-1h"},
		"words":    {Kind: "set_update", Every: "hourly"},
		"days":     {Kind: "set_update", Every: "xd"},
	} {
		if err := mustParse(t, opSample).Apply(op); err == nil {
			t.Errorf("%s must be rejected", name)
		}
	}
	for text, want := range map[string]time.Duration{"5m": 5 * time.Minute, "90m": 90 * time.Minute, "1h30m": 90 * time.Minute, "2d": 48 * time.Hour, " 1h ": time.Hour} {
		if got, err := ParseEvery(text); err != nil || got != want {
			t.Errorf("ParseEvery(%q) = %v, %v", text, got, err)
		}
	}
}

func TestValidateRejectsAPeriodUnderTheMinimum(t *testing.T) {
	f := mustParse(t, "name: shop\nupdate:\n  every: 1m\n")
	var found *Issue
	for _, is := range f.Validate(nil) {
		if is.Field == "update.every" {
			found = &is
		}
	}
	if found == nil || found.Level != "error" || found.Line != 3 || !strings.Contains(found.Message, "minimum of 5m") {
		t.Fatalf("issue = %+v", found)
	}
	if len(found.Fixes) != 2 || found.Fixes[0].Ops[0].Every != "5m" || found.Fixes[1].Ops[0].Every != "default" {
		t.Fatalf("fixes = %+v", found.Fixes)
	}
	if err := f.Apply(found.Fixes[0].Ops...); err != nil {
		t.Fatal(err)
	}
	for _, is := range f.Validate(nil) {
		if is.Field == "update.every" {
			t.Errorf("the fix leaves the problem: %+v", is)
		}
	}
	if is := mustParse(t, "name: shop\nupdate:\n  every: 5m\n").Validate(nil); len(is) != 0 {
		t.Errorf("5m is the minimum and fine: %+v", is)
	}
}

func TestHintsAboutTheSchedule(t *testing.T) {
	const base = "name: shop\nenvs: [prod]\nsince: 2026-01-01\ntechs: [{name: php, version: \"8\"}]\nlockfiles: []\n"
	for _, block := range []string{"", "update: {every: 1h}\n"} {
		for _, h := range hintsOf(t, base+block, HintOptions{}) {
			if strings.HasPrefix(h.Field, "update") {
				t.Errorf("%q is no hint: %+v", block, h)
			}
		}
	}

	hs := hintsOf(t, base+"update: {auto: false}\n", HintOptions{})
	h, ok := hintAt(hs, "update.auto", "scheduled runs skip this project; run cvewatch update or press u in the TUI")
	if !ok || h.Level != "info" || len(h.Fix) != 1 || h.Fix[0].Kind != "set_update" || h.Fix[0].Auto == nil || !*h.Fix[0].Auto {
		t.Fatalf("hint = %+v (%+v)", h, hs)
	}

	hs = hintsOf(t, base+"update: {every: 800h}\n", HintOptions{})
	if h, ok := hintAt(hs, "update.every", "longer than 30 days"); !ok || h.Level != "info" {
		t.Fatalf("a period over 30 days is a hint: %+v", hs)
	}
	hs = hintsOf(t, base+"update: {every: 720h}\n", HintOptions{})
	if _, ok := hintAt(hs, "update.every", "longer"); ok {
		t.Errorf("30 days is the limit and fine")
	}
}
