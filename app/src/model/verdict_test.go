package model

import (
	"errors"
	"testing"
	"time"
)

var day = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)

func php() []Installed { return []Installed{{Via: "tech", Name: "php", Version: "8.2.1"}} }

func TestEveryTransitionLeavesALegalFindingWithItsVerdict(t *testing.T) {
	f := NewFinding("CVE-1", "shop", EnvProd, php(), AppAffected, []string{"in range"}, day)
	steps := []struct {
		name string
		do   func(*Finding)
		want Verdict
	}{
		{"new", func(*Finding) {}, VerdictActionable},
		{"refresh to not affected", func(f *Finding) { f.Refresh(php(), AppNotAffected, []string{"fixed in 8.2.1"}, day) }, VerdictUnaffected},
		{"retire", func(f *Finding) {
			f.Retire(RetiredUnmatched, []string{"no longer matched"}, "no longer matched php", day)
		}, VerdictRetired},
		{"matches again", func(f *Finding) { f.Reinventory(php(), AppAffected, nil, "matches again", day) }, VerdictActionable},
		{"since close", func(f *Finding) { f.AutoClose(StatusNotAffected, AutoSince, "before the since date", day) }, VerdictAutoClosed},
		{"since reopen", func(f *Finding) { f.AutoReopen("since moved", day) }, VerdictActionable},
		{"env close", func(f *Finding) { f.AutoClose(StatusIgnored, AutoEnvRemoved, EnvRemovedNote, day) }, VerdictAutoClosed},
		{"a person fixes it", func(f *Finding) { note := "deployed"; f.Resolve("ann", StatusFixed, &note, day) }, VerdictClosed},
		{"a person reopens it", func(f *Finding) { f.Resolve("ann", StatusOpen, nil, day) }, VerdictActionable},
	}
	for _, s := range steps {
		s.do(&f)
		if err := f.Check(); err != nil {
			t.Fatalf("%s: %v", s.name, err)
		}
		if got := f.Verdict(); got != s.want {
			t.Fatalf("%s: verdict %s, want %s", s.name, got, s.want)
		}
	}
	if f.Auto || f.AutoReason != "" || f.Note != "deployed" {
		t.Errorf("a person's change makes the finding theirs and keeps the note: %+v", f)
	}
	if n := len(f.History); n != 7 {
		t.Errorf("every transition but the refresh is in the history: %d entries", n)
	}
}

func TestAutoCloseKeepsAPersonsNoteInTheHistory(t *testing.T) {
	f := NewFinding("CVE-1", "shop", EnvProd, php(), AppAffected, nil, day)
	f.Note = "waiting for the vendor"
	f.AutoClose(StatusIgnored, AutoEnvRemoved, EnvRemovedNote, day)
	if f.Note != EnvRemovedNote || f.ClosedBy() != AutoEnvRemoved {
		t.Fatalf("closed: %+v", f)
	}
	if h := f.History[len(f.History)-1].Note; h != EnvRemovedNote+" (previous note: waiting for the vendor)" {
		t.Errorf("history note %q", h)
	}
	f.AutoReopen("declared again", day)
	if f.Note != "" || f.ClosedBy() != "" || f.Status != StatusOpen {
		t.Errorf("reopened: %+v", f)
	}
}

func TestClosedByReadsFindingsWrittenBeforeTheReasonWasStored(t *testing.T) {
	since := Finding{Status: StatusNotAffected, Auto: true}
	env := Finding{Status: StatusIgnored, Auto: true, Note: EnvRemovedNote}
	person := Finding{Status: StatusIgnored, Note: EnvRemovedNote}
	if since.ClosedBy() != AutoSince || env.ClosedBy() != AutoEnvRemoved || person.ClosedBy() != "" {
		t.Errorf("since %q, env %q, person %q", since.ClosedBy(), env.ClosedBy(), person.ClosedBy())
	}
}

func TestCheckRefusesFieldsThatDisagree(t *testing.T) {
	for name, f := range map[string]Finding{
		"retired with installed": {Status: StatusOpen, Retired: RetiredUninstalled, Installed: php(), Applies: AppNotAffected},
		"retired but affected":   {Status: StatusOpen, Retired: RetiredUnmatched, Applies: AppAffected},
		"open and auto":          {Status: StatusOpen, Auto: true},
		"reason without auto":    {Status: StatusIgnored, AutoReason: AutoEnvRemoved},
		"unknown status":         {Status: "done"},
		"unknown applicability":  {Status: StatusOpen, Applies: "maybe"},
		"unknown retirement":     {Status: StatusOpen, Retired: "bored", Applies: AppNotAffected},
		"unknown auto reason":    {Status: StatusIgnored, Auto: true, AutoReason: "whim"},
	} {
		if err := f.Check(); !errors.Is(err, ErrIllegalFinding) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
