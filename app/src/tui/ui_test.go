package tui

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/ops"
	"github.com/b070nd/cvewatch/app/src/query"
)

func read(t *testing.T, b Backend, fn func(*ops.Session)) {
	t.Helper()
	if err := b.Read(func(s *ops.Session) error { fn(s); return nil }); err != nil {
		t.Fatal(err)
	}
}

func TestOverviewShowsCounts(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	v := d.view()
	for _, re := range []string{
		`open issues\s+3`, `open findings\s+4`, `critical \+ high open\s+2`, `open in prod\s+1`,
		`critical\s+1\s`, `high\s+1\s`, `medium\s+0\s`, `low\s+1\s`,
		`dev\s+1\s`, `staging\s+1\s`, `prod\s+2\s`,
		`policy violations\s+0`, `items 40  new 3`,
	} {
		if !regexp.MustCompile(re).MatchString(v) {
			t.Errorf("overview lacks %q:\n%s", re, v)
		}
	}
	d.want("cvewatch", "[1 Overview]", "2 Findings (3)", "3 Projects", "4 Status", "OK", "updated")
}

func TestFindingsListAndSeverityFilter(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	d.press("2")
	d.want("[2 Findings (3)]", "3 of 3 open issues", "SEVERITY", "CVE-2026-3", "critical", "Critical nginx bug", "CVE-2026-1", "high", "Tracked PHP bug",
		"mw:prod shop:prod", "CVE-2026-4", "low", "> critical")
	if v := d.view(); strings.Index(v, "CVE-2026-3") > strings.Index(v, "CVE-2026-1") {
		t.Errorf("the critical issue must come first:\n%s", v)
	}

	for _, c := range []struct {
		label string
		shown []string
		gone  []string
	}{
		{"low+", []string{"CVE-2026-3", "CVE-2026-1", "CVE-2026-4"}, nil},
		{"medium+", []string{"CVE-2026-3", "CVE-2026-1"}, []string{"CVE-2026-4"}},
		{"high+", []string{"CVE-2026-3", "CVE-2026-1"}, []string{"CVE-2026-4"}},
		{"critical+", []string{"CVE-2026-3"}, []string{"CVE-2026-1", "CVE-2026-4"}},
		{"all", []string{"CVE-2026-3", "CVE-2026-1", "CVE-2026-4"}, nil},
	} {
		d.press("s")
		d.want("min severity: " + c.label)
		d.want(c.shown...)
		d.wantNot(c.gone...)
	}
	d.want("ok: minimum severity: all")

	d.press("/")
	d.typ("nginx")
	d.want("1 of 3 open issues", "filter: nginx", "CVE-2026-3")
	d.wantNot("CVE-2026-1")
	d.press("enter")
	d.want("filter: nginx")
	d.press("esc")
	d.want("3 of 3 open issues")
}

func TestFilterInputDoesNotTriggerKeys(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	d.press("2", "/")
	d.typ("q?r3")
	if d.quit {
		t.Fatal("q typed into the filter quit the program")
	}
	d.want("filter: q?r3", "No issue matches the filter")
	d.press("esc")
	d.want("3 of 3")
}

func TestFindingsFilterAcceptsFieldQueries(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	d.press("2", "/")
	d.typ("severity:critical")
	d.want("1 of 3 open issues", "CVE-2026-3")
	d.wantNot("CVE-2026-1", "CVE-2026-4")
}

func TestFindingsFilterFallsBackToWordsOnBadQuery(t *testing.T) {
	all := []query.Issue{
		{ID: "CVE-1", Severity: model.SevHigh, Untrusted: query.Untrusted{Title: "Bug: heap overflow"}},
		{ID: "CVE-2", Severity: model.SevHigh, Untrusted: query.Untrusted{Title: "Other"}},
	}
	if got := filterIssues(all, model.SevUnknown, "bug: heap"); len(got) != 1 || got[0].ID != "CVE-1" {
		t.Fatalf("text that does not parse as a query must still filter by words: %+v", got)
	}
}

func TestDetailView(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	d.press("2", "down", "enter")
	d.want("CVE-2026-1", "high", "Tracked PHP bug", "Summary of CVE-2026-1",
		"Environments", "mw", "shop", "prod", "open", "unknown",
		"Fix evidence", "version 8.2.9 (official) via hn",
		"Why it matched", "shop/prod: php 8.2 is installed [matched php@8.2]", "relevant under the current configuration")
	d.want("> mw") // the first environment is selected
	d.press("down")
	d.want("> shop")
	d.press("esc")
	d.want("3 of 3 open issues")
	d.wantNot("Fix evidence")
}

func TestMarkFixedPersistsThroughWrite(t *testing.T) {
	b := newFake(t, nil)
	d := start(t, b, Options{})
	d.press("2", "down", "enter", "down", "f")
	d.want("fixed: shop/prod")
	d.typ("MR 42")
	d.press("enter")
	d.want("ok: CVE-2026-1 marked fixed in shop/prod (1 finding)")
	if b.writes != 1 {
		t.Fatalf("one short write session expected, got %d", b.writes)
	}
	read(t, b, func(s *ops.Session) {
		issues, err := s.List(query.Filter{})
		if err != nil {
			t.Fatal(err)
		}
		for _, is := range issues {
			if is.ID != "CVE-2026-1" {
				continue
			}
			if len(is.Targets) != 1 || is.Targets[0].Project != "mw" {
				t.Errorf("shop/prod must be closed, got %+v", is.Targets)
			}
		}
		is, _, err := s.Show("CVE-2026-1")
		if err != nil {
			t.Fatal(err)
		}
		for _, tg := range is.Targets {
			if tg.Project == "shop" && (tg.Status != model.StatusFixed || tg.Note != "MR 42") {
				t.Errorf("shop/prod = %s %q", tg.Status, tg.Note)
			}
		}
	})
	log, err := os.ReadFile(filepath.Join(b.cfg.DataDir, "audit.log"))
	if err != nil || !strings.Contains(string(log), `"actor":"tui:`) || !strings.Contains(string(log), `"status":"fixed"`) {
		t.Fatalf("the audit log must show the change by a tui actor: %v\n%s", err, log)
	}
	// the screen follows: the detail view shows the new state after the reload
	d.want("fixed", "MR 42")
}

func TestNotAffectedNeedsAReason(t *testing.T) {
	b := newFake(t, nil)
	d := start(t, b, Options{})
	d.press("2", "down", "enter", "n")
	d.want("Reason (required)")
	d.press("enter") // no reason typed
	d.want("error: a not-affected statement needs a reason")
	if b.writes != 1 {
		t.Fatalf("the change goes through Write so ops can refuse it, writes=%d", b.writes)
	}
	read(t, b, func(s *ops.Session) {
		is, _, _ := s.Show("CVE-2026-1")
		for _, tg := range is.Targets {
			if tg.Status != model.StatusOpen {
				t.Errorf("nothing may change after a refusal: %+v", tg)
			}
		}
	})
	d.want("Reason (required)", "problem: a not-affected statement needs a reason") // the prompt stays open
	d.typ("not exposed, internal only")
	d.press("enter")
	d.want("ok: CVE-2026-1 marked not affected in mw/prod")
}

func TestIgnoreReopenAndWholeProject(t *testing.T) {
	b := newFake(t, nil)
	d := start(t, b, Options{})
	d.press("2", "down", "enter", "I", "enter")
	d.want("ok: CVE-2026-1 ignored in mw (all environments)")
	d.press("o", "enter")
	d.want("ok: CVE-2026-1 reopened in mw/prod")
}

func TestAssignAsksOwnerDueTicket(t *testing.T) {
	b := newFake(t, nil)
	d := start(t, b, Options{})
	d.press("2", "down", "enter", "down", "a")
	d.want("Assign CVE-2026-1 in shop/prod", "Owner", "Due", "Ticket")
	d.typ("bob")
	d.press("enter")
	d.typ("tomorrow")
	d.press("enter")
	d.typ("OPS-7")
	d.press("enter")
	d.want("error: due must look like 2026-11-30", "problem: due must look like 2026-11-30")
	d.want("bob", "tomorrow", "OPS-7") // the prompt is still open with what was typed

	d.press("shift+tab") // to Due
	d.press("ctrl+u")
	d.typ("2026-11-30")
	d.press("enter", "enter")
	d.want("ok: CVE-2026-1 assigned in shop/prod")
	d.want("owner bob", "2026-11-30", "ticket OPS-7")
}

func TestPromptEscapeCancelsWithoutWriting(t *testing.T) {
	b := newFake(t, nil)
	d := start(t, b, Options{})
	d.press("2", "enter", "f")
	d.typ("abc")
	d.press("esc")
	if b.writes != 0 {
		t.Fatal("cancelled prompt wrote")
	}
	d.wantNot("Note (optional)")
}

func TestAccessRulesComeFromOps(t *testing.T) {
	t.Setenv("CVEWATCH_ACTOR", "carol")
	b := newFake(t, nil)
	b.cfg.Access = map[string]config.Grant{"carol": {Projects: []string{"shop"}}} // may read shop, may not write
	d := start(t, b, Options{})
	d.press("2")
	d.want("CVE-2026-1", "shop:prod")
	d.wantNot("mw:prod") // scoped by ops, not by the TUI
	d.press("down", "enter", "f", "enter")
	d.want("error: access denied: tui:carol may not change anything")
	d.press("esc")
	d.press("3")
	d.wantNot("mw ")
}
