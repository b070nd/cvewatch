package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/b070nd/cvewatch/app/src/ledger"
	"github.com/b070nd/cvewatch/app/src/model"
)

// problemFake is a fake whose feed hn has failed red times in a row and whose
// feed gh has failed yellow times: three failures are red, one is yellow.
func problemFake(t *testing.T, red, yellow int) *fake {
	t.Helper()
	st := seed(t, func(l *ledger.Ledger) {
		l.State().Sources["hn"] = model.SourceHealth{Type: "hn", LastAttempt: tNow.Add(-time.Hour), LastSuccess: tNow.Add(-5 * time.Hour), Failures: red,
			FailingSince: tNow.Add(-4 * time.Hour), LastError: "connection refused"}
		l.State().Sources["gh"] = model.SourceHealth{Type: "hn", LastAttempt: tNow.Add(-time.Hour), LastSuccess: tNow.Add(-2 * time.Hour), Failures: yellow,
			FailingSince: tNow.Add(-time.Hour), LastError: "timeout"}
	})
	b := newFake(t, st)
	b.cfg.Sources = append(b.cfg.Sources, model.Source{ID: "gh", Type: "hn"})
	return b
}

func headerOf(d *driver) string { return strings.Split(d.view(), "\n")[0] }

func TestHeaderShowsTheHealthSummary(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	d.want("● GREEN · last check")
	if h := headerOf(d); !strings.Contains(h, "ago)") || strings.Contains(h, "problem") {
		t.Errorf("green shows the last check and nothing else: %q", h)
	}
	d.wantNot("Needs attention")

	d = start(t, problemFake(t, 0, 1), Options{})
	if h := headerOf(d); !strings.Contains(h, "▲ YELLOW · 1 problem") || strings.Contains(h, "problems") {
		t.Errorf("yellow: %q", h)
	}

	d = start(t, problemFake(t, 3, 1), Options{})
	if h := headerOf(d); !strings.Contains(h, "✖ RED · 2 problems") {
		t.Errorf("red: %q", h)
	}
	d.screen("health")
	if h := headerOf(d); !strings.Contains(h, "✖ RED · 2 problems") {
		t.Errorf("the header is on every screen: %q", h)
	}
}

func TestProblemsComeFirstOnTheOverviewRedBeforeYellow(t *testing.T) {
	d := start(t, problemFake(t, 3, 1), Options{})
	v := d.view()
	v = v[strings.Index(v, "Needs attention"):]
	at := func(s string) int {
		i := strings.Index(v, s)
		if i < 0 {
			t.Fatalf("the overview lacks %q:\n%s", s, v)
		}
		return i
	}
	if !(at("Needs attention first (2)") < at("✖ RED") && at("✖ RED") < at("feed hn is failing") &&
		at("feed hn is failing") < at("▲ YELLOW") && at("▲ YELLOW") < at("feed gh had a failed fetch") &&
		at("feed gh had a failed fetch") < at("CVE-2026-3")) {
		t.Errorf("problems first, red before yellow, then the issues:\n%s", v)
	}
	d.want("for 4h", "for 1h")

	d = start(t, problemFake(t, 0, 1), Options{})
	d.want("Needs attention first (1)", "▲ YELLOW", "feed gh had a failed fetch")
	d.wantNot("✖ RED")
}

func TestProblemsHaveNoDismissAndEnterOpensTheHealthScreenOnThem(t *testing.T) {
	b := problemFake(t, 3, 1)
	d := start(t, b, Options{})
	for _, md := range allModes() {
		for i := range md.binds {
			h := md.binds[i].help
			for _, w := range []string{"dismiss", "hide", "snooze", "silence", "mute", "acknowledge"} {
				if strings.Contains(h, w) && !strings.Contains(h, "help") {
					t.Errorf("%s: %q looks like a way to get rid of a problem", md.name, h)
				}
			}
		}
	}
	d.press("x", "d", "delete", "backspace", "i", "n", "f", "o", "-", " ", "h")
	if b.writes != 0 || d.app().prm != nil {
		t.Fatalf("a key did something to a problem: writes %d", b.writes)
	}
	d.want("Needs attention first (2)", "feed hn is failing", "feed gh had a failed fetch")

	d.press("down", "enter") // the yellow one
	if screenOf(d) != scrStatus {
		t.Fatalf("on %s", screens[screenOf(d)].name)
	}
	d.want("Problems (2)", "> ▲ YELLOW", "feed gh had a failed fetch", "failed 1 in a row: timeout", "what to do: cvewatch doctor -online")
	d.wantNot("> ✖ RED")
	d.press("O")
	d.want("Needs attention first (2)", "feed hn is failing", "feed gh had a failed fetch")
}

func TestHealthScreenListsTheProblemsAboveTheRest(t *testing.T) {
	d := start(t, problemFake(t, 3, 1), Options{})
	d.screen("health")
	v := d.view()
	i := func(s string) int {
		n := strings.Index(v, s)
		if n < 0 {
			t.Fatalf("the health screen lacks %q:\n%s", s, v)
		}
		return n
	}
	if !(i("Problems (2)") < i("feed hn is failing") && i("feed hn is failing") < i("feed gh had a failed fetch") && i("feed gh had a failed fetch") < i("Feeds (2)") && i("Feeds (2)") < i("Recent cycles")) {
		t.Errorf("problems on top, then feeds, channels and cycles:\n%s", v)
	}
	d.want("failed 3 times in a row: connection refused", "for 4h")

	d = start(t, newFake(t, nil), Options{})
	d.screen("health")
	d.want("Overall", "GREEN", "Problems (0)")
}
