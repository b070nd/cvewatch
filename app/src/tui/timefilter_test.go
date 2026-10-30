package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/ledger"
	"github.com/b070nd/cvewatch/app/src/query"
)

// agedSeed publishes CVE-2026-1 half an hour, CVE-2026-3 three days and
// CVE-2026-4 sixty days before the clock of the tests.
func agedSeed(t *testing.T) *fake {
	t.Helper()
	st := seed(t, func(l *ledger.Ledger) {
		l.Lookup([]string{"CVE-2026-1"}).Published = tNow.Add(-30 * time.Minute)
		l.Lookup([]string{"CVE-2026-3"}).Published = tNow.Add(-3 * 24 * time.Hour)
		l.Lookup([]string{"CVE-2026-4"}).Published = tNow.Add(-60 * 24 * time.Hour)
	})
	return newFake(t, st)
}

func crumbLineOf(d *driver) string { return strings.Split(d.view(), "\n")[1] }

func TestTimeFilterKeyCyclesThroughThePeriodsAndCountsFollow(t *testing.T) {
	d := start(t, agedSeed(t), Options{})
	d.want("open issues 3", "3 of 3 open issues")
	d.wantNot("published:")
	steps := []struct {
		chip string
		n    int
	}{{"past hour", 1}, {"past 24 hours", 1}, {"past week", 2}, {"past month", 2}, {"past year", 3}}
	for _, s := range steps {
		d.press("t")
		if line := crumbLineOf(d); !strings.Contains(line, "published: "+s.chip) {
			t.Fatalf("the chip lacks %q: %q", s.chip, line)
		}
		d.want("open issues "+string(rune('0'+s.n)), string(rune('0'+s.n))+" of "+string(rune('0'+s.n))+" open issues")
	}
	d.press("t")
	d.wantNot("published:")
	d.want("open issues 3", "3 of 3 open issues")
}

func TestTimeFilterNarrowsBothListsTheBarsAndTheBadge(t *testing.T) {
	d := start(t, agedSeed(t), Options{})
	d.press("t", "t", "t") // past week
	d.want("1 Overview", "2 Findings (2)", "CVE-2026-1", "CVE-2026-3")
	d.wantNot("CVE-2026-4")
	d.press("2")
	d.want("2 of 2 open issues", "CVE-2026-1", "CVE-2026-3")
	d.wantNot("CVE-2026-4")
	d.press("3")
	d.want("published: past week") // the chip is on every screen
}

func TestTimeFilterWorksWithTheScopeAndEachOneClearsOnItsOwn(t *testing.T) {
	d := start(t, agedSeed(t), Options{})
	a := d.m.(*app)
	scopeTo(d, "shop")
	d.press("t", "t", "t")
	d.want("scope: shop", "published: past week", "open issues 2")
	scopeTo(d, "mw")
	d.want("open issues 1", "CVE-2026-1")
	d.press("0") // the scope goes first
	if a.scope != "" || a.published.Any() {
		t.Fatalf("scope %q, time filter %v", a.scope, a.published.Label())
	}
	d.press("0")
	if !a.published.Any() {
		t.Fatalf("0 clears the time filter: %v", a.published.Label())
	}
	d.want("time filter cleared", "open issues 3")
	d.wantNot("published:")
}

func TestTimeChipIsClearedByAClick(t *testing.T) {
	d := start(t, agedSeed(t), Options{})
	a := d.m.(*app)
	d.press("t")
	line := crumbLineOf(d)
	d.click(width(line[:strings.Index(line, "published:")])+2, 1)
	if !a.published.Any() {
		t.Fatalf("a click on the chip keeps %q", a.published.Label())
	}
	d.wantNot("published:")
	scopeTo(d, "mw")
	d.press("t")
	line = crumbLineOf(d)
	if !strings.Contains(line, "published: past hour") || !strings.Contains(line, "scope: mw") {
		t.Fatalf("both chips are on the line: %q", line)
	}
	d.click(width(line[:strings.Index(line, "scope: mw")])+2, 1)
	if a.scope != "" || a.published.Any() {
		t.Fatalf("a click on the scope chip clears only the scope: %q %q", a.scope, a.published.Label())
	}
}

func TestSearchPublishedTermShowsInTheChip(t *testing.T) {
	d := start(t, agedSeed(t), Options{})
	d.press("2", "/")
	d.typ("published:2026-09-25..2026-10-01")
	d.press("enter")
	d.want("1 of 3 open issues", "CVE-2026-3", "published: 2026-09-25 to 2026-10-01")
	d.wantNot("CVE-2026-1 ", "CVE-2026-4")
	if strings.Contains(crumbLineOf(d), "×") {
		t.Fatalf("a range typed in the filter is cleared by the filter, not by a click: %q", crumbLineOf(d))
	}
	d.press("esc")
	d.wantNot("published:")
	d.want("3 of 3 open issues")

	d.press("/")
	d.typ("published:2026-09-25..2026-10-04")
	d.press("enter")
	d.want("2 of 3 open issues", "published: 2026-09-25 to 2026-10-04")
	d.press("t") // together with the filter of the key
	d.want("published: past hour + 2026-09-25 to 2026-10-04", "1 of 1 open issues")
}

func TestTimeFilterSaysWhenNothingIsInIt(t *testing.T) {
	d := start(t, newFake(t, nil), Options{}) // every issue is two days old
	d.press("t")
	d.want("Nothing open published past hour", "0 for any time")
	d.press("2")
	d.want("Nothing open published past hour")
	scopeTo(d, "mw")
	d.want("Nothing open in project mw published past hour")
}

func TestJumpingToAnIssueOutsideTheTimeFilterShowsIt(t *testing.T) {
	d := start(t, agedSeed(t), Options{})
	a := d.m.(*app)
	d.press("t") // past hour: only CVE-2026-1
	d.send(a.goTo(issueTarget("CVE-2026-4", false)))
	if !a.published.Any() {
		t.Fatalf("the time filter hides the issue the jump is for: %q", a.published.Label())
	}
	d.want("CVE-2026-4", "3 of 3 open issues")
}

func TestTimeKeyIsListedInTheHelpOfBothLists(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	for _, key := range []string{"1", "2"} {
		d.press(key, "?")
		d.want("cycle the time filter")
		d.press("esc")
	}
}

func TestHorizonIsShownOnOverviewAndStatusOnlyWhenLimited(t *testing.T) {
	b := newFake(t, nil)
	d := start(t, b, Options{})
	d.wantNot("alert horizon")
	d.press("4")
	d.wantNot("alert horizon")

	b.cfg.Horizon = config.Horizon{Window: config.WindowWeek}
	d = start(t, b, Options{})
	d.want("alert horizon: past week")
	d.press("4")
	d.want("alert horizon: past week")

	b.cfg.Horizon = config.Horizon{Window: config.WindowCustom}
	d = start(t, b, Options{})
	d.wantNot("alert horizon") // a custom range with no ends lets everything through

	b.cfg.Horizon = config.Horizon{Window: config.WindowCustom, From: "2026-01-01", To: "2026-03-01"}
	d = start(t, b, Options{})
	d.want("alert horizon: 2026-01-01 to 2026-03-01")
}

func TestInRangeKeepsOnlyIssuesPublishedInside(t *testing.T) {
	now := tNow
	issues := []query.Issue{{ID: "new", Published: now.Add(-time.Minute)}, {ID: "old", Published: now.Add(-400 * 24 * time.Hour)}, {ID: "undated"}}
	ids := func(r query.TimeRange) string {
		var out []string
		for _, is := range inRange(issues, r, now) {
			out = append(out, is.ID)
		}
		return strings.Join(out, ",")
	}
	if got := ids(query.TimeRange{}); got != "new,old,undated" {
		t.Errorf("any time: %s", got)
	}
	if got := ids(query.Presets[3]); got != "new" {
		t.Errorf("past week: %s", got)
	}
}

func TestSearchPublishedLabelsOnlyUsableTerms(t *testing.T) {
	cases := map[string][]string{
		"":                           nil,
		"severity:high php":          nil,
		"published:week":             {"past week"},
		"PUBLISHED:3d nginx":         {"past 3d"},
		"published:..2026-03-01":     {"until 2026-03-01"},
		"published:nonsense":         nil,
		"published:any":              nil,
		"published:day published:1y": {"past 24 hours", "past year"},
	}
	for text, want := range cases {
		got := searchPublished(text)
		if strings.Join(got, "|") != strings.Join(want, "|") {
			t.Errorf("%q: %v, want %v", text, got, want)
		}
	}
}
