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
	d.want("[O]verview", "[F]indings (2)", "CVE-2026-1", "CVE-2026-3")
	d.wantNot("CVE-2026-4")
	d.screen("findings")
	d.want("2 of 2 open issues", "CVE-2026-1", "CVE-2026-3")
	d.wantNot("CVE-2026-4")
	d.screen("projects")
	d.want("published: past week") // the chip is on every screen
}

func TestTimeFilterWorksInTheContextAndZeroClearsOnlyTheTimeFilter(t *testing.T) {
	d := start(t, agedSeed(t), Options{})
	a := d.m.(*app)
	scopeTo(d, "shop")
	d.press("t", "t", "t")
	d.want("context: shop", "published: past week", "open issues 2")
	scopeTo(d, "mw")
	d.want("open issues 1", "CVE-2026-1")
	d.press("0")
	if !a.published.Any() || a.tenant.project != "mw" {
		t.Fatalf("0 clears the time filter and keeps the context: %v, %q", a.published.Label(), a.tenant.project)
	}
	d.want("time filter cleared", "context: mw", "open issues 1")
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
	if !strings.Contains(line, "published: past hour") || !strings.Contains(line, "context: mw") {
		t.Fatalf("both chips are on the line: %q", line)
	}
	d.click(width(line[:strings.Index(line, "context: mw")])+2, 1)
	d.want("Choose the context")
	if a.tenant.project != "mw" || a.published.Label() != "past hour" {
		t.Fatalf("a click on the context chip opens the choice and changes nothing: %q %q", a.tenant.project, a.published.Label())
	}
}

func TestSearchPublishedTermShowsInTheChip(t *testing.T) {
	d := start(t, agedSeed(t), Options{})
	d.screen("findings")
	d.press("/")
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
	d.want("Nothing open in shop published past hour", "0 for any time")
	d.screen("findings")
	d.want("Nothing open in shop published past hour")
	scopeTo(d, "mw")
	d.want("Nothing open in mw published past hour")
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
	for _, key := range []string{"O", "F"} {
		d.press(key, "?")
		d.want("cycle the time filter")
		d.press("esc")
	}
}

func TestHorizonIsShownOnOverviewAndStatusOnlyWhenLimited(t *testing.T) {
	b := newFake(t, nil)
	d := start(t, b, Options{})
	d.wantNot("alert horizon")
	d.screen("health")
	d.wantNot("alert horizon")

	b.cfg.Horizon = config.Horizon{Window: config.WindowWeek}
	d = start(t, b, Options{})
	d.want("alert horizon: past week")
	d.screen("health")
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
