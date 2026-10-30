package query

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/b070nd/cvewatch/app/src/config"
)

var rangeNow = time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

func TestParseTimeRange(t *testing.T) {
	for text, c := range map[string]struct {
		span     time.Duration
		from, to string
		label    string
	}{
		"":                           {label: "any time"},
		"any":                        {label: "any time"},
		"hour":                       {span: time.Hour, label: "past hour"},
		"Day":                        {span: 24 * time.Hour, label: "past 24 hours"},
		"week":                       {span: 7 * 24 * time.Hour, label: "past week"},
		"month":                      {span: 30 * 24 * time.Hour, label: "past month"},
		"year":                       {span: 365 * 24 * time.Hour, label: "past year"},
		"24h":                        {span: 24 * time.Hour, label: "past 24 hours"},
		"7d":                         {span: 7 * 24 * time.Hour, label: "past week"},
		"2w":                         {span: 14 * 24 * time.Hour, label: "past 14d"},
		"90d":                        {span: 90 * 24 * time.Hour, label: "past 90d"},
		"36h":                        {span: 36 * time.Hour, label: "past 36h0m0s"},
		"2026-01-01":                 {from: "2026-01-01T00:00:00Z", to: "2026-01-01T23:59:59.999999999Z", label: "2026-01-01 to 2026-01-01"},
		"2026-01-01..2026-03-01":     {from: "2026-01-01T00:00:00Z", to: "2026-03-01T23:59:59.999999999Z", label: "2026-01-01 to 2026-03-01"},
		"..2026-03-01":               {to: "2026-03-01T23:59:59.999999999Z", label: "until 2026-03-01"},
		"2026-01-01..":               {from: "2026-01-01T00:00:00Z", label: "since 2026-01-01"},
		"2026-01-01T10:00:00Z..":     {from: "2026-01-01T10:00:00Z", label: "since 2026-01-01"},
		" 2026-01-01 .. 2026-01-02 ": {from: "2026-01-01T00:00:00Z", to: "2026-01-02T23:59:59.999999999Z", label: "2026-01-01 to 2026-01-02"},
	} {
		r, err := ParseTimeRange(text)
		if err != nil {
			t.Errorf("%q: %v", text, err)
			continue
		}
		var from, to time.Time
		if c.from != "" {
			from, _ = time.Parse(time.RFC3339Nano, c.from)
		}
		if c.to != "" {
			to, _ = time.Parse(time.RFC3339Nano, c.to)
		}
		if r.Span != c.span || !r.From.Equal(from) || !r.To.Equal(to) || r.Label() != c.label {
			t.Errorf("%q: %+v label %q, want span %v %v..%v label %q", text, r, r.Label(), c.span, from, to, c.label)
		}
	}
	for _, bad := range []string{"soon", "..", "2026-02-30", "03/01/2026", "2026-03-01..2026-01-01", "0d", "-3d", "99999999999999y", "1..2"} {
		if _, err := ParseTimeRange(bad); err == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
}

func TestTimeRangeContainsAndCycle(t *testing.T) {
	week, _ := ParseTimeRange("week")
	custom, _ := ParseTimeRange("2026-09-01..2026-09-30")
	for name, c := range map[string]struct {
		r    TimeRange
		when time.Time
		want bool
	}{
		"any, old":           {TimeRange{}, time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC), true},
		"any, undated":       {TimeRange{}, time.Time{}, true},
		"week, start":        {week, rangeNow.Add(-7 * 24 * time.Hour), true},
		"week, before":       {week, rangeNow.Add(-7*24*time.Hour - time.Second), false},
		"week, ahead":        {week, rangeNow.Add(time.Hour), true},
		"week, undated":      {week, time.Time{}, false},
		"custom, last day":   {custom, time.Date(2026, 9, 30, 23, 59, 0, 0, time.UTC), true},
		"custom, next day":   {custom, time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), false},
		"horizon, undated":   {InHorizon(config.Horizon{Window: "week"}, rangeNow), time.Time{}, true},
		"horizon, too old":   {InHorizon(config.Horizon{Window: "week"}, rangeNow), rangeNow.AddDate(0, 0, -8), false},
		"horizon, unlimited": {InHorizon(config.Horizon{}, rangeNow), rangeNow.AddDate(-9, 0, 0), true},
	} {
		if got := c.r.Contains(c.when, rangeNow); got != c.want {
			t.Errorf("%s: got %v", name, got)
		}
	}

	var labels []string
	r := TimeRange{}
	for range Presets {
		labels = append(labels, r.Label())
		r = r.Next()
	}
	want := []string{"any time", "past hour", "past 24 hours", "past week", "past month", "past year"}
	if !slices.Equal(labels, want) || !r.Any() {
		t.Errorf("cycle %v, back at %+v", labels, r)
	}
	if custom.Next().Label() != "any time" {
		t.Error("a custom range goes back to any time")
	}
}

func TestSearchPublished(t *testing.T) {
	ids := func(text string) string {
		s, err := ParseSearchAt(text, rangeNow)
		if err != nil {
			t.Fatalf("%q: %v", text, err)
		}
		var got []string
		for _, is := range searchIssues() {
			if s.Match(is) {
				got = append(got, is.ID)
			}
		}
		return strings.Join(got, ",")
	}
	for text, want := range map[string]string{
		"published:week":                           openssl,
		"published:7d":                             openssl,
		"published:24h":                            "",
		"published:month":                          php + "," + openssl,
		"published:year":                           php + "," + openssl + "," + nginx,
		"published:2026-09-01..2026-09-30":         php,
		"published:..2026-01-31":                   nginx,
		"published:2026-10-01..":                   openssl,
		"published:2026-10-02":                     openssl,
		"-published:week":                          php + "," + nginx,
		"published:week OR published:..2026-01-31": openssl + "," + nginx,
		"published:month severity:critical":        openssl,
		"published:week,2026-09-15":                php + "," + openssl,
		"published:any":                            php + "," + openssl + "," + nginx,
	} {
		if got := ids(text); got != want {
			t.Errorf("%q: got %q, want %q", text, got, want)
		}
	}
	for _, bad := range []string{"published:soon", "published:", "published:2026-03-01..2026-01-01"} {
		if _, err := ParseSearchAt(bad, rangeNow); err == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
	_, err := ParseSearchAt("foo:bar", rangeNow)
	if err == nil || !strings.Contains(err.Error(), "published") {
		t.Errorf("the field list must name published: %v", err)
	}
}

func TestFilterPublishedNarrowsOpen(t *testing.T) {
	l := seed()
	all := Open(l, Filter{}, now)
	recent := Open(l, Filter{Published: TimeRange{Span: 24 * time.Hour}}, now)
	if len(all) != 4 || len(recent) != 0 {
		t.Fatalf("all %d, last day %d", len(all), len(recent))
	}
	if got := Open(l, Filter{Published: TimeRange{Span: 3 * 24 * time.Hour}}, now); len(got) != 1 || got[0].ID != "NEW" {
		t.Fatalf("the last three days hold only NEW: %+v", got)
	}
	r, _ := ParseTimeRange("2026-10-01..2026-10-01")
	if got := Open(l, Filter{Published: r}, now); len(got) != 3 {
		t.Fatalf("the first day holds three issues: %d", len(got))
	}
}
