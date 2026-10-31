package query

import (
	"fmt"
	"strings"
	"time"

	"github.com/b070nd/cvewatch/app/src/config"
)

// TimeRange filters publication dates like Google: any time (zero value), a rolling span or a custom range; ends are inclusive, a zero end is open.
type TimeRange struct {
	Span     time.Duration // rolling: the last Span up to now
	From, To time.Time     // custom range; used when Span is 0
	Undated  bool          // an issue without a publication date counts as inside
}

// Presets are the cycle of quick filters: any time, then the rolling windows
// of config.Horizon (hour, day, week, month, year).
var Presets = []TimeRange{{}, rolling(config.WindowHour), rolling(config.WindowDay), rolling(config.WindowWeek), rolling(config.WindowMonth), rolling(config.WindowYear)}

func rolling(window string) TimeRange { return TimeRange{Span: config.WindowSpan(window)} }

// Between is the custom range from..to, with open ends when zero.
func Between(from, to time.Time) TimeRange { return TimeRange{From: from, To: to} }

// InHorizon is the alert horizon at now as a filter range; undated issues stay inside.
func InHorizon(h config.Horizon, now time.Time) TimeRange {
	from, to := h.Range(now)
	return TimeRange{From: from, To: to, Undated: true}
}

// Any reports whether the range lets everything through.
func (r TimeRange) Any() bool { return r.Span == 0 && r.From.IsZero() && r.To.IsZero() }

// Bounds resolves the range at now; a zero side is open.
func (r TimeRange) Bounds(now time.Time) (from, to time.Time) {
	if r.Span > 0 {
		return now.Add(-r.Span), time.Time{}
	}
	return r.From, r.To
}

// Contains reports whether a publication date is inside the range at now.
func (r TimeRange) Contains(published, now time.Time) bool {
	if r.Any() {
		return true
	}
	if published.IsZero() {
		return r.Undated
	}
	from, to := r.Bounds(now)
	return (from.IsZero() || !published.Before(from)) && (to.IsZero() || !published.After(to))
}

// Next cycles any time, hour, day, week, month, year, any time; a range that is no preset goes to any time.
func (r TimeRange) Next() TimeRange {
	for i, p := range Presets {
		if p.Span == r.Span && r.From.IsZero() && r.To.IsZero() {
			next := Presets[(i+1)%len(Presets)]
			next.Undated = r.Undated
			return next
		}
	}
	return TimeRange{Undated: r.Undated}
}

// Label describes the range in plain words, for a status line.
func (r TimeRange) Label() string {
	switch {
	case r.Any():
		return "any time"
	case r.Span == 24*time.Hour:
		return "past 24 hours"
	case r.Span > 0:
		for _, w := range config.Windows {
			if config.WindowSpan(w) == r.Span {
				return "past " + w
			}
		}
		return "past " + spanText(r.Span)
	}
	day := func(t time.Time) string { return t.UTC().Format(time.DateOnly) }
	switch {
	case r.From.IsZero():
		return "until " + day(r.To)
	case r.To.IsZero():
		return "since " + day(r.From)
	}
	return day(r.From) + " to " + day(r.To)
}

func spanText(d time.Duration) string {
	if d%(24*time.Hour) == 0 {
		return fmt.Sprintf("%dd", d/(24*time.Hour))
	}
	return d.String()
}

// ParseTimeRange reads any, hour/day/week/month/year, a span (24h, 7d, 2w, 1y), a day (2026-01-01) or a range (2026-01-01..2026-03-01, ..2026-03-01, 2026-01-01..); dates are UTC.
func ParseTimeRange(text string) (TimeRange, error) {
	v := strings.ToLower(strings.TrimSpace(text))
	switch v {
	case "", "any", "all", "anytime", "unlimited":
		return TimeRange{}, nil
	case "today":
		v = "day"
	}
	for _, w := range config.Windows {
		if v == w && config.WindowSpan(w) > 0 {
			return rolling(w), nil
		}
	}
	if d, ok := parseSpan(v); ok {
		return TimeRange{Span: d}, nil
	}
	from, to, found := strings.Cut(strings.TrimSpace(text), "..")
	if !found {
		to = from
	}
	f, ferr := config.ParseBound(from, false)
	t, terr := config.ParseBound(to, true)
	switch {
	case ferr != nil || terr != nil:
		return TimeRange{}, fmt.Errorf("bad time filter %q; use hour, day, week, month, year, a span like 24h or 7d, a day YYYY-MM-DD, or a range like 2026-01-01..2026-03-01", text)
	case f.IsZero() && t.IsZero():
		return TimeRange{}, fmt.Errorf("bad time filter %q; a range needs a date on at least one side", text)
	case !f.IsZero() && !t.IsZero() && t.Before(f):
		return TimeRange{}, fmt.Errorf("bad time filter %q; the range ends before it starts", text)
	}
	return Between(f, t), nil
}

// parseSpan reads 24h, 7d, 2w, 3mo or 1y.
func parseSpan(v string) (time.Duration, bool) {
	units := []struct {
		suffix string
		unit   time.Duration
	}{{"mo", 30 * 24 * time.Hour}, {"h", time.Hour}, {"d", 24 * time.Hour}, {"w", 7 * 24 * time.Hour}, {"y", 365 * 24 * time.Hour}}
	for _, u := range units {
		num, ok := strings.CutSuffix(v, u.suffix)
		if !ok || num == "" {
			continue
		}
		n := 0
		for _, c := range num {
			if c < '0' || c > '9' || n > 1000000 {
				return 0, false
			}
			n = n*10 + int(c-'0')
		}
		if d := time.Duration(n) * u.unit; n > 0 && d/u.unit == time.Duration(n) {
			return d, true
		}
	}
	return 0, false
}
