package config

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

// Alert horizon windows, as Google's time filter names them.
const (
	WindowUnlimited = "unlimited" // any time
	WindowHour      = "hour"      // past hour
	WindowDay       = "day"       // past 24 hours
	WindowWeek      = "week"      // past week
	WindowMonth     = "month"     // past month
	WindowYear      = "year"      // past year
	WindowCustom    = "custom"    // from and to
)

// Windows lists the window names in the order a front end offers them.
var Windows = []string{WindowUnlimited, WindowHour, WindowDay, WindowWeek, WindowMonth, WindowYear, WindowCustom}

// WindowSpan is how far back a rolling window reaches; 0 for unlimited and custom.
func WindowSpan(window string) time.Duration {
	switch window {
	case WindowHour:
		return time.Hour
	case WindowDay:
		return 24 * time.Hour
	case WindowWeek:
		return 7 * 24 * time.Hour
	case WindowMonth:
		return 30 * 24 * time.Hour
	case WindowYear:
		return 365 * 24 * time.Hour
	}
	return 0
}

// Horizon limits which vulnerabilities are judged, alerted and digested by
// their publication date. Rolling windows are computed from "now" each cycle.
type Horizon struct {
	Window string `yaml:"window"` // unlimited (default), hour, day, week, month, year or custom
	From   string `yaml:"from"`   // custom only: YYYY-MM-DD or RFC3339; empty means no start
	To     string `yaml:"to"`     // custom only: YYYY-MM-DD (that whole day) or RFC3339; empty means now
}

// Range is the window at now. A zero from or to means that side is open, so
// the zero Horizon (unlimited) gives two zero times. Rolling windows are open
// at the end, which keeps items dated a little ahead of the clock inside.
func (h Horizon) Range(now time.Time) (from, to time.Time) {
	switch h.window() {
	case WindowCustom:
		from, _ = ParseBound(h.From, false)
		to, _ = ParseBound(h.To, true)
	default:
		if span := WindowSpan(h.window()); span > 0 {
			from = now.Add(-span)
		}
	}
	return from, to
}

// Contains reports whether a publication date is inside the window at now.
// An item without a date is always inside; bounds are inclusive.
func (h Horizon) Contains(published, now time.Time) bool {
	if published.IsZero() {
		return true
	}
	from, to := h.Range(now)
	return (from.IsZero() || !published.Before(from)) && (to.IsZero() || !published.After(to))
}

// Unlimited reports whether the window lets everything through at now.
func (h Horizon) Unlimited(now time.Time) bool {
	from, to := h.Range(now)
	return from.IsZero() && to.IsZero()
}

// Label describes the window in plain words, for status lines and the TUI.
func (h Horizon) Label() string {
	switch w := h.window(); w {
	case WindowUnlimited:
		return "any time"
	case WindowDay:
		return "past 24 hours"
	case WindowCustom:
		switch {
		case h.From != "" && h.To != "":
			return h.From + " to " + h.To
		case h.From != "":
			return "since " + h.From
		case h.To != "":
			return "until " + h.To
		}
		return "any time"
	default:
		return "past " + w
	}
}

func (h Horizon) window() string {
	if h.Window == "" {
		return WindowUnlimited
	}
	return h.Window
}

// HorizonProblem is one thing wrong with the horizon; Field is the key inside horizon.
type HorizonProblem struct {
	Field string
	Msg   string
}

// Problems checks the window and, for custom, the dates. A from or to that
// does not apply to the window is not an error, so switching the window back
// and forth keeps the dates.
func (h Horizon) Problems() []HorizonProblem {
	var out []HorizonProblem
	if !slices.Contains(Windows, h.window()) {
		out = append(out, HorizonProblem{"window", fmt.Sprintf("horizon.window %q is unknown (use %s)", h.Window, strings.Join(Windows, ", "))})
	}
	if h.window() != WindowCustom {
		return out
	}
	from, ferr := ParseBound(h.From, false)
	to, terr := ParseBound(h.To, true)
	if ferr != nil {
		out = append(out, HorizonProblem{"from", "horizon.from " + ferr.Error()})
	}
	if terr != nil {
		out = append(out, HorizonProblem{"to", "horizon.to " + terr.Error()})
	}
	if ferr == nil && terr == nil && !from.IsZero() && !to.IsZero() && to.Before(from) {
		out = append(out, HorizonProblem{"to", "horizon.to is before horizon.from"})
	}
	return out
}

// Reach is how far back the window can see at now, or 0 when it has no start
// or none that can be told. It is compared with the lookback of a first run.
func (h Horizon) Reach(now time.Time) time.Duration {
	if from, _ := h.Range(now); !from.IsZero() {
		return now.Sub(from)
	}
	return 0
}

// ParseBound reads a date (YYYY-MM-DD, read as UTC) or an RFC3339 time. An
// empty string is the zero time. With endOfDay a date stands for the last
// instant of that day, so a range ending on it includes the whole day.
func ParseBound(s string, endOfDay bool) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse(time.DateOnly, s); err == nil {
		if endOfDay {
			t = t.AddDate(0, 0, 1).Add(-time.Nanosecond)
		}
		return t, nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("%q must be YYYY-MM-DD or RFC3339 like 2026-03-01T12:00:00Z", s)
}

// formatSpan writes spans of a day or more as days (30d) and shorter ones as a Go duration.
func formatSpan(d time.Duration) string {
	if d >= 24*time.Hour {
		return fmt.Sprintf("%dd", d/(24*time.Hour))
	}
	return d.Round(time.Minute).String()
}
