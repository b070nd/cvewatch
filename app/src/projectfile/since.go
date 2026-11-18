package projectfile

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var relativeSince = regexp.MustCompile(`^(?:now)?\s*-?\s*(\d{1,4})\s*([hdwmy])$`)

// ParseSince reads where a project's history starts: a day (2026-01-31), a
// time (2026-01-31T08:30:00Z or 2026-01-31 08:30, UTC) or a span back from
// now (24h, 7d, 2w, 3m, 1y, also written now-7d). A span of days or more
// starts at the beginning of that day in UTC; hours are exact.
func ParseSince(s string, now time.Time) (time.Time, error) {
	s = strings.TrimSpace(s)
	for _, layout := range []string{SinceLayout, time.RFC3339, "2006-01-02 15:04", "2006-01-02T15:04"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	if m := relativeSince.FindStringSubmatch(strings.ToLower(s)); m != nil {
		n, _ := strconv.Atoi(m[1])
		now = now.UTC()
		switch m[2] {
		case "h":
			return now.Add(-time.Duration(n) * time.Hour).Truncate(time.Minute), nil
		case "d":
			return day(now.AddDate(0, 0, -n)), nil
		case "w":
			return day(now.AddDate(0, 0, -7*n)), nil
		case "m":
			return day(now.AddDate(0, -n, 0)), nil
		case "y":
			return day(now.AddDate(-n, 0, 0)), nil
		}
	}
	return time.Time{}, fmt.Errorf("since must be a day like 2026-01-31, a time like 2026-01-31T08:30:00Z or a span back from now like 24h, 7d, 2w, 3m or 1y; got %q", s)
}

func day(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}

// FormatSince writes a start the way the project file holds it: the day when
// it begins at midnight UTC, else the time.
func FormatSince(t time.Time) string {
	t = t.UTC()
	if t.Equal(day(t)) {
		return t.Format(SinceLayout)
	}
	return t.Format(time.RFC3339)
}
