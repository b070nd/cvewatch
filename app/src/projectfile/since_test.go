package projectfile

import (
	"testing"
	"time"
)

func TestParseSince(t *testing.T) {
	now := time.Date(2026, 11, 18, 14, 35, 20, 0, time.UTC)
	for in, want := range map[string]string{
		"2026-01-31":           "2026-01-31",
		"2026-01-31T08:30:00Z": "2026-01-31T08:30:00Z",
		"2026-01-31 08:30":     "2026-01-31T08:30:00Z",
		"24h":                  "2026-11-17T14:35:00Z",
		"7d":                   "2026-11-11",
		"now-7d":               "2026-11-11",
		"-30d":                 "2026-10-19",
		"2w":                   "2026-11-04",
		"3m":                   "2026-08-18",
		"1y":                   "2025-11-18",
		" 1 y ":                "2025-11-18",
	} {
		got, err := ParseSince(in, now)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if f := FormatSince(got); f != want {
			t.Errorf("%q = %s, want %s", in, f, want)
		}
	}
	for _, bad := range []string{"", "yesterday", "7", "d7", "2026-13-01", "10000d", "7x"} {
		if _, err := ParseSince(bad, now); err == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
}
