package config

import (
	"strings"
	"testing"
	"time"
)

func at(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func TestHorizonRange(t *testing.T) {
	now := at("2026-10-27T12:00:00Z")
	for name, c := range map[string]struct {
		h        Horizon
		from, to time.Time
	}{
		"zero value":      {Horizon{}, time.Time{}, time.Time{}},
		"unlimited":       {Horizon{Window: "unlimited"}, time.Time{}, time.Time{}},
		"hour":            {Horizon{Window: "hour"}, now.Add(-time.Hour), time.Time{}},
		"day":             {Horizon{Window: "day"}, now.Add(-24 * time.Hour), time.Time{}},
		"week":            {Horizon{Window: "week"}, at("2026-10-20T12:00:00Z"), time.Time{}},
		"month":           {Horizon{Window: "month"}, at("2026-09-27T12:00:00Z"), time.Time{}},
		"year":            {Horizon{Window: "year"}, at("2025-10-27T12:00:00Z"), time.Time{}},
		"custom both":     {Horizon{Window: "custom", From: "2026-01-01", To: "2026-03-01"}, at("2026-01-01T00:00:00Z"), at("2026-03-01T23:59:59Z").Add(999999999 * time.Nanosecond)},
		"custom no end":   {Horizon{Window: "custom", From: "2026-01-01"}, at("2026-01-01T00:00:00Z"), time.Time{}},
		"custom no start": {Horizon{Window: "custom", To: "2026-03-01T10:00:00Z"}, time.Time{}, at("2026-03-01T10:00:00Z")},
		"custom empty":    {Horizon{Window: "custom"}, time.Time{}, time.Time{}},
		"dates ignored":   {Horizon{Window: "week", From: "2020-01-01", To: "2020-02-01"}, at("2026-10-20T12:00:00Z"), time.Time{}},
	} {
		from, to := c.h.Range(now)
		if !from.Equal(c.from) || !to.Equal(c.to) {
			t.Errorf("%s: got %v .. %v, want %v .. %v", name, from, to, c.from, c.to)
		}
	}
}

func TestHorizonContains(t *testing.T) {
	now := at("2026-10-27T12:00:00Z")
	week := Horizon{Window: "week"}
	custom := Horizon{Window: "custom", From: "2026-01-01", To: "2026-03-01"}
	for name, c := range map[string]struct {
		h    Horizon
		when time.Time
		want bool
	}{
		"week: exactly the start":    {week, at("2026-10-20T12:00:00Z"), true},
		"week: a second before":      {week, at("2026-10-20T11:59:59Z"), false},
		"week: now":                  {week, now, true},
		"week: a little ahead":       {week, now.Add(time.Hour), true},
		"week: undated":              {week, time.Time{}, true},
		"unlimited: very old":        {Horizon{}, at("1999-01-01T00:00:00Z"), true},
		"custom: the first instant":  {custom, at("2026-01-01T00:00:00Z"), true},
		"custom: just before":        {custom, at("2025-12-31T23:59:59Z"), false},
		"custom: the whole last day": {custom, at("2026-03-01T23:30:00Z"), true},
		"custom: the next day":       {custom, at("2026-03-02T00:00:00Z"), false},
		"custom: undated":            {custom, time.Time{}, true},
	} {
		if got := c.h.Contains(c.when, now); got != c.want {
			t.Errorf("%s: got %v", name, got)
		}
	}
	if !(Horizon{}).Unlimited(now) || !(Horizon{Window: "custom"}).Unlimited(now) || week.Unlimited(now) {
		t.Error("Unlimited must be true only without bounds")
	}
}

func TestHorizonProblems(t *testing.T) {
	for name, c := range map[string]struct {
		h     Horizon
		field string // empty: no problem
	}{
		"fine":                 {Horizon{Window: "month"}, ""},
		"unknown window":       {Horizon{Window: "decade"}, "window"},
		"bad from":             {Horizon{Window: "custom", From: "yesterday"}, "from"},
		"bad to":               {Horizon{Window: "custom", To: "2026-13-01"}, "to"},
		"to before from":       {Horizon{Window: "custom", From: "2026-03-01", To: "2026-01-01"}, "to"},
		"same day is fine":     {Horizon{Window: "custom", From: "2026-03-01", To: "2026-03-01"}, ""},
		"rfc3339 order":        {Horizon{Window: "custom", From: "2026-03-01T12:00:00Z", To: "2026-03-01T11:00:00Z"}, "to"},
		"dates ignored":        {Horizon{Window: "week", From: "nonsense"}, ""},
		"open ends are fine":   {Horizon{Window: "custom"}, ""},
		"empty window":         {Horizon{}, ""},
		"one open end is fine": {Horizon{Window: "custom", To: "2026-01-01"}, ""},
	} {
		ps := c.h.Problems()
		switch {
		case c.field == "" && len(ps) != 0, c.field != "" && (len(ps) != 1 || ps[0].Field != c.field):
			t.Errorf("%s: %+v", name, ps)
		}
	}
}

func TestHorizonLabel(t *testing.T) {
	for h, want := range map[Horizon]string{
		{}:                                     "any time",
		{Window: "day"}:                        "past 24 hours",
		{Window: "week"}:                       "past week",
		{Window: "custom", From: "2026-01-01"}: "since 2026-01-01",
		{Window: "custom", To: "2026-02-01"}:   "until 2026-02-01",
		{Window: "custom", From: "2026-01-01", To: "2026-02-01"}: "2026-01-01 to 2026-02-01",
	} {
		if got := h.Label(); got != want {
			t.Errorf("%+v: %q, want %q", h, got, want)
		}
	}
}

func TestHorizonSettingsDefaultsAndChecks(t *testing.T) {
	root := t.TempDir()
	b, err := Load(root)
	if err != nil || b.Horizon.Window != WindowUnlimited || len(b.Warnings) != 0 {
		t.Fatalf("default: %+v %v %v", b.Horizon, err, b.Warnings)
	}

	_, issues := Check(root, Overlay{SettingsPath(root): []byte("horizon:\n  window: custom\n  from: 2026-03-01\n  to: 2026-01-01\n")})
	if len(issues) != 1 || issues[0].Field != "horizon.to" || issues[0].File != SettingsPath(root) {
		t.Fatalf("to before from: %+v", issues)
	}
	_, issues = Check(root, Overlay{SettingsPath(root): []byte("horizon:\n  window: decade\n  frm: x\n")})
	if len(issues) == 0 {
		t.Fatal("an unknown key must be rejected")
	}
	_, issues = Check(root, Overlay{SettingsPath(root): []byte("horizon:\n  window: decade\n")})
	if len(issues) != 1 || issues[0].Field != "horizon.window" {
		t.Fatalf("unknown window: %+v", issues)
	}
}

func TestHorizonWarnsWhenItReachesBeyondTheLookback(t *testing.T) {
	root := t.TempDir()
	warn := func(text string) []string {
		b, issues := Check(root, Overlay{SettingsPath(root): []byte(text)})
		if len(issues) != 0 {
			t.Fatalf("%q: %+v", text, issues)
		}
		return b.Warnings
	}
	if w := warn("horizon:\n  window: month\n"); len(w) != 1 || !strings.Contains(w[0], "raise lookback") || !strings.Contains(w[0], "30d") {
		t.Fatalf("a month is more than the default week of lookback: %v", w)
	}
	for _, text := range []string{
		"horizon:\n  window: week\n",
		"horizon:\n  window: month\nlookback: 720h\n",
		"horizon:\n  window: custom\n  to: 2020-01-01\n",
		"",
	} {
		if w := warn(text); len(w) != 0 {
			t.Errorf("%q: unexpected warning %v", text, w)
		}
	}
	if w := warn("horizon:\n  window: custom\n  from: 2020-01-01\n"); len(w) != 1 {
		t.Errorf("a custom start far back warns: %v", w)
	}
}
