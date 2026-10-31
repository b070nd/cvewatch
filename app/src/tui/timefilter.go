package tui

import (
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/b070nd/cvewatch/app/src/query"
)

// timeNow is the clock the time filter counts back from: the moment of the snapshot.
func (m *app) timeNow() time.Time {
	if m.data != nil && !m.data.At.IsZero() {
		return m.data.At
	}
	return time.Now()
}

// inRange keeps the issues published inside the range.
func inRange(issues []query.Issue, r query.TimeRange, now time.Time) []query.Issue {
	if r.Any() {
		return issues
	}
	var out []query.Issue
	for _, is := range issues {
		if r.Contains(is.Published, now) {
			out = append(out, is)
		}
	}
	return out
}

// cycleTime steps the time filter: any time, past hour, 24 hours, week, month, year.
func (m *app) cycleTime() tea.Cmd {
	m.published = m.published.Next()
	m.rescope()
	if m.published.Any() {
		m.say("time filter: any time")
		return nil
	}
	m.say("time filter: published " + m.published.Label() + " (t changes it, 0 shows any time)")
	return nil
}

// clearTime shows issues of any age again.
func (m *app) clearTime() {
	if m.published.Any() {
		return
	}
	m.published = query.TimeRange{}
	m.rescope()
	m.say("time filter cleared: any time")
}

// searchPublished are the labels of the published: terms the search text has.
func searchPublished(text string) []string {
	var out []string
	for _, w := range strings.Fields(text) {
		v, ok := strings.CutPrefix(strings.ToLower(w), "published:")
		if !ok {
			continue
		}
		if r, err := query.ParseTimeRange(v); err == nil && !r.Any() {
			out = append(out, r.Label())
		}
	}
	return out
}

// timeChip is the note on the breadcrumb line that tells the time filter: the
// one set with t, and any published: term of the search text of the list in
// front. Empty when neither narrows the list.
func (m *app) timeChip() string {
	var parts []string
	if !m.published.Any() {
		parts = append(parts, m.published.Label())
	}
	if m.scr == scrOverview || m.scr == scrFindings {
		parts = append(parts, searchPublished(m.list().text)...)
	}
	if len(parts) == 0 {
		return ""
	}
	chip := "published: " + trunc(oneLine(strings.Join(parts, " + ")), 36)
	if !m.published.Any() {
		chip += " ×"
	}
	return chip
}

// chips are the notes at the right end of the breadcrumb line that fit in w
// cells; the one dropped first is the time filter.
func (m *app) chips(w int) (timeChip, scopeChip string) {
	timeChip, scopeChip = m.timeChip(), m.tenantChip()
	room := func() int {
		n := 0
		for _, c := range []string{timeChip, scopeChip} {
			if c != "" {
				n += width(c) + 1
			}
		}
		return n
	}
	if room()+11 >= w {
		timeChip = ""
	}
	if room()+11 >= w {
		scopeChip = ""
	}
	return timeChip, scopeChip
}

func bindTime() binding {
	return binding{keys: ks("t"), help: "cycle the time filter on the publication date: any time, past hour, 24 hours, week, month, year; 0 or a click on its note clears it; for a range type published:2026-01-01..2026-03-01 in the filter",
		short: "time", prio: 4, do: plain((*app).cycleTime)}
}

func bindClearTime() binding {
	return binding{keys: ks("0"), help: "show issues of any age again: clears the time filter", short: "any time", prio: 2,
		when: func(m *app) bool { return !m.published.Any() }, do: plain(func(m *app) tea.Cmd { m.clearTime(); return nil })}
}

// horizonText is the alert horizon in words, empty when it is unlimited.
func (sn *snapshot) horizonText() string {
	if sn == nil || sn.Horizon.Unlimited(sn.At) {
		return ""
	}
	return sn.Horizon.Label()
}
