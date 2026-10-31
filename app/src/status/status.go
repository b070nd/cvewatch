// Package status describes the health of the tool itself: whether the daemon
// is running, whether each feed and channel works, and what the recent cycles
// did. The types are plain data shared by the status command, the dashboard,
// the TUI, doctor and MCP.
package status

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/b070nd/cvewatch/app/src/model"
)

// Level is a traffic-light judgement.
type Level string

const (
	OK      Level = "ok"
	Warn    Level = "warn"
	Fail    Level = "fail"
	Unknown Level = "unknown"
)

// Worse returns the more serious of two levels (fail, warn, unknown, ok).
func (l Level) Worse(o Level) Level {
	rank := func(x Level) int {
		switch x {
		case Fail:
			return 3
		case Warn:
			return 2
		case Unknown:
			return 1
		}
		return 0
	}
	if rank(o) > rank(l) {
		return o
	}
	return l
}

type SourceRow struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Level       Level     `json:"level"`
	LastSuccess time.Time `json:"last_success"`
	LastAttempt time.Time `json:"last_attempt"`
	Failures    int       `json:"failures"` // consecutive failed attempts
	LastError   string    `json:"last_error"`
	Items       int       `json:"items"` // items in the last successful fetch
}

type ChannelRow struct {
	Name        string    `json:"name"`
	Level       Level     `json:"level"`
	LastSuccess time.Time `json:"last_success"`
	LastAttempt time.Time `json:"last_attempt"`
	Failures    int       `json:"failures"`
	LastError   string    `json:"last_error"`
}

type CycleRow struct {
	Started    time.Time `json:"started"`
	Finished   time.Time `json:"finished"`
	Items      int       `json:"items"`
	New        int       `json:"new"`
	Merged     int       `json:"merged"`
	Findings   int       `json:"findings"`
	Reconciled int       `json:"reconciled"`
	Alerted    int       `json:"alerted"`
	Digests    int       `json:"digests"`
	Failed     int       `json:"failed"`
	Err        string    `json:"err,omitempty"`
}

// ProjectRow is when a project is refreshed: Auto says whether scheduled runs
// include it, Every how often, LastUpdate when it was last refreshed (zero if
// never) and Next when the next scheduled run is due (zero when none is).
type ProjectRow struct {
	Name       string        `json:"name"`
	Auto       bool          `json:"auto"`
	Every      time.Duration `json:"every"`
	LastUpdate time.Time     `json:"last_update"`
	Next       time.Time     `json:"next"`
}

// Schedule says how a project is refreshed, as people say it: every is "every
// 1h", "paused" (the project opted out) or "manual" (update.auto switched the
// schedule off for all), next is "next 14:05" ("next 11-02 14:05" on another
// day), "due now" or empty. Times are shown in the location of the report's
// time.
func (r Report) Schedule(p ProjectRow) (every, next string) {
	switch {
	case !r.Scheduled:
		return "manual", ""
	case !p.Auto:
		return "paused", ""
	}
	every = "every " + model.Span(p.Every)
	at := p.Next.In(r.GeneratedAt.Location())
	switch {
	case !p.Next.After(r.GeneratedAt):
		return every, "due now"
	case at.YearDay() == r.GeneratedAt.YearDay() && at.Year() == r.GeneratedAt.Year():
		return every, "next " + at.Format("15:04")
	}
	return every, "next " + at.Format("01-02 15:04")
}

type Daemon struct {
	Level     Level         `json:"level"`
	Mode      string        `json:"mode"` // daemon, or cli when only one-off runs were seen
	LastCycle time.Time     `json:"last_cycle"`
	NextRun   time.Time     `json:"next_run"`
	Interval  time.Duration `json:"interval"`
	Message   string        `json:"message"`
}

// Report is what every health view shows.
type Report struct {
	GeneratedAt time.Time    `json:"generated_at"`
	Level       Level        `json:"level"`
	Daemon      Daemon       `json:"daemon"`
	Sources     []SourceRow  `json:"sources"`
	Channels    []ChannelRow `json:"channels"`
	Cycles      []CycleRow   `json:"cycles"` // most recent first
	Projects    []ProjectRow `json:"projects"`
	Scheduled   bool         `json:"scheduled"` // false when update.auto in config.yaml switched the schedule off
	Warnings    []string     `json:"warnings"`
}

// Reason explains an overall level of unknown, and is empty for any other.
func (r Report) Reason() string {
	if r.Level == Unknown {
		return "no cycle has read a feed yet"
	}
	return ""
}

// Ref names a configured feed or channel, so health can be reported even for
// ones that never ran.
type Ref struct{ ID, Type string }

// Input is everything Build needs; the caller gathers it from config and state.
type Input struct {
	Now      time.Time
	Interval time.Duration // configured refresh interval
	Sources  []Ref         // enabled feeds
	Channels []string      // active channels
	Cycles   []model.CycleRecord
	Health   map[string]model.SourceHealth
	Delivery map[string]model.ChannelHealth
	Beat     *model.Heartbeat
	Projects []ProjectRow
	// Unscheduled is set when update.auto in config.yaml switched the schedule off.
	Unscheduled bool
}

// Build turns stored records into the report every health view shows.
//
// A feed fails after three attempts in a row and warns after one. A feed or
// channel that never ran is unknown, not broken. The daemon is overdue when
// it is more than half an interval (at least ten minutes) past its next run.
// The overall level is unknown, never ok, until a cycle has read a feed, and
// warn when no feed is enabled.
func Build(in Input) Report {
	r := Report{GeneratedAt: in.Now, Level: OK, Projects: in.Projects, Scheduled: !in.Unscheduled}
	stale := in.Interval * 2
	if stale < 12*time.Hour {
		stale = 12 * time.Hour
	}

	for _, ref := range in.Sources {
		h, seen := in.Health[ref.ID]
		row := SourceRow{ID: ref.ID, Type: ref.Type, Level: Unknown, LastSuccess: h.LastSuccess, LastAttempt: h.LastAttempt,
			Failures: h.Failures, LastError: h.LastError, Items: h.Items}
		switch {
		case !seen:
		case h.Failures >= 3:
			row.Level = Fail
			r.Warnings = append(r.Warnings, fmt.Sprintf("feed %s has failed %d times in a row: %s", ref.ID, h.Failures, h.LastError))
		case h.Failures > 0:
			row.Level = Warn
		case in.Now.Sub(h.LastSuccess) > stale:
			row.Level = Warn
			r.Warnings = append(r.Warnings, fmt.Sprintf("feed %s was last read %s ago", ref.ID, ago(in.Now.Sub(h.LastSuccess))))
		default:
			row.Level = OK
		}
		r.Sources = append(r.Sources, row)
		r.Level = r.Level.Worse(row.Level.floor())
	}
	slices.SortFunc(r.Sources, func(a, b SourceRow) int { return strings.Compare(a.ID, b.ID) })

	for _, name := range in.Channels {
		h, seen := in.Delivery[name]
		row := ChannelRow{Name: name, Level: Unknown, LastSuccess: h.LastSuccess, LastAttempt: h.LastAttempt, Failures: h.Failures, LastError: h.LastError}
		switch {
		case !seen:
		case h.Failures >= 3:
			row.Level = Fail
			r.Warnings = append(r.Warnings, fmt.Sprintf("channel %s has failed %d times in a row: %s", name, h.Failures, h.LastError))
		case h.Failures > 0:
			row.Level = Warn
		default:
			row.Level = OK
		}
		r.Channels = append(r.Channels, row)
		r.Level = r.Level.Worse(row.Level.floor())
	}
	slices.SortFunc(r.Channels, func(a, b ChannelRow) int { return strings.Compare(a.Name, b.Name) })

	for i := len(in.Cycles) - 1; i >= 0 && len(r.Cycles) < 10; i-- {
		c := in.Cycles[i]
		r.Cycles = append(r.Cycles, CycleRow{Started: c.Started, Finished: c.Finished, Items: c.Items, New: c.New, Merged: c.Merged,
			Findings: c.Findings, Reconciled: c.Reconciled, Alerted: c.Alerted, Digests: c.Digests, Failed: c.Failed, Err: c.Err})
	}

	r.Daemon = daemon(in)
	r.Level = r.Level.Worse(r.Daemon.Level.floor())
	if r.Daemon.Level == Fail {
		r.Warnings = append(r.Warnings, r.Daemon.Message)
	}
	switch {
	case len(in.Sources) == 0:
		r.Level = r.Level.Worse(Warn)
		r.Warnings = append(r.Warnings, "no enabled sources: nothing will be fetched")
	case r.Level == OK && !succeeded(in):
		r.Level = Unknown // no evidence yet is not good news
	}
	return r
}

// succeeded is whether a cycle has finished with at least one feed read.
func succeeded(in Input) bool {
	return slices.ContainsFunc(in.Cycles, func(c model.CycleRecord) bool { return c.Err == "" && c.Failed < len(in.Sources) })
}

// floor treats "never ran" as healthy for the parts: unknown parts are shown
// but do not make the whole tool look broken. The overall level is unknown, not
// ok, until a cycle has succeeded (see Build).
func (l Level) floor() Level {
	if l == Unknown {
		return OK
	}
	return l
}

// Alive is whether a daemon runs: it recorded a heartbeat and is not overdue.
func (d Daemon) Alive() bool { return d.Mode == "daemon" && d.Level == OK }

func daemon(in Input) Daemon {
	d := Daemon{Level: Unknown, Interval: in.Interval}
	if in.Beat != nil {
		d.Mode, d.LastCycle, d.NextRun, d.Interval = in.Beat.Mode, in.Beat.LastCycle, in.Beat.NextRun, in.Beat.Interval
		grace := d.Interval / 2
		if grace < 10*time.Minute {
			grace = 10 * time.Minute
		}
		if in.Now.After(d.NextRun.Add(grace)) {
			d.Level = Fail
			d.Message = fmt.Sprintf("the daemon is overdue: it should have run at %s and last ran %s ago; is it still running?",
				d.NextRun.UTC().Format("2006-01-02 15:04"), ago(in.Now.Sub(d.LastCycle)))
		} else {
			d.Level = OK
			d.Message = "running; next cycle " + d.NextRun.UTC().Format("2006-01-02 15:04") + " UTC"
		}
		return d
	}
	if n := len(in.Cycles); n > 0 {
		d.Mode, d.LastCycle = "cli", in.Cycles[n-1].Finished
		d.Message = "no daemon seen; cycles are run by hand, the last " + ago(in.Now.Sub(d.LastCycle)) + " ago"
		return d
	}
	d.Message = "no cycle has run yet"
	return d
}

// ago renders a duration the way people say it: 5m, 3h, 2d.
func ago(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "moments"
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%dd", int(d.Hours())/24)
}
