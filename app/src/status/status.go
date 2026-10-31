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

// Level is a traffic-light judgement, as in an Elasticsearch cluster: green
// when nothing needs attention, yellow when something does, red when the
// monitor cannot be relied on.
type Level string

const (
	Green  Level = "green"
	Yellow Level = "yellow"
	Red    Level = "red"
)

// Worse returns the more serious of two levels (red, yellow, green).
func (l Level) Worse(o Level) Level {
	if o.rank() > l.rank() {
		return o
	}
	return l
}

func (l Level) rank() int {
	switch l {
	case Red:
		return 2
	case Yellow:
		return 1
	}
	return 0
}

// Label is the level as a header says it: GREEN, YELLOW, RED.
func (l Level) Label() string { return strings.ToUpper(string(l)) }

// Problem is something that needs a person, listed until its cause is gone.
// There is no way to dismiss one. Key is stable between reports, so a view can
// keep its cursor on the same problem.
type Problem struct {
	Key    string    `json:"key"`
	Level  Level     `json:"level"` // yellow or red
	Title  string    `json:"title"`
	Detail string    `json:"detail,omitempty"`
	Hint   string    `json:"hint,omitempty"`
	Since  time.Time `json:"since,omitempty"`
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
	Problems    []Problem    `json:"problems"` // red first, then yellow, then oldest first; the overall level is the worst
}

// KeyCycle is the key of the problem that no cycle has read a feed yet.
const KeyCycle = "cycle"

// Reason says why a monitor that has not proven itself is not green, and is
// empty once a cycle has read a feed.
func (r Report) Reason() string {
	for _, p := range r.Problems {
		if p.Key == KeyCycle {
			return p.Title
		}
	}
	return ""
}

// Summary is the one line a header shows. Green says when the last check was,
// yellow and red count the problems the views list.
func (r Report) Summary(now time.Time) string {
	if r.Level == Green {
		last := r.Daemon.LastCycle
		if len(r.Cycles) > 0 {
			last = r.Cycles[0].Finished
		}
		if last.IsZero() {
			return r.Level.Label()
		}
		at := last.In(now.Location())
		stamp := at.Format("15:04")
		if at.YearDay() != now.YearDay() || at.Year() != now.Year() {
			stamp = at.Format("01-02 15:04")
		}
		return fmt.Sprintf("%s · last check %s (%s ago)", r.Level.Label(), stamp, ago(now.Sub(last)))
	}
	noun := "problems"
	if len(r.Problems) == 1 {
		noun = "problem"
	}
	return fmt.Sprintf("%s · %d %s", r.Level.Label(), len(r.Problems), noun)
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
	// Problems are the ones only the caller can see: project files, the audit log.
	Problems []Problem
}

// Build turns stored records into the report every health view shows.
//
// A feed or channel is red after three failed attempts in a row and yellow
// after one. The daemon is overdue (red) when it is more than half an interval
// (at least ten minutes) past its next run. Each cause is a problem, and the
// overall level is the worst problem: green only when there are none. Until a
// cycle has read a feed the monitor has not proven itself, which is a problem
// too, as is having no enabled feed.
func Build(in Input) Report {
	r := Report{GeneratedAt: in.Now, Projects: in.Projects, Scheduled: !in.Unscheduled}
	stale := in.Interval * 2
	if stale < 12*time.Hour {
		stale = 12 * time.Hour
	}
	hint := "cvewatch doctor -online fetches every feed once and shows what fails"

	for _, ref := range in.Sources {
		h, seen := in.Health[ref.ID]
		row := SourceRow{ID: ref.ID, Type: ref.Type, Level: Yellow, LastSuccess: h.LastSuccess, LastAttempt: h.LastAttempt,
			Failures: h.Failures, LastError: h.LastError, Items: h.Items}
		key := "feed:" + ref.ID
		switch {
		case !seen: // a feed added since the last cycle is read in the next one
		case h.Failures >= 3:
			row.Level = Red
			r.Warnings = append(r.Warnings, fmt.Sprintf("feed %s has failed %d times in a row: %s", ref.ID, h.Failures, h.LastError))
			r.Problems = append(r.Problems, Problem{Key: key, Level: Red, Title: "feed " + ref.ID + " is failing",
				Detail: fmt.Sprintf("failed %d times in a row: %s", h.Failures, h.LastError), Hint: hint, Since: failingSince(h.FailingSince, h.LastSuccess, h.LastAttempt)})
		case h.Failures > 0:
			row.Level = Yellow
			r.Problems = append(r.Problems, Problem{Key: key, Level: Yellow, Title: "feed " + ref.ID + " had a failed fetch",
				Detail: fmt.Sprintf("failed %d in a row: %s", h.Failures, h.LastError), Hint: hint, Since: failingSince(h.FailingSince, h.LastSuccess, h.LastAttempt)})
		case in.Now.Sub(h.LastSuccess) > stale:
			row.Level = Yellow
			r.Warnings = append(r.Warnings, fmt.Sprintf("feed %s was last read %s ago", ref.ID, ago(in.Now.Sub(h.LastSuccess))))
			r.Problems = append(r.Problems, Problem{Key: key, Level: Yellow, Title: "feed " + ref.ID + " is stale",
				Detail: "last read " + ago(in.Now.Sub(h.LastSuccess)) + " ago", Hint: "is the daemon running? cvewatch update reads the feeds now", Since: h.LastSuccess})
		default:
			row.Level = Green
		}
		r.Sources = append(r.Sources, row)
	}
	slices.SortFunc(r.Sources, func(a, b SourceRow) int { return strings.Compare(a.ID, b.ID) })

	for _, name := range in.Channels {
		h := in.Delivery[name]
		row := ChannelRow{Name: name, Level: Green, LastSuccess: h.LastSuccess, LastAttempt: h.LastAttempt, Failures: h.Failures, LastError: h.LastError}
		key := "channel:" + name
		since := failingSince(h.FailingSince, h.LastSuccess, h.LastAttempt)
		switch {
		case h.Failures >= 3:
			row.Level = Red
			r.Warnings = append(r.Warnings, fmt.Sprintf("channel %s has failed %d times in a row: %s", name, h.Failures, h.LastError))
			r.Problems = append(r.Problems, Problem{Key: key, Level: Red, Title: "channel " + name + " is failing",
				Detail: fmt.Sprintf("failed %d times in a row: %s", h.Failures, h.LastError), Hint: "check the channel's settings; alerts are not delivered through it", Since: since})
		case h.Failures > 0:
			row.Level = Yellow
			r.Problems = append(r.Problems, Problem{Key: key, Level: Yellow, Title: "channel " + name + " had a failed delivery",
				Detail: fmt.Sprintf("failed %d in a row: %s", h.Failures, h.LastError), Hint: "check the channel's settings; the next alert tries again", Since: since})
		}
		r.Channels = append(r.Channels, row)
	}
	slices.SortFunc(r.Channels, func(a, b ChannelRow) int { return strings.Compare(a.Name, b.Name) })

	for i := len(in.Cycles) - 1; i >= 0 && len(r.Cycles) < 10; i-- {
		c := in.Cycles[i]
		r.Cycles = append(r.Cycles, CycleRow{Started: c.Started, Finished: c.Finished, Items: c.Items, New: c.New, Merged: c.Merged,
			Findings: c.Findings, Reconciled: c.Reconciled, Alerted: c.Alerted, Digests: c.Digests, Failed: c.Failed, Err: c.Err})
	}

	r.Daemon = daemon(in)
	if r.Daemon.Level == Red {
		r.Warnings = append(r.Warnings, r.Daemon.Message)
		r.Problems = append(r.Problems, Problem{Key: "daemon", Level: Red, Title: "the daemon is overdue", Detail: r.Daemon.Message,
			Hint: "start it again with cvewatch daemon, or check the service that runs it", Since: r.Daemon.NextRun})
	}
	switch {
	case len(in.Sources) == 0:
		r.Warnings = append(r.Warnings, "no enabled sources: nothing will be fetched")
		r.Problems = append(r.Problems, Problem{Key: "sources", Level: Yellow, Title: "no enabled sources",
			Detail: "nothing will be fetched", Hint: "enable a feed in config/sources/ or remove its disabled flag"})
	case !succeeded(in) && !slices.ContainsFunc(r.Problems, func(p Problem) bool { return strings.HasPrefix(p.Key, "feed:") }):
		title := "no cycle has run yet"
		if len(in.Cycles) > 0 {
			title = "no cycle has read a feed yet"
		}
		r.Problems = append(r.Problems, Problem{Key: KeyCycle, Level: Yellow, Title: title,
			Hint: "cvewatch update runs one now; a daemon runs them on its own"})
	}
	r.Problems = append(r.Problems, in.Problems...)
	sortProblems(r.Problems)

	r.Level = Green
	for _, p := range r.Problems {
		r.Level = r.Level.Worse(p.Level)
	}
	if r.Problems == nil {
		r.Problems = []Problem{}
	}
	return r
}

// sortProblems puts red before yellow, then the oldest first, then by key.
func sortProblems(ps []Problem) {
	slices.SortStableFunc(ps, func(a, b Problem) int {
		if a.Level != b.Level {
			return b.Level.rank() - a.Level.rank()
		}
		switch {
		case a.Since.IsZero() != b.Since.IsZero():
			if a.Since.IsZero() {
				return 1
			}
			return -1
		case !a.Since.Equal(b.Since):
			return a.Since.Compare(b.Since)
		}
		return strings.Compare(a.Key, b.Key)
	})
}

// failingSince is when a failure streak began: recorded when it started, else
// the last success (the streak began after it), else the last attempt.
func failingSince(recorded, lastSuccess, lastAttempt time.Time) time.Time {
	switch {
	case !recorded.IsZero():
		return recorded
	case !lastSuccess.IsZero():
		return lastSuccess
	}
	return lastAttempt
}

// succeeded is whether a cycle has finished with at least one feed read.
func succeeded(in Input) bool {
	return slices.ContainsFunc(in.Cycles, func(c model.CycleRecord) bool { return c.Err == "" && c.Failed < len(in.Sources) })
}

// Alive is whether a daemon runs: it recorded a heartbeat and is not overdue.
func (d Daemon) Alive() bool { return d.Mode == "daemon" && d.Level == Green }

func daemon(in Input) Daemon {
	d := Daemon{Level: Yellow, Interval: in.Interval}
	if in.Beat != nil {
		d.Mode, d.LastCycle, d.NextRun, d.Interval = in.Beat.Mode, in.Beat.LastCycle, in.Beat.NextRun, in.Beat.Interval
		grace := d.Interval / 2
		if grace < 10*time.Minute {
			grace = 10 * time.Minute
		}
		if in.Now.After(d.NextRun.Add(grace)) {
			d.Level = Red
			d.Message = fmt.Sprintf("the daemon is overdue: it should have run at %s and last ran %s ago; is it still running?",
				d.NextRun.UTC().Format("2006-01-02 15:04"), ago(in.Now.Sub(d.LastCycle)))
		} else {
			d.Level = Green
			d.Message = "running; next cycle " + d.NextRun.UTC().Format("2006-01-02 15:04") + " UTC"
		}
		return d
	}
	if n := len(in.Cycles); n > 0 {
		d.Level = Green
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
