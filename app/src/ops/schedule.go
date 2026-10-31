package ops

import (
	"context"
	"slices"
	"time"

	"github.com/b070nd/cvewatch/app/src/pipeline"
	"github.com/b070nd/cvewatch/app/src/status"
)

// ProjectSchedule is when one project is refreshed. Next is when the next
// scheduled run is due: a period after Last, or now when the project was never
// refreshed. It is zero when scheduled runs skip the project.
type ProjectSchedule struct {
	Project string
	Auto    bool // the project's own switch (update.auto in its file)
	Every   time.Duration
	Last    time.Time
	Next    time.Time
}

// Schedule is the refresh plan of every project. On is the main switch,
// update.auto in config.yaml: off, nothing is scheduled.
type Schedule struct {
	On       bool
	Projects []ProjectSchedule
}

// Schedule works out when each project is due, as of now.
func (s *Session) Schedule() Schedule { return s.scheduleAt(s.Now()) }

func (s *Session) scheduleAt(now time.Time) Schedule {
	sc := Schedule{On: s.Cfg.Update.Auto}
	for _, p := range s.Cfg.Projects {
		ps := ProjectSchedule{Project: p.Name, Auto: p.AutoUpdate(), Every: p.Every(s.Cfg.Interval), Last: s.Ledger.LastUpdate(p.Name)}
		if sc.On && ps.Auto {
			ps.Next = now
			if !ps.Last.IsZero() {
				ps.Next = ps.Last.Add(ps.Every)
			}
		}
		sc.Projects = append(sc.Projects, ps)
	}
	return sc
}

// Due lists the projects whose scheduled run is due at now, in project order.
func (sc Schedule) Due(now time.Time) []string {
	var out []string
	for _, p := range sc.Projects {
		if !p.Next.IsZero() && !p.Next.After(now) {
			out = append(out, p.Project)
		}
	}
	return out
}

// Wake is how long to wait from now until a project is due, never longer than
// limit (the interval, so that configuration changes are looked at) and zero
// when one is due already.
func (sc Schedule) Wake(now time.Time, limit time.Duration) time.Duration {
	wait := limit
	for _, p := range sc.Projects {
		if !p.Next.IsZero() {
			wait = min(wait, p.Next.Sub(now))
		}
	}
	return max(wait, 0)
}

// RefreshScheduled is the refresh of a daemon cycle, and of the TUI when no
// daemon runs: the feeds are fetched once, but only the projects that are due
// are judged, reconciled and alerted. Nothing is fetched when none is due. A
// manual Refresh covers every project.
func (s *Session) RefreshScheduled(ctx context.Context, progress func(RefreshProgress)) (pipeline.Result, error) {
	if err := s.mayWrite(""); err != nil {
		return pipeline.Result{}, err
	}
	due := s.Schedule().Due(s.Now())
	if len(due) == 0 {
		return pipeline.Result{}, nil
	}
	runner, err := pipeline.NewRunner(s.Cfg, s.Ledger, s.Commit, s.Log)
	if err != nil {
		return pipeline.Result{}, err
	}
	runner.Progress = progress
	if len(due) < len(s.Cfg.Projects) {
		runner.Only = map[string]bool{}
		for _, name := range due {
			runner.Only[name] = true
		}
	}
	return runner.Run(ctx)
}

// statusProjects is the schedule as the health report shows it, for the
// projects the actor may see.
func (s *Session) statusProjects(now time.Time, visible []string) []status.ProjectRow {
	var out []status.ProjectRow
	for _, p := range s.scheduleAt(now).Projects {
		if len(visible) == 0 || slices.Contains(visible, p.Project) {
			out = append(out, status.ProjectRow{Name: p.Project, Auto: p.Auto, Every: p.Every, LastUpdate: p.Last, Next: p.Next})
		}
	}
	return out
}
