package ops

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/b070nd/cvewatch/app/src/audit"
	"github.com/b070nd/cvewatch/app/src/inventory"
	"github.com/b070nd/cvewatch/app/src/pipeline"
	"github.com/b070nd/cvewatch/app/src/query"
	"github.com/b070nd/cvewatch/app/src/store"
)

// Revalidate re-judges every stored record against the current configuration,
// offline; see pipeline.Revalidation. Without apply nothing changes and the
// result says what would, which any session may ask for. Applying needs write
// access to all projects.
func (s *Session) Revalidate(apply bool) (pipeline.Revalidation, error) {
	f, err := s.scope(query.Filter{})
	if err != nil {
		return pipeline.Revalidation{}, err
	}
	if apply {
		if err := s.mayWrite(""); err != nil {
			return pipeline.Revalidation{}, err
		}
	}
	rv, err := s.revalidateOnce(apply)
	if apply && errors.Is(err, store.ErrConflict) { // another process saved first (SQLite): reload and redo once
		if rerr := s.reload(); rerr != nil {
			return pipeline.Revalidation{}, rerr
		}
		rv, err = s.revalidateOnce(apply)
	}
	if err != nil {
		return rv, err
	}
	if len(f.Projects) > 0 { // keep other projects' issues out of what this actor sees
		rv.Projects = slices.DeleteFunc(rv.Projects, func(p string) bool { return !slices.Contains(f.Projects, p) })
		var visible []pipeline.Change
		for _, c := range rv.Changes {
			c.Projects = slices.DeleteFunc(c.Projects, func(p string) bool { return !slices.Contains(f.Projects, p) })
			if len(c.Projects) > 0 {
				visible = append(visible, c)
			}
		}
		rv.Changes = visible
	}
	return rv, nil
}

func (s *Session) revalidateOnce(apply bool) (pipeline.Revalidation, error) {
	r := &pipeline.Runner{Cfg: s.Cfg, Ledger: s.Ledger, Audit: s.Audit, Log: s.Log, Now: s.Now, Actor: s.Actor}
	rv, err := r.Revalidate(apply)
	if err != nil || !apply {
		return rv, err
	}
	if err := s.Commit(); err != nil {
		s.Audit.Append(audit.Event{Time: s.Now(), Actor: s.Actor, Action: "revalidate-failed", Note: "not saved: " + err.Error()})
		return rv, err
	}
	return rv, nil
}

// Staleness says whether the findings were judged against something other than
// the configuration on disk, and which sources still owe a back-fill. It reads
// only, so a read-only session can ask.
type Staleness struct {
	Stale           bool      `json:"stale"`
	Never           bool      `json:"never"`                      // no judgement is recorded yet
	Projects        []string  `json:"projects,omitempty"`         // projects whose inputs differ
	Horizon         bool      `json:"horizon,omitempty"`          // the alert horizon differs
	JudgedAt        time.Time `json:"judged_at,omitempty"`        // when the findings were last judged
	Backfill        time.Time `json:"backfill,omitempty"`         // how far back the change wants to reach
	BackfillPending []string  `json:"backfill_pending,omitempty"` // sources that owe a fetch reaching back
}

func (s *Session) Stale() (Staleness, error) {
	f, err := s.scope(query.Filter{})
	if err != nil {
		return Staleness{}, err
	}
	now := s.Now()
	cur := inventory.Load(s.Cfg).Within(s.Cfg.Horizon, now).Judging(s.Cfg, now)
	d := inventory.Compare(s.Ledger.Judged(), cur, s.Cfg.Horizon, now)
	out := Staleness{Stale: d.Stale(), Never: d.Never, Horizon: d.Horizon, Backfill: d.Backfill, Projects: d.Changed}
	if j := s.Ledger.Judged(); j != nil {
		out.JudgedAt = j.At
	}
	if len(f.Projects) > 0 {
		out.Projects = slices.DeleteFunc(out.Projects, func(p string) bool { return !slices.Contains(f.Projects, p) })
	}
	for _, src := range s.Cfg.Sources {
		if !src.Disabled && !s.Ledger.Feed(src.ID).Backfill.IsZero() {
			out.BackfillPending = append(out.BackfillPending, src.ID)
		}
	}
	return out, nil
}

// Backfill fetches only what a configuration change asked the sources to reach
// back for (see Revalidate), re-judging first if the configuration changed. It
// is the quick run after an edit; a full Refresh does the same and more.
func (s *Session) Backfill(ctx context.Context, progress func(RefreshProgress)) (pipeline.Result, error) {
	if err := s.mayWrite(""); err != nil {
		return pipeline.Result{}, err
	}
	runner, err := pipeline.NewRunner(s.Cfg, s.Ledger, s.Commit, s.Log)
	if err != nil {
		return pipeline.Result{}, err
	}
	runner.Progress, runner.BackfillOnly, runner.Actor = progress, true, s.Actor
	return runner.Run(ctx)
}

// Rescan is Revalidate seen as a list of issues that get findings. It is kept
// for callers of the old name: it also applies the since date to existing findings.
type Rescan struct {
	Candidates []Candidate `json:"candidates"`
	Applied    bool        `json:"applied"`
}

type Candidate struct {
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Projects []string `json:"projects"`
}

func (s *Session) Rescan(apply bool) (Rescan, error) {
	rv, err := s.Revalidate(apply)
	out := Rescan{Applied: apply}
	for _, c := range rv.Changes {
		if c.Action == "new" {
			out.Candidates = append(out.Candidates, Candidate{ID: c.ID, Title: c.Title, Projects: c.Projects})
		}
	}
	return out, err
}
