package pipeline

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/b070nd/cvewatch/app/src/audit"
	"github.com/b070nd/cvewatch/app/src/inventory"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/query"
	"github.com/b070nd/cvewatch/app/src/relevance"
)

// heartbeat is how often a long judgement says it is still going.
var heartbeat = 5 * time.Second

const (
	// An irrelevant record keeps this much of its summary and of its product
	// list, so a later config change can judge it again without a new download.
	briefSummary  = 400
	briefProducts = 20
)

// brief trims what an irrelevant record keeps. Fixes are dropped: a finding
// created later takes them from the next sighting.
func brief(summary string, affected []model.Affected) (string, []model.Affected, []model.Fix) {
	if len(affected) > briefProducts {
		affected = affected[:briefProducts]
	}
	return query.Clip(summary, briefSummary), slices.Clone(affected), nil
}

// ItemOf rebuilds the item a stored record was judged from. The title-only and
// structured-only flags come from the source that first reported it; a record
// that kept no summary is judged by its title.
func ItemOf(v *model.Vulnerability, sources []model.Source) model.Item {
	it := model.Item{
		Title: v.Title, Summary: v.Summary, IDs: v.Keys(), Affected: v.Affected, Severity: v.Severity,
		Published: v.Published, TitleOnly: v.Summary == "",
	}
	if len(v.Refs) > 0 {
		if i := slices.IndexFunc(sources, func(s model.Source) bool { return s.ID == v.Refs[0].Source }); i >= 0 {
			it.TitleOnly = it.TitleOnly || sources[i].MatchTitleOnly
			it.StructuredOnly = sources[i].MatchStructured
		}
	}
	return it
}

// Change is one issue a revalidation creates, closes or reopens findings for.
type Change struct {
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Action   string   `json:"action"` // new | closed | reopened
	Projects []string `json:"projects"`
}

// Revalidation is what re-judging every stored record against the current
// configuration did, or with Applied false would do.
type Revalidation struct {
	Applied     bool     `json:"applied"`
	NewFindings int      `json:"new_findings"`           // findings created for records that match now
	Closed      int      `json:"closed"`                 // open findings closed because the vulnerability predates the project's since date
	Reopened    int      `json:"reopened"`               // those closed findings that reopened because the date moved
	EnvClosed   int      `json:"env_closed,omitempty"`   // open findings closed because their environment is no longer declared
	EnvReopened int      `json:"env_reopened,omitempty"` // those that reopened because the environment is declared again
	Reconciled  int      `json:"reconciled"`             // open findings whose installed version or presence changed
	Unchanged   int      `json:"unchanged"`              // findings nothing happened to
	Projects    []string `json:"projects_changed"`
	Changes     []Change `json:"changes,omitempty"`
	// Backfill is the earliest publication date the change needs the sources
	// to reach back to, and BackfillSources the sources that will do so on
	// their next fetch.
	Backfill        time.Time `json:"backfill,omitempty"`
	BackfillSources []string  `json:"backfill_sources,omitempty"`
}

// Revalidate re-judges every stored record, including the irrelevant ones,
// against the current projects, techs, since dates and horizon. It needs no
// network. It creates findings for records that match now, closes open
// findings whose vulnerability predates the project's since date or whose
// environment is no longer declared, reopens the ones it closed itself when
// the date moves or the environment returns, re-checks installed versions,
// asks the sources to reach back for what the change newly wants, and records
// what the findings are now judged against. Without apply nothing is changed.
// The caller saves the ledger.
func (r *Runner) Revalidate(apply bool) (Revalidation, error) {
	run := r
	if !apply {
		clone, err := r.Ledger.Clone()
		if err != nil {
			return Revalidation{}, err
		}
		copied := *r
		copied.Ledger, copied.Audit = clone, nil
		run = &copied
	}
	c := newCycle(run)
	cur := c.inv.Judging(run.Cfg, c.now)
	started := time.Now()
	r.Log.Info("revalidating", "advisories", len(run.Ledger.State().Vulns), "findings", len(run.Ledger.Findings()), "apply", apply)
	rv := c.revalidate(inventory.Compare(run.Ledger.Judged(), cur, run.Cfg.Horizon, c.now), cur, false)
	rv.Applied = apply
	r.Log.Info("revalidated", "elapsed", time.Since(started).Round(time.Millisecond), "new_findings", rv.NewFindings, "closed", rv.Closed+rv.EnvClosed,
		"reopened", rv.Reopened+rv.EnvReopened, "reconciled", rv.Reconciled, "unchanged", rv.Unchanged)
	if !apply {
		return rv, nil
	}
	if err := c.writeReports(); err != nil {
		return rv, err
	}
	return rv, run.Audit.Append(c.events...)
}

// revalidateIfStale is Revalidate for the start of a cycle: it runs only when
// the recorded judging differs from the configuration, and leaves its reports,
// audit events and counts to the cycle.
func (c *cycle) revalidateIfStale() {
	cur := c.inv.Judging(c.r.Cfg, c.now)
	d := inventory.Compare(c.r.Ledger.Judged(), cur, c.r.Cfg.Horizon, c.now)
	if !d.Stale() {
		return
	}
	rv := c.revalidate(d, cur, true)
	rv.Applied = true
	c.res.Revalidation = &rv
	c.res.Findings += rv.NewFindings
	c.r.Log.Info("revalidated after a configuration change", "projects", strings.Join(rv.Projects, ","),
		"new_findings", rv.NewFindings, "closed", rv.Closed, "reopened", rv.Reopened, "reconciled", rv.Reconciled)
}

// revalidate runs the steps. A quiet run, the automatic one at the start of a
// cycle, leaves no audit event when it changed nothing.
func (c *cycle) revalidate(d inventory.Delta, cur model.Judging, quiet bool) Revalidation {
	l := c.r.Ledger
	rv := Revalidation{Projects: d.Changed, Backfill: d.Backfill}
	total := len(l.Findings())
	c.applyEnvs(&rv, nil)
	c.applySince(&rv)
	c.rejudge(&rv, nil)
	c.markBackfill(d.Backfill, &rv)
	reconciled := c.res.Reconciled
	c.reconcile(nil)
	rv.Reconciled = c.res.Reconciled - reconciled
	rv.Unchanged = max(0, total-rv.Closed-rv.Reopened-rv.EnvClosed-rv.EnvReopened-rv.Reconciled)

	cur.At = c.now
	l.SetJudged(cur)
	if quiet && rv.NewFindings+rv.Closed+rv.Reopened+rv.EnvClosed+rv.EnvReopened+rv.Reconciled == 0 {
		return rv
	}
	c.events = append(c.events, audit.Event{Time: c.now, Actor: c.r.actor(), Action: "revalidate", Project: strings.Join(rv.Projects, ","),
		Note: fmt.Sprintf("%d new findings, %d closed, %d reopened, %d reconciled, %d unchanged",
			rv.NewFindings, rv.Closed+rv.EnvClosed, rv.Reopened+rv.EnvReopened, rv.Reconciled, rv.Unchanged)})
	return rv
}

func (r *Runner) actor() string {
	if r.Actor != "" {
		return r.Actor
	}
	return "cvewatch"
}

// applySince closes open findings whose vulnerability was published before
// their project's since date, marking them Auto, and reopens those it closed
// when the date no longer excludes them. A status a person set is never touched.
func (c *cycle) applySince(rv *Revalidation) {
	l := c.r.Ledger
	changes := map[string]*Change{}
	record := func(f model.Finding, v *model.Vulnerability, action string) {
		key := action + "|" + v.ID
		ch := changes[key]
		if ch == nil {
			ch = &Change{ID: v.ID, Title: query.Clip(v.Title, 120), Action: action}
			changes[key] = ch
		}
		if !slices.Contains(ch.Projects, f.Project) {
			ch.Projects = append(ch.Projects, f.Project)
		}
	}
	for _, f := range l.Findings() {
		tg, ok := c.inv.Target(f.Project, f.Env)
		v := l.Vuln(f.VulnID)
		if !ok || v == nil {
			continue
		}
		before := !tg.Since.IsZero() && !v.Published.IsZero() && v.Published.Before(tg.Since)
		switch {
		case f.Status == model.StatusOpen && before:
			note := fmt.Sprintf("published before this project's since date (%s); closed automatically", tg.Since.UTC().Format(time.DateOnly))
			c.setAuto(f.Key(), model.StatusNotAffected, true, note, f.Note)
			rv.Closed++
			record(f, v, "closed")
		case f.Status == model.StatusNotAffected && f.Auto && !before:
			note := "this project's since date no longer excludes it; reopened automatically"
			c.setAuto(f.Key(), model.StatusOpen, false, note, "")
			rv.Reopened++
			record(f, v, "reopened")
		default:
			continue
		}
		c.dirty[v.ID] = true
	}
	for _, key := range slices.Sorted(maps.Keys(changes)) {
		rv.Changes = append(rv.Changes, *changes[key])
	}
}

// envRemoved is the note of a finding closed because its environment is gone.
const envRemoved = "environment removed from project"

// applyEnvs closes open findings of environments the project no longer
// declares, marking them Auto, and reopens those it closed when the
// environment is declared again. The declared set is the inventory's: the
// project's envs, or the legacy default. History stays; a status a person set
// is never touched. Projects the configuration does not know are left alone.
func (c *cycle) applyEnvs(rv *Revalidation, only map[string]bool) {
	l := c.r.Ledger
	declared := map[string][]model.Env{}
	for _, p := range c.r.Cfg.Projects {
		declared[p.Name] = p.EffectiveEnvs()
	}
	for _, f := range l.Findings() {
		envs, ok := declared[f.Project]
		v := l.Vuln(f.VulnID)
		if !ok || v == nil || !has(only, f.Project) {
			continue
		}
		var action string
		switch {
		case f.Status == model.StatusOpen && !slices.Contains(envs, f.Env):
			c.setAuto(f.Key(), model.StatusIgnored, true, envRemoved, f.Note)
			rv.EnvClosed++
			action = "closed"
		case f.Status == model.StatusIgnored && f.Auto && f.Note == envRemoved && slices.Contains(envs, f.Env):
			c.setAuto(f.Key(), model.StatusOpen, false, "this environment is declared again; reopened automatically", "")
			rv.EnvReopened++
			action = "reopened"
		default:
			continue
		}
		c.dirty[v.ID] = true
		i := slices.IndexFunc(rv.Changes, func(ch Change) bool { return ch.ID == v.ID && ch.Action == action })
		if i < 0 {
			rv.Changes = append(rv.Changes, Change{ID: v.ID, Title: query.Clip(v.Title, 120), Action: action})
			i = len(rv.Changes) - 1
		}
		if !slices.Contains(rv.Changes[i].Projects, f.Project) {
			rv.Changes[i].Projects = append(rv.Changes[i].Projects, f.Project)
		}
	}
}

// setAuto changes a finding's status on cvewatch's own account and records it
// in the audit trail. A note a person wrote stays in the history.
func (c *cycle) setAuto(key string, st model.Status, auto bool, note, prior string) {
	c.r.Ledger.Mutate(key, func(m *model.Finding) {
		m.Status, m.Auto, m.Updated = st, auto, c.now
		m.Note = ""
		if auto {
			m.Note = note
		}
		event := note
		if prior != "" {
			note += " (previous note: " + prior + ")"
		}
		m.History = append(m.History, model.Disposition{Time: c.now, Actor: "cvewatch", Action: "status", Status: st, Note: note})
		c.events = append(c.events, audit.Event{Time: c.now, Actor: "cvewatch", Action: "status", Vuln: m.VulnID,
			Project: m.Project, Env: string(m.Env), Status: string(st), Note: event})
	})
}

// rejudge judges every stored record again, creating findings where the
// current configuration matches and none exists. It never removes any. With
// only (nil: all) it looks at the targets of those projects.
func (c *cycle) rejudge(rv *Revalidation, only map[string]bool) {
	l := c.r.Ledger
	targets := slices.DeleteFunc(slices.Clone(c.inv.Targets()), func(t relevance.Target) bool { return !has(only, t.Project) })
	ids := slices.Sorted(maps.Keys(l.State().Vulns))
	started := time.Now()
	next := started.Add(heartbeat)
	for i, id := range ids {
		if now := time.Now(); !now.Before(next) {
			c.r.Log.Info("still judging stored advisories", "done", i, "of", len(ids), "elapsed", now.Sub(started).Round(time.Second), "new_findings", rv.NewFindings)
			next = now.Add(heartbeat)
		}
		v := l.Vuln(id)
		verdict := c.judge.Judge(ItemOf(v, c.r.Cfg.Sources), targets)
		if len(verdict.Matches) == 0 {
			continue
		}
		made := AddFindings(l, v.ID, verdict.Matches, c.now)
		if len(made) == 0 {
			continue
		}
		c.detected(made, "matched an advisory already stored")
		rv.NewFindings += len(made)
		ch := Change{ID: v.ID, Title: query.Clip(v.Title, 120), Action: "new"}
		for _, m := range verdict.Matches {
			if !slices.Contains(ch.Projects, m.Project) {
				ch.Projects = append(ch.Projects, m.Project)
			}
		}
		for _, t := range verdict.Techs {
			if !slices.Contains(v.Techs, t) {
				v.Techs = append(v.Techs, t)
			}
		}
		rv.Changes = append(rv.Changes, ch)
		c.dirty[v.ID] = true
	}
}

// catchUp brings the projects of a restricted run up to date with what the
// runs that skipped them stored: advisories that match them and affected data
// that arrived late. A run of every project has nothing to catch up on.
func (c *cycle) catchUp() {
	if c.r.Only == nil {
		return
	}
	var rv Revalidation
	c.rejudge(&rv, c.r.Only)
	c.res.Findings += rv.NewFindings
	for _, ch := range rv.Changes {
		c.res.Fresh[ch.ID] = true
	}
	for _, v := range c.r.Ledger.Relevant() {
		c.reassess(v)
	}
}

// markBackfill asks every source that has not covered back to the date to
// reach back to it on its next fetch.
func (c *cycle) markBackfill(from time.Time, rv *Revalidation) {
	if from.IsZero() {
		return
	}
	for _, src := range c.r.activeSources() {
		st := c.r.Ledger.Feed(src.ID)
		if !st.Covered.IsZero() && !from.Before(st.Covered) {
			continue
		}
		if st.Backfill.IsZero() || from.Before(st.Backfill) {
			st.Backfill = from
			c.r.Ledger.SetFeed(src.ID, st)
		}
		rv.BackfillSources = append(rv.BackfillSources, src.ID)
	}
}
