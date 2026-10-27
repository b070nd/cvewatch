// Package pipeline runs one monitoring cycle: fetch feeds, skip what was
// already evaluated, match the rest against the current config, record
// findings, write reports and alert.
package pipeline

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"cvewatch/src/audit"
	"cvewatch/src/config"
	"cvewatch/src/feeds"
	"cvewatch/src/match"
	"cvewatch/src/matrix"
	"cvewatch/src/model"
	"cvewatch/src/notify"
	"cvewatch/src/report"
	"cvewatch/src/store"
)

// maxBatchesPerRun bounds Slack messages per cycle.
const maxBatchesPerRun = 5

type Runner struct {
	Cfg      *config.Bundle
	Store    *store.Store
	Getter   feeds.Getter
	Notifier notify.Notifier // nil disables alerting
	Audit    *audit.Log      // nil disables the audit trail
	Log      *slog.Logger
	Now      func() time.Time
}

type Result struct {
	Items    int             // entries fetched
	New      int             // vulnerabilities seen for the first time
	Merged   int             // items folded into an already tracked issue
	Pruned   int             // old irrelevant records forgotten
	Findings int             // findings created
	Fresh    map[string]bool // vulnerabilities that gained findings this cycle
	Alerted  int             // findings delivered to the notifier
	Failed   []string        // sources that errored, with the reason
}

type fetched struct {
	items []model.Item
	val   model.Validators
	err   error
}

// Run executes one cycle. A failing source never stops the others, and its
// cursor stays put so the next run retries the same window.
func (r *Runner) Run(ctx context.Context) (Result, error) {
	started := r.Now()
	res := Result{Fresh: map[string]bool{}}

	packages := r.loadMatrix()
	matcher := match.New(r.Cfg.Techs)
	results := r.fetchAll(ctx, started)

	dirty := map[string]bool{} // vulnerabilities whose report needs rewriting
	for i, src := range r.activeSources() {
		f := results[i]
		if f.err != nil {
			res.Failed = append(res.Failed, src.ID+": "+f.err.Error())
			r.Log.Warn("source failed", "source", src.ID, "err", f.err)
			continue
		}
		r.Store.SetFeed(src.ID, model.FeedState{Validators: f.val, LastRun: started})
		for _, it := range f.items {
			res.Items++
			r.process(it, matcher, packages, started, dirty, &res)
		}
	}

	if r.Cfg.Retention > 0 {
		res.Pruned = r.Store.Prune(started.Add(-r.Cfg.Retention))
	}
	if err := r.writeReports(dirty); err != nil {
		return res, err
	}
	if err := r.auditDetected(res.Fresh, started); err != nil {
		return res, err
	}
	if err := r.Store.Save(); err != nil { // persist before alerting: a crash then repeats an alert, never loses a finding
		return res, err
	}
	res.Alerted = r.alert(ctx, started)
	return res, r.Store.Save()
}

// auditDetected records when each new finding set was first seen.
func (r *Runner) auditDetected(fresh map[string]bool, now time.Time) error {
	var events []audit.Event
	for _, id := range slices.Sorted(maps.Keys(fresh)) {
		var projects []string
		for _, f := range r.Store.FindingsOf(id) {
			if !slices.Contains(projects, f.Project) {
				projects = append(projects, f.Project)
			}
		}
		events = append(events, audit.Event{Time: now, Actor: "cvewatch", Action: "detected", Vuln: id,
			Project: strings.Join(projects, ",")})
	}
	return r.Audit.Append(events...)
}

func (r *Runner) activeSources() []model.Source {
	return slices.DeleteFunc(slices.Clone(r.Cfg.Sources), func(s model.Source) bool { return s.Disabled })
}

// fetchAll polls sources concurrently; the HTTP client rate-limits per host.
func (r *Runner) fetchAll(ctx context.Context, now time.Time) []fetched {
	srcs := r.activeSources()
	out := make([]fetched, len(srcs))
	var wg sync.WaitGroup
	for i, src := range srcs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			st := r.Store.Feed(src.ID) // read-only here; written after the join
			out[i].items, out[i].val, out[i].err = feeds.Fetch(ctx, r.Getter, src, st, now, r.Cfg.Lookback)
		}()
	}
	wg.Wait()
	return out
}

// loadMatrix reads every project's lockfiles afresh, so the tech matrix
// always follows the repositories.
func (r *Runner) loadMatrix() map[string][]model.Package {
	out := map[string][]model.Package{}
	for _, p := range r.Cfg.Projects {
		for _, lf := range p.Lockfiles {
			pkgs, err := matrix.Load(lf)
			if err != nil {
				r.Log.Warn("lockfile skipped", "project", p.Name, "err", err)
				continue
			}
			out[p.Name] = append(out[p.Name], pkgs...)
		}
	}
	return out
}

func (r *Runner) process(it model.Item, m *match.Matcher, pkgs map[string][]model.Package,
	now time.Time, dirty map[string]bool, res *Result) {

	if !safeURL(it.URL) {
		r.Log.Debug("item skipped: link is not a plain http(s) URL", "source", it.SourceID)
		return
	}
	if v := r.Store.Lookup(it.Keys()); v != nil {
		if merge(r.Store, v, it) && len(r.Store.FindingsOf(v.ID)) > 0 {
			dirty[v.ID] = true
		}
		return // already evaluated: config changes never re-judge old items
	}

	v := &model.Vulnerability{
		ID: it.Keys()[0], Aliases: slices.Clone(it.Keys()[1:]), Title: it.Title, Summary: it.Summary,
		Severity: it.Severity, CVSS: it.CVSS, Published: it.Published, FirstSeen: now,
		Refs: []model.Ref{{Source: it.SourceID, URL: it.URL}}, Techs: m.Techs(it),
	}
	if v.Severity == "" {
		v.Severity = model.SevUnknown
	}
	if v.Published.IsZero() {
		v.Published = now
	}
	res.New++

	hits := map[string][]string{} // project name -> what matched
	for _, p := range r.Cfg.Projects {
		if matched := match.Project(p, pkgs[p.Name], v.Techs, it); len(matched) > 0 {
			hits[p.Name] = matched
		}
	}

	// A relevant item about an issue we already track joins that record
	// instead of creating a second one.
	if len(hits) > 0 {
		if base := r.similar(v); base != nil {
			merge(r.Store, base, it)
			if base.Summary == "" {
				base.Summary = it.Summary
			}
			r.addFindings(base.ID, hits, now, dirty, res)
			dirty[base.ID] = true
			res.Merged++
			return
		}
	}

	r.addFindings(v.ID, hits, now, dirty, res)
	if !dirty[v.ID] {
		v.Summary = "" // irrelevant: keep only what dedup needs
	}
	r.Store.AddVuln(v)
}

// safeURL accepts only plain http(s) links. Feed links end up in markdown and
// Slack markup, so anything that could break out of them is dropped.
func safeURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" &&
		!strings.ContainsAny(raw, " \t\r\n<>|\"`\\")
}

// mergeWindow is how far apart two reports may be dated and still count as one issue.
const mergeWindow = 14 * 24 * time.Hour

// similar finds a tracked, relevant vulnerability about the same issue.
func (r *Runner) similar(v *model.Vulnerability) *model.Vulnerability {
	for _, base := range r.Store.Relevant() {
		gap := base.Published.Sub(v.Published)
		if gap < mergeWindow && gap > -mergeWindow && match.Similar(base.Title, v.Title) {
			return base
		}
	}
	return nil
}

func (r *Runner) addFindings(vulnID string, hits map[string][]string, now time.Time, dirty map[string]bool, res *Result) {
	for _, p := range r.Cfg.Projects {
		matched, ok := hits[p.Name]
		if !ok {
			continue
		}
		for _, env := range p.EffectiveEnvs() {
			f := model.Finding{VulnID: vulnID, Project: p.Name, Env: env, Status: model.StatusOpen, Matched: matched, Updated: now}
			if r.Store.AddFinding(f) {
				res.Findings++
				res.Fresh[vulnID] = true
				dirty[vulnID] = true
			}
		}
	}
}

// merge folds a repeat sighting into the known record. It reports whether anything changed.
func merge(s *store.Store, v *model.Vulnerability, it model.Item) bool {
	changed := false
	if !slices.ContainsFunc(v.Refs, func(r model.Ref) bool { return r.URL == it.URL }) {
		v.Refs = append(v.Refs, model.Ref{Source: it.SourceID, URL: it.URL})
		changed = true
	}
	before := len(v.Aliases)
	s.AddAliases(v, it.Keys())
	if len(v.Aliases) != before {
		changed = true
	}
	if it.Severity.Rank() > v.Severity.Rank() {
		v.Severity, v.CVSS = it.Severity, it.CVSS
		changed = true
	}
	return changed
}

func (r *Runner) writeReports(dirty map[string]bool) error {
	for id := range dirty {
		v := r.Store.Vuln(id)
		path, err := report.Write(r.Cfg.AlertsDir, v, r.Store.FindingsOf(id))
		if err != nil {
			return err
		}
		v.ReportPath = path
	}
	return nil
}

// alert sends every open finding that has not been delivered yet, including
// ones whose delivery failed in an earlier run.
func (r *Runner) alert(ctx context.Context, now time.Time) int {
	if r.Notifier == nil {
		return 0
	}
	floor := r.Cfg.Slack.MinSeverity.Rank()
	var batch []notify.Alert
	for _, f := range r.Store.Findings() {
		v := r.Store.Vuln(f.VulnID)
		if f.Status != model.StatusOpen || !f.AlertedAt.IsZero() || v == nil || v.Severity.Rank() < floor {
			continue
		}
		if n := len(batch); n > 0 && batch[n-1].Vuln.ID == v.ID {
			batch[n-1].Findings = append(batch[n-1].Findings, f)
		} else {
			batch = append(batch, notify.Alert{Vuln: v, Findings: []model.Finding{f}})
		}
	}

	// Most severe first, and a cap per run so enabling Slack on a busy
	// backlog does not flood the channel; the rest goes out next cycle.
	slices.SortStableFunc(batch, func(a, b notify.Alert) int { return b.Vuln.Severity.Rank() - a.Vuln.Severity.Rank() })
	if limit := maxBatchesPerRun * notify.BatchSize; len(batch) > limit {
		r.Log.Info("alert backlog throttled", "sending", limit, "deferred", len(batch)-limit)
		batch = batch[:limit]
	}

	sent := 0
	for chunk := range slices.Chunk(batch, notify.BatchSize) {
		if err := r.Notifier.Send(ctx, chunk); err != nil {
			r.Log.Error("alert delivery failed, will retry next run", "err", err)
			break
		}
		var events []audit.Event
		for _, a := range chunk {
			for _, f := range a.Findings {
				r.Store.MarkAlerted(f.Key(), now)
				sent++
			}
			events = append(events, audit.Event{Time: now, Actor: "cvewatch", Action: "alerted", Vuln: a.Vuln.ID, Note: "slack"})
		}
		if err := r.Audit.Append(events...); err != nil {
			r.Log.Error("audit write failed", "err", err)
		}
	}
	return sent
}

// Change describes a status update requested by a person or an agent.
type Change struct {
	ID, Project string
	Env         model.Env // empty means every environment of the project
	Status      model.Status
	Note        string
}

// Resolve applies a status change, records it in the audit log, and refreshes
// the vulnerability's report.
func Resolve(s *store.Store, alertsDir string, a *audit.Log, actor string, c Change, now time.Time) (int, error) {
	v := s.Lookup([]string{strings.ToUpper(c.ID)})
	if v == nil {
		return 0, fmt.Errorf("unknown vulnerability %s", c.ID)
	}
	n, err := s.SetStatus(v.ID, c.Project, c.Env, c.Status, c.Note, now)
	if err != nil {
		return 0, err
	}
	err = a.Append(audit.Event{Time: now, Actor: actor, Action: "status", Vuln: v.ID, Project: c.Project,
		Env: string(c.Env), Status: string(c.Status), Note: c.Note})
	if err != nil {
		return 0, fmt.Errorf("audit log: %w", err) // never change status without a record
	}
	path, err := report.Write(alertsDir, v, s.FindingsOf(v.ID))
	if err != nil {
		return n, err
	}
	v.ReportPath = path
	return n, s.Save()
}
