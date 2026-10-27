// Package pipeline runs one monitoring cycle: fetch feeds, judge each item
// against the current config, fold it into the ledger, write reports and
// alert. Rules about relevance live in package relevance, rules about
// identity in package ledger; this package only sequences them.
package pipeline

import (
	"context"
	"log/slog"
	"maps"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/b070nd/cvewatch/app/src/audit"
	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/feeds"
	"github.com/b070nd/cvewatch/app/src/ledger"
	"github.com/b070nd/cvewatch/app/src/matrix"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/notify"
	"github.com/b070nd/cvewatch/app/src/relevance"
	"github.com/b070nd/cvewatch/app/src/report"
)

// maxBatchesPerRun bounds Slack messages per cycle.
const maxBatchesPerRun = 5

type Runner struct {
	Cfg      *config.Bundle
	Ledger   *ledger.Ledger
	Save     func() error // persists the ledger; called before alerting and at the end
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

// cycle carries what one run shares between its steps.
type cycle struct {
	r        *Runner
	judge    *relevance.Judge
	packages map[string][]model.Package
	now      time.Time
	dirty    map[string]bool // vulnerabilities whose report needs rewriting
	gone     []*model.Vulnerability
	res      Result
}

// Run executes one cycle. A failing source never stops the others, and its
// cursor stays put so the next run retries the same window.
func (r *Runner) Run(ctx context.Context) (Result, error) {
	c := &cycle{
		r: r, judge: relevance.New(r.Cfg.Techs), packages: LoadMatrix(r.Cfg, r.Log), now: r.Now(),
		dirty: map[string]bool{}, res: Result{Fresh: map[string]bool{}},
	}
	results := r.fetchAll(ctx, c.now)

	for i, src := range r.activeSources() {
		f := results[i]
		if f.err != nil {
			c.res.Failed = append(c.res.Failed, src.ID+": "+f.err.Error())
			r.Log.Warn("source failed", "source", src.ID, "err", f.err)
			continue
		}
		r.Ledger.SetFeed(src.ID, model.FeedState{Validators: f.val, LastRun: c.now})
		for _, it := range f.items {
			c.res.Items++
			c.process(it)
		}
	}

	if r.Cfg.Retention > 0 {
		c.res.Pruned = r.Ledger.Prune(c.now.Add(-r.Cfg.Retention))
	}
	if err := c.writeReports(); err != nil {
		return c.res, err
	}
	if err := r.auditDetected(c.res.Fresh, c.now); err != nil {
		return c.res, err
	}
	if err := r.Save(); err != nil { // persist before alerting: a crash then repeats an alert, never loses a finding
		return c.res, err
	}
	c.res.Alerted = r.alert(ctx, c.now)
	return c.res, r.Save()
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
			st := r.Ledger.Feed(src.ID) // read-only here; written after the join
			out[i].items, out[i].val, out[i].err = feeds.Fetch(ctx, r.Getter, src, st, now, r.Cfg.Lookback)
		}()
	}
	wg.Wait()
	return out
}

// LoadMatrix reads every project's lockfiles afresh, so the tech matrix
// always follows the repositories.
func LoadMatrix(cfg *config.Bundle, log *slog.Logger) map[string][]model.Package {
	out := map[string][]model.Package{}
	for _, p := range cfg.Projects {
		for _, lf := range p.Lockfiles {
			pkgs, err := matrix.Load(lf)
			if err != nil {
				log.Warn("lockfile skipped", "project", p.Name, "err", err)
				continue
			}
			out[p.Name] = append(out[p.Name], pkgs...)
		}
	}
	return out
}

func (c *cycle) process(it model.Item) {
	if !safeURL(it.URL) {
		c.r.Log.Debug("item skipped: link is not a plain http(s) URL", "source", it.SourceID)
		return
	}
	l := c.r.Ledger
	verdict := c.judge.Judge(it, c.r.Cfg.Projects, c.packages)

	known, folded, linked := l.Identify(it, verdict.Relevant())
	c.dropReports(folded)
	for _, o := range linked {
		if len(l.FindingsOf(o.ID)) > 0 {
			c.dirty[o.ID] = true // it gained a link to this article
		}
	}

	if known != nil {
		hadFindings := len(l.FindingsOf(known.ID)) > 0
		change := l.Absorb(known, it)
		// The same sighting again changes nothing, so a config edit never
		// re-judges an old item. New information does count: a relevant article
		// joining a tracked issue, or ranges for a CVE first seen in the news.
		if change.Any && verdict.Relevant() {
			if len(known.Techs) == 0 {
				known.Techs = verdict.Techs
			}
			if known.Summary == "" {
				known.Summary = it.Summary
			}
			c.addFindings(known.ID, verdict.Matches)
			if hadFindings {
				c.res.Merged++
			} else {
				c.res.New++
			}
		}
		if change.Evidence {
			c.reassess(known)
		}
		if change.Any && (hadFindings || verdict.Relevant()) {
			c.dirty[known.ID] = true
		}
		return
	}

	v := l.Create(it, c.now, verdict.Techs)
	c.res.New++
	if verdict.Relevant() {
		c.addFindings(v.ID, verdict.Matches)
		c.dirty[v.ID] = true
		return
	}
	v.Summary, v.Affected, v.Fixes = "", nil, nil // irrelevant: keep only what dedup needs
}

// reassess re-checks existing findings against affected data that arrived late.
func (c *cycle) reassess(v *model.Vulnerability) {
	c.r.Ledger.UpdateFindings(v.ID, func(f *model.Finding) {
		if len(f.Installed) == 0 {
			return
		}
		applies, reasons := c.judge.Reassess(f.Installed, v.Affected)
		if applies != f.Applies {
			f.Applies, f.Reasons, f.Updated = applies, reasons, c.now
			c.dirty[v.ID] = true
		}
	})
}

func (c *cycle) addFindings(vulnID string, ms []relevance.Match) {
	n := AddFindings(c.r.Ledger, c.r.Cfg.Projects, vulnID, ms, c.now)
	c.res.Findings += n
	if n > 0 {
		c.res.Fresh[vulnID] = true
	}
}

// AddFindings creates one finding per environment of each matched project. It
// never touches existing findings, so statuses survive. It returns how many
// were created.
func AddFindings(l *ledger.Ledger, projects []model.Project, vulnID string, ms []relevance.Match, now time.Time) int {
	created := 0
	for _, m := range ms {
		i := slices.IndexFunc(projects, func(p model.Project) bool { return p.Name == m.Project })
		if i < 0 {
			continue
		}
		labels := make([]string, len(m.Installed))
		for k, in := range m.Installed {
			labels[k] = in.Label()
		}
		for _, env := range projects[i].EffectiveEnvs() {
			f := model.Finding{
				VulnID: vulnID, Project: m.Project, Env: env, Status: model.StatusOpen, Matched: labels,
				Installed: m.Installed, Applies: m.Applies, Reasons: m.Reasons, Updated: now,
			}
			if l.AddFinding(f) {
				created++
			}
		}
	}
	return created
}

// safeURL accepts only plain http(s) links. Feed links end up in markdown and
// Slack markup, so anything that could break out of them is dropped.
func safeURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" &&
		!strings.ContainsAny(raw, " \t\r\n<>|\"`\\")
}

// dropReports removes report files of records that were folded into another.
func (c *cycle) dropReports(gone []*model.Vulnerability) {
	for _, g := range gone {
		delete(c.dirty, g.ID)
		if g.ReportPath != "" {
			os.Remove(g.ReportPath)
		}
	}
}

func (c *cycle) writeReports() error {
	for id := range c.dirty {
		v := c.r.Ledger.Vuln(id)
		if v == nil {
			continue
		}
		path, err := report.Write(c.r.Cfg.AlertsDir, v, c.r.Ledger.FindingsOf(id), c.now)
		if err != nil {
			return err
		}
		v.ReportPath = path
	}
	return nil
}

// auditDetected records when each new finding set was first seen.
func (r *Runner) auditDetected(fresh map[string]bool, now time.Time) error {
	var events []audit.Event
	for _, id := range slices.Sorted(maps.Keys(fresh)) {
		var projects []string
		for _, f := range r.Ledger.FindingsOf(id) {
			if !slices.Contains(projects, f.Project) {
				projects = append(projects, f.Project)
			}
		}
		events = append(events, audit.Event{Time: now, Actor: "cvewatch", Action: "detected", Vuln: id,
			Project: strings.Join(projects, ",")})
	}
	return r.Audit.Append(events...)
}

// alert sends every open finding that has not been delivered yet, including
// ones whose delivery failed in an earlier run. Findings whose version is
// known to be unaffected are recorded but never alerted.
func (r *Runner) alert(ctx context.Context, now time.Time) int {
	if r.Notifier == nil {
		return 0
	}
	var batch []notify.Alert
	for _, f := range r.Ledger.Findings() {
		v := r.Ledger.Vuln(f.VulnID)
		if f.Status != model.StatusOpen || !f.AlertedAt.IsZero() || v == nil ||
			f.Applies == model.AppNotAffected || !v.Severity.AtLeast(r.Cfg.Slack.MinSeverity) {
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
				r.Ledger.MarkAlerted(f.Key(), now)
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
