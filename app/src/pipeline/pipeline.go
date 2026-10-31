// Package pipeline runs one monitoring cycle: fetch feeds, judge each item
// against what every project environment runs, fold it into the ledger,
// re-check findings whose inventory changed, write reports, alert and send
// digests. Rules about relevance live in package relevance, identity in
// package ledger, inventory in package inventory; this package only sequences
// them.
package pipeline

import (
	"context"
	"errors"
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
	"github.com/b070nd/cvewatch/app/src/cvss"
	"github.com/b070nd/cvewatch/app/src/epss"
	"github.com/b070nd/cvewatch/app/src/feeds"
	"github.com/b070nd/cvewatch/app/src/inventory"
	"github.com/b070nd/cvewatch/app/src/ledger"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/notify"
	"github.com/b070nd/cvewatch/app/src/query"
	"github.com/b070nd/cvewatch/app/src/relevance"
	"github.com/b070nd/cvewatch/app/src/report"
)

// maxBatchesPerRun bounds messages per channel and cycle.
const maxBatchesPerRun = 5

// Delivery is a channel with the lowest severity it should hear about.
type Delivery struct {
	Channel notify.Channel
	Min     model.Severity
}

type Runner struct {
	Cfg      *config.Bundle
	Ledger   *ledger.Ledger
	Save     func() error // persists the ledger; called before alerting and at the end
	Getter   feeds.Getter
	Channels []Delivery // empty disables alerting and digests
	Audit    *audit.Log // nil disables the audit trail
	Log      *slog.Logger
	Now      func() time.Time
	Progress func(Progress) // optional; see Progress
	Actor    string         // who acts in the audit trail; default "cvewatch"
	// BackfillOnly polls just the sources that still owe a back-fill and skips
	// enrichment, pruning and digests: the quick run after a config change.
	BackfillOnly bool
}

// Phase is a step of a cycle, in the order they run.
type Phase string

const (
	PhaseFetch   Phase = "fetch"   // polling the sources
	PhaseProcess Phase = "process" // judging items, then re-checking findings
	PhaseEnrich  Phase = "enrich"  // outside lookups, when switched on
	PhaseSave    Phase = "save"    // reports, audit trail and the ledger
	PhaseAlert   Phase = "alert"   // alerts and digests
)

// Progress is reported from a running cycle through Runner.Progress: once at
// the start of every phase, and in the fetch phase once more for each source
// that finishes. It is never sent per item. Calls are serialized, but the
// fetch ones come from the goroutine of a source, so the callback must not
// block for long.
type Progress struct {
	Phase  Phase
	Done   int    // fetch: sources finished so far
	Total  int    // fetch: sources polled
	Source string // fetch: the source that just finished; empty at the start of the phase
	Failed bool   // fetch: that source errored
	// Chunk and Chunks report a long window being fetched piece by piece (or
	// pages being followed): Source is then the one working, Chunks is 0 when
	// the number of pieces is not known, and Done does not move.
	Chunk, Chunks int
}

// Result summarizes a cycle. The JSON names are part of the MCP contract.
type Result struct {
	Items        int             `json:"items"`                  // entries fetched
	New          int             `json:"new"`                    // vulnerabilities seen for the first time
	Merged       int             `json:"merged"`                 // items folded into an already tracked issue
	Pruned       int             `json:"pruned"`                 // old irrelevant records forgotten
	Findings     int             `json:"findings"`               // findings created
	Reconciled   int             `json:"reconciled"`             // findings re-checked because the inventory changed
	Enriched     int             `json:"enriched"`               // EPSS scores updated
	Rated        int             `json:"rated"`                  // unrated issues that got a CVSS score from NVD
	Fresh        map[string]bool `json:"-"`                      // vulnerabilities that gained findings this cycle
	Alerted      int             `json:"alerted"`                // findings delivered, summed over channels
	Digests      int             `json:"digests"`                // digests sent
	Failed       []string        `json:"failed_sources"`         // sources that errored, with the reason
	Backfilled   []string        `json:"backfilled,omitempty"`   // sources that reached back further than usual
	Notes        []string        `json:"notes,omitempty"`        // informational lines, such as a source that cannot go back
	Revalidation *Revalidation   `json:"revalidation,omitempty"` // set when the cycle re-judged everything first
}

type fetched struct {
	items []model.Item
	val   model.Validators
	err   error
	from  time.Time // start of the window asked for
	back  bool
	note  string
}

// cycle carries what one run shares between its steps.
type cycle struct {
	r      *Runner
	judge  *relevance.Judge
	inv    *inventory.Inventory
	now    time.Time
	dirty  map[string]bool // vulnerabilities whose report needs rewriting
	events []audit.Event
	res    Result
}

func newCycle(r *Runner) *cycle {
	now := r.Now()
	return &cycle{
		r: r, judge: relevance.New(r.Cfg.Techs), inv: inventory.Load(r.Cfg).Within(r.Cfg.Horizon, now), now: now,
		dirty: map[string]bool{}, res: Result{Fresh: map[string]bool{}},
	}
}

// Run executes one cycle. A failing source never stops the others, and its
// cursor stays put so the next run retries the same window.
func (r *Runner) Run(ctx context.Context) (Result, error) {
	c := newCycle(r)
	for _, p := range c.inv.Problems() {
		r.Log.Warn("inventory problem", "problem", p.String())
	}
	c.revalidateIfStale()
	srcs := r.polled()
	var recentOnly []string // back-fill asked of sources that cannot serve history
	results := r.fetchAll(ctx, srcs, c.now)
	r.report(Progress{Phase: PhaseProcess})

	for i, src := range srcs {
		f := results[i]
		if f.err != nil {
			c.res.Failed = append(c.res.Failed, src.ID+": "+f.err.Error())
			r.Log.Warn("source failed", "source", src.ID, "err", f.err)
			r.Ledger.SourceOutcome(src.ID, src.Type, c.now, 0, errors.New(query.Clip(f.err.Error(), 200)))
			continue
		}
		prior := r.Ledger.Feed(src.ID)
		covered := f.from
		if !prior.Covered.IsZero() && prior.Covered.Before(covered) {
			covered = prior.Covered
		}
		r.Ledger.SetFeed(src.ID, model.FeedState{Validators: f.val, LastRun: c.now, Covered: covered})
		r.Ledger.SourceOutcome(src.ID, src.Type, c.now, len(f.items), nil)
		if f.back {
			c.res.Backfilled = append(c.res.Backfilled, src.ID)
		}
		if f.note != "" {
			recentOnly = append(recentOnly, src.ID)
		}
		for _, it := range f.items {
			c.res.Items++
			c.process(it)
		}
	}

	if len(recentOnly) > 0 {
		note := "cannot go back for " + strings.Join(recentOnly, ", ") + ": they only serve recent items"
		c.res.Notes = append(c.res.Notes, note)
		r.Log.Info(note)
	}
	c.reconcile()
	r.report(Progress{Phase: PhaseEnrich})
	if !r.BackfillOnly {
		c.enrich(ctx)
	}
	if r.Cfg.Retention > 0 && !r.BackfillOnly {
		c.res.Pruned = r.Ledger.Prune(c.now.Add(-r.Cfg.Retention))
	}
	r.report(Progress{Phase: PhaseSave})
	if err := c.writeReports(); err != nil {
		return c.res, err
	}
	c.auditDetected()
	if err := r.Audit.Append(c.events...); err != nil {
		return c.res, err
	}
	if err := r.Save(); err != nil { // persist before alerting: a crash then repeats an alert, never loses a finding
		return c.res, err
	}
	r.report(Progress{Phase: PhaseAlert})
	c.res.Alerted = r.alert(ctx, c.now)
	if !r.BackfillOnly {
		c.res.Digests = r.digests(ctx, c.now)
	}
	r.Ledger.RecordCycle(model.CycleRecord{
		Started: c.now, Finished: r.Now(), Items: c.res.Items, New: c.res.New, Merged: c.res.Merged,
		Findings: c.res.Findings, Reconciled: c.res.Reconciled, Alerted: c.res.Alerted, Digests: c.res.Digests,
		Failed: len(c.res.Failed),
	})
	return c.res, r.Save()
}

func (r *Runner) report(p Progress) {
	if r.Progress != nil {
		r.Progress(p)
	}
}

func (r *Runner) activeSources() []model.Source {
	return slices.DeleteFunc(slices.Clone(r.Cfg.Sources), func(s model.Source) bool { return s.Disabled })
}

// polled lists the sources this run reads: all active ones, or with
// BackfillOnly just those that owe a back-fill.
func (r *Runner) polled() []model.Source {
	return slices.DeleteFunc(r.activeSources(), func(s model.Source) bool {
		return r.BackfillOnly && r.Ledger.Feed(s.ID).Backfill.IsZero()
	})
}

// fetchAll polls sources concurrently; the HTTP client rate-limits per host.
func (r *Runner) fetchAll(ctx context.Context, srcs []model.Source, now time.Time) []fetched {
	out := make([]fetched, len(srcs))
	r.report(Progress{Phase: PhaseFetch, Total: len(srcs)})
	var wg sync.WaitGroup
	var mu sync.Mutex
	done := 0
	for i, src := range srcs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			st := r.Ledger.Feed(src.ID) // read-only here; written after the join
			chunk := func(n, total int) {
				mu.Lock()
				defer mu.Unlock()
				r.report(Progress{Phase: PhaseFetch, Done: done, Total: len(srcs), Source: src.ID, Chunk: n, Chunks: total})
			}
			o, err := feeds.FetchRange(ctx, r.Getter, src, st, now, r.Cfg.Lookback, chunk)
			out[i] = fetched{items: o.Items, val: o.Validators, err: err, from: o.From, back: o.Backfilled, note: o.Note}
			mu.Lock()
			defer mu.Unlock()
			done++
			r.report(Progress{Phase: PhaseFetch, Done: done, Total: len(srcs), Source: src.ID, Failed: out[i].err != nil})
		}()
	}
	wg.Wait()
	return out
}

func (c *cycle) process(it model.Item) {
	if !safeURL(it.URL) {
		c.r.Log.Debug("item skipped: link is not a plain http(s) URL", "source", it.SourceID)
		return
	}
	l := c.r.Ledger
	judged := it
	// A later article about a known CVE keeps the date the CVE was first published.
	if prior := l.Lookup(it.Keys()); prior != nil && !prior.Published.IsZero() && (judged.Published.IsZero() || prior.Published.Before(judged.Published)) {
		judged.Published = prior.Published
	}
	verdict := c.judge.Judge(judged, c.inv.Targets())

	known, folded, linked := l.Identify(it, verdict.Relevant())
	for _, g := range folded {
		delete(c.dirty, g.ID)
		if g.ReportPath != "" {
			os.Remove(g.ReportPath)
		}
		c.events = append(c.events, audit.Event{Time: c.now, Actor: "cvewatch", Action: "unified", Vuln: known.ID, Note: "absorbed " + g.ID})
	}
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
			if it.Summary != "" && (known.Summary == "" || !hadFindings) { // an irrelevant record kept only a short summary
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
	v.Summary, v.Affected, v.Fixes = brief(v.Summary, v.Affected) // irrelevant: keep what a later revalidation needs
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

// reconcile re-checks open findings whose inventory changed: an upgraded
// lockfile, a new declared version, a package that is gone. It only changes
// what the finding records about the installed version and the verdict that
// follows from it; status, owner and notes are left alone.
func (c *cycle) reconcile() {
	l := c.r.Ledger
	for _, f := range l.Findings() {
		if f.Status != model.StatusOpen || len(f.Installed) == 0 {
			continue
		}
		tg, ok := c.inv.Target(f.Project, f.Env)
		v := l.Vuln(f.VulnID)
		if !ok || v == nil {
			continue
		}
		var now []model.Installed
		var changes, gone []string
		for _, old := range f.Installed {
			cur, found := tg.Find(old)
			switch {
			case !found:
				gone = append(gone, old.Label())
			case cur.Version != old.Version:
				changes = append(changes, old.Label()+" → "+cur.Label())
				now = append(now, cur)
			default:
				now = append(now, cur)
			}
		}
		if len(changes) == 0 && len(gone) == 0 {
			continue
		}

		applies, reasons := model.AppNotAffected, []string{"no longer installed: " + strings.Join(gone, ", ")}
		if len(now) > 0 {
			applies, reasons = c.judge.Reassess(now, v.Affected)
		}
		note := strings.Join(append(changes, prefixed("removed ", gone)...), "; ") + "; now " + string(applies)
		labels := make([]string, len(now))
		for i, in := range now {
			labels[i] = in.Label()
		}
		l.Mutate(f.Key(), func(m *model.Finding) {
			m.Installed, m.Matched, m.Applies, m.Reasons, m.Updated = now, labels, applies, reasons, c.now
			m.History = append(m.History, model.Disposition{Time: c.now, Actor: "cvewatch", Action: "inventory", Note: note})
		})
		c.events = append(c.events, audit.Event{Time: c.now, Actor: "cvewatch", Action: "inventory", Vuln: f.VulnID,
			Project: f.Project, Env: string(f.Env), Note: note})
		c.dirty[f.VulnID] = true
		c.res.Reconciled++
	}
}

func prefixed(p string, xs []string) []string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = p + x
	}
	return out
}

func (c *cycle) enrich(ctx context.Context) {
	c.enrichCVSS(ctx)
	c.enrichEPSS(ctx)
}

// cvssRecheck is how long an issue NVD could not rate is left alone; NVD
// analyses a CVE days or weeks after it is published.
const cvssRecheck = 24 * time.Hour

// enrichCVSS rates tracked CVEs that no source scored (news items carry no
// score). It asks for a few per cycle and remembers the lookup in the ledger,
// so the same CVE is not asked again before cvssRecheck has passed.
func (c *cycle) enrichCVSS(ctx context.Context) {
	if !c.r.Cfg.Enrich.CVSS {
		return
	}
	l := c.r.Ledger
	vulnOf := map[string]string{} // CVE id -> vulnerability id
	var cves []string
	for _, v := range l.Relevant() {
		if !v.Unrated() || c.now.Sub(v.CVSSChecked) < cvssRecheck {
			continue
		}
		if i := slices.IndexFunc(v.Keys(), func(k string) bool { return strings.HasPrefix(k, "CVE-") }); i >= 0 && len(cves) < cvss.MaxPerCycle {
			cves = append(cves, v.Keys()[i])
			vulnOf[v.Keys()[i]] = v.ID
		}
	}
	if len(cves) == 0 {
		return
	}
	found, answered, err := cvss.Lookup(ctx, c.r.Getter, cves)
	if err != nil {
		c.r.Log.Warn("cvss lookup incomplete", "err", err)
	}
	for _, cve := range answered {
		l.MarkRated(vulnOf[cve], c.now)
	}
	for cve, r := range found {
		if l.SetRating(vulnOf[cve], r) {
			c.res.Rated++
			c.dirty[vulnOf[cve]] = true
		}
	}
}

// enrichEPSS adds EPSS scores to tracked CVEs when the operator turned it on.
// Only CVE ids leave the machine, and only for issues that have findings.
func (c *cycle) enrichEPSS(ctx context.Context) {
	if !c.r.Cfg.Enrich.EPSS {
		return
	}
	var ids []string
	for _, v := range c.r.Ledger.Relevant() {
		if strings.HasPrefix(v.ID, "CVE-") {
			ids = append(ids, v.ID)
		}
	}
	scores, err := epss.Scores(ctx, c.r.Getter, ids)
	if err != nil {
		c.r.Log.Warn("epss lookup incomplete", "err", err)
	}
	for id, e := range scores {
		if c.r.Ledger.SetEPSS(id, e) {
			c.res.Enriched++
			c.dirty[id] = true
		}
	}
}

func (c *cycle) addFindings(vulnID string, ms []relevance.Match) {
	n := AddFindings(c.r.Ledger, vulnID, ms, c.now)
	c.res.Findings += n
	if n > 0 {
		c.res.Fresh[vulnID] = true
	}
}

// AddFindings creates one finding per matched project environment. It never
// touches existing findings, so statuses survive. It returns how many were created.
func AddFindings(l *ledger.Ledger, vulnID string, ms []relevance.Match, now time.Time) int {
	created := 0
	for _, m := range ms {
		labels := make([]string, len(m.Installed))
		for k, in := range m.Installed {
			labels[k] = in.Label()
		}
		f := model.Finding{
			VulnID: vulnID, Project: m.Project, Env: m.Env, Status: model.StatusOpen, Matched: labels,
			Installed: m.Installed, Applies: m.Applies, Reasons: m.Reasons, Updated: now,
		}
		if l.AddFinding(f) {
			created++
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
func (c *cycle) auditDetected() {
	for _, id := range slices.Sorted(maps.Keys(c.res.Fresh)) {
		var projects []string
		for _, f := range c.r.Ledger.FindingsOf(id) {
			if !slices.Contains(projects, f.Project) {
				projects = append(projects, f.Project)
			}
		}
		c.events = append(c.events, audit.Event{Time: c.now, Actor: "cvewatch", Action: "detected", Vuln: id,
			Project: strings.Join(projects, ",")})
	}
}

// alert sends every open finding that a channel has not been told about yet,
// including ones whose delivery failed in an earlier run. Delivery is tracked
// per channel. Findings whose version is known to be unaffected are recorded
// but never alerted.
func (r *Runner) alert(ctx context.Context, now time.Time) int {
	sent := 0
	for _, d := range r.Channels {
		name := d.Channel.Name()
		var batch []notify.Alert
		for _, f := range r.Ledger.Findings() {
			v := r.Ledger.Vuln(f.VulnID)
			if f.Status != model.StatusOpen || f.Delivered(name) || v == nil ||
				f.Applies == model.AppNotAffected || !v.Severity.AtLeast(d.Min) || !r.Cfg.Horizon.Contains(v.Published, now) {
				continue
			}
			if n := len(batch); n > 0 && batch[n-1].Vuln.ID == v.ID {
				batch[n-1].Findings = append(batch[n-1].Findings, f)
			} else {
				batch = append(batch, notify.Alert{Vuln: v, Findings: []model.Finding{f}})
			}
		}

		// Most urgent first, and a cap per run so enabling a channel on a busy
		// backlog does not flood it; the rest goes out next cycle.
		slices.SortStableFunc(batch, func(a, b notify.Alert) int {
			return query.Compare(a.Vuln, b.Vuln, hasProd(a.Findings), hasProd(b.Findings))
		})
		if limit := maxBatchesPerRun * notify.BatchSize; len(batch) > limit {
			r.Log.Info("alert backlog throttled", "channel", name, "sending", limit, "deferred", len(batch)-limit)
			batch = batch[:limit]
		}

		for chunk := range slices.Chunk(batch, notify.BatchSize) {
			err := d.Channel.Send(ctx, chunk, now)
			r.Ledger.ChannelOutcome(name, now, clipErr(err))
			if err != nil {
				r.Log.Error("alert delivery failed, will retry next run", "channel", name, "err", err)
				break
			}
			var events []audit.Event
			for _, a := range chunk {
				for _, f := range a.Findings {
					r.Ledger.MarkAlerted(f.Key(), name, now)
					sent++
				}
				events = append(events, audit.Event{Time: now, Actor: "cvewatch", Action: "alerted", Vuln: a.Vuln.ID, Note: name})
			}
			if err := r.Audit.Append(events...); err != nil {
				r.Log.Error("audit write failed", "err", err)
			}
		}
	}
	return sent
}

// clipErr bounds an error for the health record; nil stays nil.
func clipErr(err error) error {
	if err == nil {
		return nil
	}
	return errors.New(query.Clip(err.Error(), 200))
}

func hasProd(fs []model.Finding) bool {
	return slices.ContainsFunc(fs, func(f model.Finding) bool { return model.IsProd(f.Env) })
}

// digests sends the periodic "still open" summary to each configured channel,
// once per day, in the first cycle after the configured time.
func (r *Runner) digests(ctx context.Context, now time.Time) int {
	cfg := r.Cfg.Notify.Digest
	if cfg.DailyAt == "" || len(r.Channels) == 0 {
		return 0
	}
	at, err := time.Parse("15:04", cfg.DailyAt)
	if err != nil {
		return 0 // config validation reports this; never crash a cycle over it
	}
	due := time.Date(now.Year(), now.Month(), now.Day(), at.Hour(), at.Minute(), 0, 0, now.Location())
	if now.Before(due) {
		return 0
	}

	sent := 0
	digest := BuildDigest(r.Ledger, query.Filter{Env: cfg.Env, Published: query.InHorizon(r.Cfg.Horizon, now)}, cfg.Max, now)
	for _, d := range r.Channels {
		name := d.Channel.Name()
		if len(cfg.Channels) > 0 && !slices.Contains(cfg.Channels, name) {
			continue
		}
		if !r.Ledger.Digest(name).Before(due) {
			continue // today's digest already went out
		}
		if digest.Open > 0 {
			err := d.Channel.SendDigest(ctx, digest, now)
			r.Ledger.ChannelOutcome(name, now, clipErr(err))
			if err != nil {
				r.Log.Error("digest delivery failed, will retry next run", "channel", name, "err", err)
				continue
			}
			sent++
			if err := r.Audit.Append(audit.Event{Time: now, Actor: "cvewatch", Action: "digest", Note: name}); err != nil {
				r.Log.Error("audit write failed", "err", err)
			}
		}
		r.Ledger.SetDigest(name, now) // also when nothing is open: no repeat today
	}
	return sent
}

// BuildDigest summarizes what is still open, most urgent first, capped at max (default 20).
func BuildDigest(l *ledger.Ledger, f query.Filter, max int, now time.Time) notify.Digest {
	if max <= 0 {
		max = 20
	}
	issues := query.Open(l, f, now)
	d := notify.Digest{Env: f.Env, Open: len(issues), BySeverity: map[model.Severity]int{}}
	for _, is := range issues {
		d.BySeverity[is.Severity]++
		overdue := false
		var projects []string
		owner := ""
		for _, t := range is.Targets {
			overdue = overdue || t.Overdue
			if !slices.Contains(projects, t.Project) {
				projects = append(projects, t.Project)
			}
			if owner == "" {
				owner = t.Owner
			}
		}
		if overdue {
			d.Overdue++
		}
		if len(d.Items) >= max {
			d.Truncated++
			continue
		}
		link := ""
		if len(is.Untrusted.Articles) > 0 {
			link = is.Untrusted.Articles[0].URL
		}
		d.Items = append(d.Items, notify.DigestItem{ID: is.ID, Title: is.Untrusted.Title, Severity: is.Severity,
			Projects: projects, Age: is.Age, KEV: is.KEV != nil, Overdue: overdue, Owner: owner, URL: link})
	}
	return d
}
