// Package ops is the one module behind every front end. The CLI and the MCP
// server are thin adapters over it, so validation, access control, audit and
// the order of write steps are decided here exactly once.
package ops

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/b070nd/cvewatch/app/src/audit"
	"github.com/b070nd/cvewatch/app/src/calendar"
	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/dashboard"
	"github.com/b070nd/cvewatch/app/src/evidence"
	"github.com/b070nd/cvewatch/app/src/export"
	"github.com/b070nd/cvewatch/app/src/host"
	"github.com/b070nd/cvewatch/app/src/inventory"
	"github.com/b070nd/cvewatch/app/src/ledger"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/notify"
	"github.com/b070nd/cvewatch/app/src/pipeline"
	"github.com/b070nd/cvewatch/app/src/priority"
	"github.com/b070nd/cvewatch/app/src/query"
	"github.com/b070nd/cvewatch/app/src/relevance"
	"github.com/b070nd/cvewatch/app/src/report"
	"github.com/b070nd/cvewatch/app/src/status"
	"github.com/b070nd/cvewatch/app/src/store"
)

// ErrDenied means the actor has no access to what it asked for.
var ErrDenied = errors.New("access denied")

// Session is one locked view of the monitor: config, ledger and storage.
// Open it, do one thing, close it, so a running daemon is never blocked for
// longer than one call.
type Session struct {
	Cfg    *config.Bundle
	Ledger *ledger.Ledger
	Audit  *audit.Log
	Log    *slog.Logger
	Now    func() time.Time
	Actor  string // who is acting; defaults to audit.Actor()

	store    store.Storage
	reader   store.Reader // set for read-only sessions
	readOnly bool
}

// ErrReadOnly is returned by anything that would change state in a session
// opened with OpenReadOnly.
var ErrReadOnly = errors.New("this session is read-only")

// Open loads the configuration under root and locks and loads the state.
func Open(root string, log *slog.Logger) (*Session, error) {
	return openLoaded(root, log, config.Load)
}

func openLoaded(root string, log *slog.Logger, loader func(string) (*config.Bundle, error)) (*Session, error) {
	cfg, err := loader(root)
	if err != nil {
		return nil, err
	}
	logLoaded(cfg, log)
	st, err := store.Open(cfg.Storage.Backend, cfg.DataDir)
	if err != nil {
		return nil, err
	}
	s, err := OpenWith(cfg, st, log)
	if err != nil {
		st.Close()
		return nil, err
	}
	return s, nil
}

func logLoaded(cfg *config.Bundle, log *slog.Logger) {
	for _, w := range cfg.Warnings {
		log.Warn(w)
	}
	for _, b := range cfg.Broken {
		log.Warn("skipping broken project", "project", b.Name, "file", b.File, "error", b.Err)
	}
}

// OpenWith builds a session on any storage adapter.
func OpenWith(cfg *config.Bundle, st store.Storage, log *slog.Logger) (*Session, error) {
	state, err := st.Load()
	if err != nil {
		return nil, err
	}
	return &Session{
		Cfg: cfg, Ledger: ledger.New(state), Audit: audit.Open(cfg.DataDir), Log: log, Now: time.Now,
		Actor: audit.Actor(), store: st,
	}, nil
}

func (s *Session) Close() error {
	if s.readOnly {
		return s.reader.Close()
	}
	return s.store.Close()
}

// Commit persists the ledger.
func (s *Session) Commit() error {
	if s.readOnly {
		return ErrReadOnly
	}
	return s.store.Save(s.Ledger.State())
}

// OpenReadOnly loads the configuration and a lock-free snapshot of the state.
// Viewers use it so they never block the daemon or each other; anything that
// would change state returns ErrReadOnly.
func OpenReadOnly(root string, log *slog.Logger) (*Session, error) {
	return openReadOnlyLoaded(root, log, config.Load)
}

func openReadOnlyLoaded(root string, log *slog.Logger, loader func(string) (*config.Bundle, error)) (*Session, error) {
	cfg, err := loader(root)
	if err != nil {
		return nil, err
	}
	logLoaded(cfg, log)
	rd, err := store.OpenReader(cfg.Storage.Backend, cfg.DataDir)
	if err != nil {
		return nil, err
	}
	s, err := OpenReadOnlyWith(cfg, rd, log)
	if err != nil {
		rd.Close()
		return nil, err
	}
	return s, nil
}

// OpenReadOnlyWith builds a read-only session on any reader.
func OpenReadOnlyWith(cfg *config.Bundle, rd store.Reader, log *slog.Logger) (*Session, error) {
	state, err := rd.Load()
	if err != nil {
		return nil, err
	}
	return &Session{Cfg: cfg, Ledger: ledger.New(state), Audit: audit.Open(cfg.DataDir), Log: log, Now: time.Now,
		Actor: audit.Actor(), reader: rd, readOnly: true}, nil
}

// reload replaces the in-memory ledger with the stored state, for retrying
// after another process saved first.
func (s *Session) reload() error {
	state, err := s.store.Load()
	if err != nil {
		return err
	}
	s.Ledger = ledger.New(state)
	return nil
}

// ParseFilter validates the flags shared by every listing.
func ParseFilter(min, project, env string) (query.Filter, error) {
	f := query.Filter{Project: project, Env: model.Env(env)}
	if env != "" && !f.Env.Valid() {
		return f, fmt.Errorf("unknown env %q (use dev, int, staging, prod)", env)
	}
	if min != "" {
		if f.Min = model.ParseSeverity(min); f.Min == model.SevUnknown {
			return f, fmt.Errorf("unknown severity %q (use low, medium, high or critical)", min)
		}
	}
	return f, nil
}

// ---- access control ----

// scope narrows a filter to what the actor may see.
func (s *Session) scope(f query.Filter) (query.Filter, error) {
	projects, _, open := s.Cfg.Allowed(baseActor(s.Actor))
	switch {
	case open:
		return f, nil
	case len(projects) == 0:
		return f, ErrDenied
	}
	f.Projects = projects
	return f, nil
}

// mayWrite checks write access to one project ("" means all projects).
func (s *Session) mayWrite(project string) error {
	if s.readOnly {
		return ErrReadOnly
	}
	projects, write, open := s.Cfg.Allowed(baseActor(s.Actor))
	switch {
	case !write:
		return fmt.Errorf("%w: %s may not change anything", ErrDenied, s.Actor)
	case open || project != "" && slices.Contains(projects, project):
		return nil
	}
	return fmt.Errorf("%w: %s has no access to project %q", ErrDenied, s.Actor, project)
}

// baseActor strips an adapter prefix such as "mcp:" so access rules name people.
func baseActor(a string) string {
	if i := strings.LastIndex(a, ":"); i >= 0 {
		return a[i+1:]
	}
	return a
}

// ---- reads ----

// List returns open issues, most severe first.
func (s *Session) List(f query.Filter) ([]query.Issue, error) {
	f, err := s.scope(f)
	if err != nil {
		return nil, err
	}
	return query.Open(s.Ledger, f, s.Now()), nil
}

// Show returns one issue and its markdown report.
func (s *Session) Show(id string) (query.Issue, string, error) {
	d, err := s.IssueDetail(id)
	return d.Issue, d.Markdown, err
}

// Calendar returns the issues published in a month.
func (s *Session) Calendar(month time.Time, f query.Filter) ([]calendar.Entry, error) {
	f, err := s.scope(f)
	if err != nil {
		return nil, err
	}
	var out []calendar.Entry
	for _, e := range query.Entries(s.Ledger, f, s.Now()) {
		if e.Date.Year() == month.Year() && e.Date.Month() == month.Month() {
			out = append(out, e)
		}
	}
	return out, nil
}

// WriteCalendar renders the month as a self-contained HTML page in the alerts directory.
func (s *Session) WriteCalendar(month time.Time, f query.Filter) (string, error) {
	entries, err := s.Calendar(month, f)
	if err != nil {
		return "", err
	}
	path := filepath.Join(s.Cfg.AlertsDir, "calendar-"+month.Format("2006-01")+".html")
	return path, host.WriteFileAtomic(path, []byte(calendar.HTML(entries, month, s.Now())))
}

// Explanation says why an issue is, or would be, relevant.
type Explanation struct {
	ID       string         `json:"id"`
	Stored   []query.Target `json:"stored"`          // what was decided when it was first seen
	Today    []string       `json:"today"`           // what the current config says, per project
	Notes    []string       `json:"notes,omitempty"` // techs that did not match, and why
	Relevant bool           `json:"relevant_today"`
}

// Explain re-judges the stored record with the current config and shows it
// next to the decision taken at the time. Irrelevant records keep only their
// title, so for them the comparison is title-only.
func (s *Session) Explain(id string) (Explanation, error) {
	f, err := s.scope(query.Filter{})
	if err != nil {
		return Explanation{}, err
	}
	is, err := query.One(s.Ledger, id, f, s.Now())
	if err != nil {
		return Explanation{}, err
	}
	v := s.Ledger.Vuln(is.ID)
	verdict := s.judge(v)
	ex := Explanation{ID: v.ID, Stored: is.Targets, Notes: verdict.Notes, Relevant: verdict.Relevant()}
	for _, m := range verdict.Matches {
		if len(f.Projects) > 0 && !slices.Contains(f.Projects, m.Project) {
			continue
		}
		ex.Today = append(ex.Today, fmt.Sprintf("%s: %s — %s", m.Project, m.Applies, strings.Join(m.Reasons, "; ")))
	}
	return ex, nil
}

func (s *Session) judge(v *model.Vulnerability) relevance.Verdict {
	it := model.Item{
		Title: v.Title, Summary: v.Summary, IDs: v.Keys(), Affected: v.Affected, Severity: v.Severity,
		Published: v.Published, TitleOnly: v.Summary == "", // irrelevant records kept no summary
	}
	return relevance.New(s.Cfg.Techs).Judge(it, inventory.Load(s.Cfg).Targets())
}

// ---- writes ----

// Change is a status update requested by a person or an agent. A reason in
// Note is required for StatusNotAffected, the human assertion that an issue
// does not apply here.
type Change struct {
	ID, Project string
	Env         model.Env // empty means every environment of the project
	Status      model.Status
	Note        string
}

func (c Change) validate(cfg *config.Bundle) error {
	switch c.Status {
	case model.StatusFixed, model.StatusIgnored, model.StatusOpen:
	case model.StatusNotAffected:
		if strings.TrimSpace(c.Note) == "" {
			return errors.New("a not-affected statement needs a reason (-note)")
		}
	default:
		return fmt.Errorf("status must be fixed, ignored, not_affected or open, not %q", c.Status)
	}
	return validateTarget(cfg, c.Project, c.Env)
}

func validateTarget(cfg *config.Bundle, project string, env model.Env) error {
	if env != "" && !env.Valid() {
		return fmt.Errorf("unknown env %q (use dev, int, staging, prod)", env)
	}
	if project == "" {
		return errors.New("a project is required")
	}
	if !slices.ContainsFunc(cfg.Projects, func(p model.Project) bool { return p.Name == project }) {
		return fmt.Errorf("unknown project %q", project)
	}
	return nil
}

// clean keeps free text from people and agents tidy: no control characters,
// no line breaks, bounded length.
func clean(s string, max int) string { return query.Clip(s, max) }

// Resolve applies a status change.
func (s *Session) Resolve(c Change) (int, error) {
	if err := c.validate(s.Cfg); err != nil {
		return 0, err
	}
	note := clean(c.Note, 500)
	return s.apply(c.ID, c.Project, c.Env, ledger.Update{Status: &c.Status, Note: &note},
		audit.Event{Action: "status", Status: string(c.Status), Note: note})
}

// Assignment sets who handles findings and by when. An empty field is left
// as it is; "-" (or "none" for Due) clears it. Due is a date, YYYY-MM-DD.
type Assignment struct {
	ID, Project        string
	Env                model.Env
	Owner, Due, Ticket string
}

func (s *Session) Assign(a Assignment) (int, error) {
	if err := validateTarget(s.Cfg, a.Project, a.Env); err != nil {
		return 0, err
	}
	var u ledger.Update
	var parts []string
	if a.Owner != "" {
		v := clean(strings.TrimPrefix(a.Owner, "-"), 100)
		u.Owner = &v
		parts = append(parts, "owner="+v)
	}
	if a.Ticket != "" {
		v := ""
		if a.Ticket != "-" {
			v = clean(a.Ticket, 300)
		}
		u.Ticket = &v
		parts = append(parts, "ticket="+v)
	}
	if a.Due != "" {
		var d time.Time
		if a.Due != "none" && a.Due != "-" {
			var err error
			if d, err = time.Parse("2006-01-02", a.Due); err != nil {
				return 0, fmt.Errorf("due must look like 2026-11-30: %w", err)
			}
		}
		u.Due = &d
		parts = append(parts, "due="+d.Format("2006-01-02"))
	}
	if len(parts) == 0 {
		return 0, errors.New("nothing to assign: give -owner, -due or -ticket")
	}
	return s.apply(a.ID, a.Project, a.Env, u, audit.Event{Action: "assign", Note: strings.Join(parts, " ")})
}

// Attachment adds a note and link as evidence for a fix, a decision or a deployment.
type Attachment struct {
	ID, Project string
	Env         model.Env
	Note, URL   string
}

func (s *Session) Attach(a Attachment) (int, error) {
	if err := validateTarget(s.Cfg, a.Project, a.Env); err != nil {
		return 0, err
	}
	note, link := clean(a.Note, 500), strings.TrimSpace(a.URL)
	if note == "" && link == "" {
		return 0, errors.New("evidence needs a note or a link")
	}
	if link != "" {
		if u, err := url.Parse(link); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" ||
			strings.ContainsAny(link, " \t\r\n<>|\"`\\") {
			return 0, errors.New("the evidence link must be a plain http(s) URL")
		}
	}
	return s.apply(a.ID, a.Project, a.Env, ledger.Update{Evidence: &model.Evidence{Note: note, URL: link}},
		audit.Event{Action: "evidence", Note: note, URL: link})
}

// apply is the one write path. The order is fixed: check access, change in
// memory, record in the audit log, refresh the report, save. If saving fails
// the audit log gets a compensating entry, so it never claims a change that
// did not land.
func (s *Session) apply(id, project string, env model.Env, u ledger.Update, ev audit.Event) (int, error) {
	n, err := s.applyOnce(id, project, env, u, ev)
	if errors.Is(err, store.ErrConflict) { // another process saved first (SQLite): reload and redo once
		if rerr := s.reload(); rerr != nil {
			return 0, rerr
		}
		return s.applyOnce(id, project, env, u, ev)
	}
	return n, err
}

func (s *Session) applyOnce(id, project string, env model.Env, u ledger.Update, ev audit.Event) (int, error) {
	if err := s.mayWrite(project); err != nil {
		return 0, err
	}
	v := s.Ledger.Lookup([]string{strings.ToUpper(strings.TrimSpace(id))})
	if v == nil {
		return 0, fmt.Errorf("unknown vulnerability %q", id)
	}
	now := s.Now()
	u.Actor = s.Actor
	n, err := s.Ledger.Update(v.ID, project, env, u, now)
	if err != nil {
		return 0, err
	}
	ev.Time, ev.Actor, ev.Vuln, ev.Project, ev.Env = now, s.Actor, v.ID, project, string(env)
	if err := s.Audit.Append(ev); err != nil {
		return 0, fmt.Errorf("audit log: %w", err) // never change anything without a record
	}
	path, rerr := report.Write(s.Cfg.AlertsDir, v, s.Ledger.FindingsOf(v.ID), now)
	if rerr == nil {
		v.ReportPath = path
	}
	if err := s.Commit(); err != nil {
		ev.Action, ev.Note = ev.Action+"-failed", "not saved: "+err.Error()
		s.Audit.Append(ev)
		return 0, err
	}
	return n, rerr
}

// Rescan re-judges tracked records that matched nothing against the current
// config. It only adds findings, never removes any, and only when apply is
// set; without it the call reports what would be created.
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
	if apply {
		if err := s.mayWrite(""); err != nil {
			return Rescan{}, err
		}
	}
	out := Rescan{Applied: apply}
	targets := inventory.Load(s.Cfg).Targets()
	judge := relevance.New(s.Cfg.Techs)
	now := s.Now()
	relevant := map[string]bool{}
	for _, v := range s.Ledger.Relevant() {
		relevant[v.ID] = true
	}
	var ids []string
	for id := range s.Ledger.State().Vulns {
		if !relevant[id] {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	for _, id := range ids {
		v := s.Ledger.Vuln(id)
		it := model.Item{Title: v.Title, Summary: v.Summary, IDs: v.Keys(), Affected: v.Affected,
			Severity: v.Severity, Published: v.Published, TitleOnly: v.Summary == ""}
		verdict := judge.Judge(it, targets)
		if len(verdict.Matches) == 0 {
			continue
		}
		c := Candidate{ID: v.ID, Title: query.Clip(v.Title, 120)}
		for _, m := range verdict.Matches {
			if !slices.Contains(c.Projects, m.Project) {
				c.Projects = append(c.Projects, m.Project)
			}
		}
		out.Candidates = append(out.Candidates, c)
		if !apply {
			continue
		}
		v.Techs = verdict.Techs
		if pipeline.AddFindings(s.Ledger, v.ID, verdict.Matches, now) > 0 {
			if path, err := report.Write(s.Cfg.AlertsDir, v, s.Ledger.FindingsOf(v.ID), now); err == nil {
				v.ReportPath = path
			}
			s.Audit.Append(audit.Event{Time: now, Actor: s.Actor, Action: "detected", Vuln: v.ID,
				Project: strings.Join(c.Projects, ","), Note: "rescan"})
		}
	}
	if apply && len(out.Candidates) > 0 {
		return out, s.Commit()
	}
	return out, nil
}

// Refresh fetches every source, records findings and alerts. It touches all
// projects, so it needs write access to all of them.
func (s *Session) Refresh(ctx context.Context) (pipeline.Result, error) {
	return s.RefreshWith(ctx, nil)
}

// RefreshProgress is one step of a running refresh; see pipeline.Progress.
type RefreshProgress = pipeline.Progress

// RefreshWith is Refresh that reports its steps. progress may be nil and is
// called from several goroutines, one at a time.
func (s *Session) RefreshWith(ctx context.Context, progress func(RefreshProgress)) (pipeline.Result, error) {
	if err := s.mayWrite(""); err != nil {
		return pipeline.Result{}, err
	}
	runner, err := pipeline.NewRunner(s.Cfg, s.Ledger, s.Commit, s.Log)
	if err != nil {
		return pipeline.Result{}, err
	}
	runner.Progress = progress
	return runner.Run(ctx)
}

// ---- exports, evidence, policy, digest, inventory ----

// Export returns the open issues with the status of every environment, as the
// versioned document all outputs share.
func (s *Session) Export(f query.Filter) (export.Document, error) {
	f, err := s.scope(f)
	if err != nil {
		return export.Document{}, err
	}
	f.Closed = true
	return export.New(query.Open(s.Ledger, f, s.Now()), s.Now()), nil
}

// Evidence assembles the evidence pack for one issue: facts from the feeds,
// the per-environment truth, and the audit trail, in time order.
func (s *Session) Evidence(id string) (evidence.Pack, error) {
	p, err := s.issueParts(id)
	if err != nil {
		return evidence.Pack{}, err
	}
	return p.pack(s.Now()), nil
}

// visibleTo reports whether an audit record concerns no project or one of the allowed ones.
func visibleTo(allowed []string, project string) bool {
	if project == "" {
		return true
	}
	for _, p := range strings.Split(project, ",") {
		if slices.Contains(allowed, p) {
			return true
		}
	}
	return false
}

// Violations lists open findings that break a policy rule or their own due date.
func (s *Session) Violations() ([]priority.Violation, error) {
	f, err := s.scope(query.Filter{})
	if err != nil {
		return nil, err
	}
	var subjects []priority.Subject
	for _, fd := range s.Ledger.Findings() {
		v := s.Ledger.Vuln(fd.VulnID)
		if fd.Status != model.StatusOpen || fd.Applies == model.AppNotAffected || v == nil ||
			(len(f.Projects) > 0 && !slices.Contains(f.Projects, fd.Project)) {
			continue
		}
		subjects = append(subjects, priority.Subject{
			VulnID: fd.VulnID, Title: query.Clip(v.Title, 100), Project: fd.Project, Env: fd.Env, Severity: v.Severity,
			KEV: v.KEV != nil, Owner: fd.Owner, Due: fd.Due, Detected: v.FirstSeen,
		})
	}
	var rules []priority.Rule
	for _, r := range s.Cfg.Policy.Rules {
		rules = append(rules, priority.Rule{Name: r.Name, Env: r.Env, KEV: r.KEV, MinSeverity: r.MinSeverity,
			OwnerWithin: r.OwnerWithin, FixWithin: r.FixWithin})
	}
	return priority.Violations(rules, subjects, s.Now()), nil
}

// Digest builds the "still open" summary as the digest channels would send it.
func (s *Session) Digest() (notify.Digest, error) {
	f, err := s.scope(query.Filter{Env: s.Cfg.Notify.Digest.Env})
	if err != nil {
		return notify.Digest{}, err
	}
	return pipeline.BuildDigest(s.Ledger, f, s.Cfg.Notify.Digest.Max, s.Now()), nil
}

// SendDigest sends the digest now to every active channel, without touching
// the daily cursor. It returns how many channels took it.
func (s *Session) SendDigest(ctx context.Context) (int, error) {
	if err := s.mayWrite(""); err != nil {
		return 0, err
	}
	d, err := s.Digest()
	if err != nil {
		return 0, err
	}
	channels, err := pipeline.Channels(s.Cfg, s.Log)
	if err != nil {
		return 0, err
	}
	sent := 0
	for _, c := range channels {
		if err := c.Channel.SendDigest(ctx, d, s.Now()); err != nil {
			return sent, fmt.Errorf("%s: %w", c.Channel.Name(), err)
		}
		sent++
	}
	return sent, nil
}

// InventoryView is what the tool believes runs in each project environment.
type InventoryView struct {
	Targets  []relevance.Target
	Sources  []inventory.Source
	Problems []inventory.Problem
}

func (s *Session) Inventory(project string) (InventoryView, error) {
	f, err := s.scope(query.Filter{Project: project})
	if err != nil {
		return InventoryView{}, err
	}
	inv := inventory.Load(s.Cfg)
	var v InventoryView
	for _, t := range inv.Targets() {
		if t.Project == f.Project || f.Project == "" {
			if len(f.Projects) == 0 || slices.Contains(f.Projects, t.Project) {
				v.Targets = append(v.Targets, t)
			}
		}
	}
	for _, src := range inv.Sources() {
		if (f.Project == "" || src.Project == f.Project) && (len(f.Projects) == 0 || slices.Contains(f.Projects, src.Project)) {
			v.Sources = append(v.Sources, src)
		}
	}
	for _, p := range inv.Problems() {
		if (f.Project == "" || p.Project == f.Project) && (len(f.Projects) == 0 || slices.Contains(f.Projects, p.Project)) {
			v.Problems = append(v.Problems, p)
		}
	}
	return v, nil
}

// ---- health and dashboard ----

// Status reports the health of the tool itself: the daemon, each feed and
// channel, and the recent cycles.
func (s *Session) Status() (status.Report, error) {
	if _, err := s.scope(query.Filter{}); err != nil {
		return status.Report{}, err
	}
	in := status.Input{Now: s.Now(), Interval: s.Cfg.Interval}
	for _, src := range s.Cfg.Sources {
		if !src.Disabled {
			in.Sources = append(in.Sources, status.Ref{ID: src.ID, Type: src.Type})
		}
	}
	for _, e := range notify.FromConfig(s.Cfg) {
		if e.Channel != nil {
			in.Channels = append(in.Channels, e.Name)
		}
	}
	in.Cycles, in.Health, in.Delivery, in.Beat = s.Ledger.Health()
	return status.Build(in), nil
}

// Beat records that the daemon is alive and when it will run next.
func (s *Session) Beat(started, next time.Time) error {
	if err := s.mayWrite(""); err != nil {
		return err
	}
	s.Ledger.SetHeartbeat(model.Heartbeat{Mode: "daemon", Started: started, LastCycle: s.Now(), NextRun: next,
		Interval: s.Cfg.Interval, PID: os.Getpid()})
	return s.Commit()
}

// DashboardHTML renders the static status page for everything the actor may see.
func (s *Session) DashboardHTML() (string, error) {
	f, err := s.scope(query.Filter{})
	if err != nil {
		return "", err
	}
	f.Closed = true
	rep, err := s.Status()
	if err != nil {
		return "", err
	}
	viol, err := s.Violations()
	if err != nil {
		return "", err
	}
	d := dashboard.Data{Issues: query.Open(s.Ledger, f, s.Now()), Violations: viol, Status: rep}
	for _, p := range s.Cfg.Projects {
		if len(f.Projects) == 0 || slices.Contains(f.Projects, p.Name) {
			d.Projects = append(d.Projects, dashboard.Project{Name: p.Name, Envs: p.EffectiveEnvs()})
		}
	}
	return dashboard.HTML(d, s.Now()), nil
}

// WriteDashboard writes the dashboard page, owner-only, and returns its path.
func (s *Session) WriteDashboard() (string, error) {
	page, err := s.DashboardHTML()
	if err != nil {
		return "", err
	}
	path := s.Cfg.DashboardPath()
	return path, host.WriteFileAtomic(path, []byte(page))
}
