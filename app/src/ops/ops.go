// Package ops is the one module behind every front end. The CLI and the MCP
// server are thin adapters over it, so validation, access control, audit and
// the order of write steps are decided here exactly once.
package ops

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/b070nd/cvewatch/app/src/audit"
	"github.com/b070nd/cvewatch/app/src/calendar"
	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/host"
	"github.com/b070nd/cvewatch/app/src/ledger"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/pipeline"
	"github.com/b070nd/cvewatch/app/src/query"
	"github.com/b070nd/cvewatch/app/src/relevance"
	"github.com/b070nd/cvewatch/app/src/report"
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

	store store.Storage
}

// Open loads the configuration under root and locks and loads the state.
func Open(root string, log *slog.Logger) (*Session, error) {
	cfg, err := config.Load(root)
	if err != nil {
		return nil, err
	}
	for _, w := range cfg.Warnings {
		log.Warn(w)
	}
	st, err := store.OpenFile(cfg.DataDir)
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

func (s *Session) Close() error { return s.store.Close() }

// Commit persists the ledger.
func (s *Session) Commit() error { return s.store.Save(s.Ledger.State()) }

// ParseFilter validates the flags shared by every listing.
func ParseFilter(min, project string) (query.Filter, error) {
	f := query.Filter{Project: project}
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
	f, err := s.scope(query.Filter{})
	if err != nil {
		return query.Issue{}, "", err
	}
	is, err := query.One(s.Ledger, id, f, s.Now())
	if err != nil {
		return is, "", err
	}
	var fs []model.Finding
	for _, fd := range s.Ledger.FindingsOf(is.ID) {
		if len(f.Projects) == 0 || slices.Contains(f.Projects, fd.Project) {
			fs = append(fs, fd)
		}
	}
	return is, report.Render(s.Ledger.Vuln(is.ID), fs, s.Now()), nil
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
	return relevance.New(s.Cfg.Techs).Judge(it, s.Cfg.Projects, pipeline.LoadMatrix(s.Cfg, s.Log))
}

// ---- writes ----

// Change is a status update requested by a person or an agent.
type Change struct {
	ID, Project string
	Env         model.Env // empty means every environment of the project
	Status      model.Status
	Note        string
}

func (c Change) validate(cfg *config.Bundle) error {
	switch c.Status {
	case model.StatusFixed, model.StatusIgnored, model.StatusOpen:
	default:
		return fmt.Errorf("status must be fixed, ignored or open, not %q", c.Status)
	}
	if c.Env != "" && !c.Env.Valid() {
		return fmt.Errorf("unknown env %q (use dev, int, staging, prod)", c.Env)
	}
	if c.Project == "" {
		return errors.New("a project is required")
	}
	if !slices.ContainsFunc(cfg.Projects, func(p model.Project) bool { return p.Name == c.Project }) {
		return fmt.Errorf("unknown project %q", c.Project)
	}
	return nil
}

// Resolve applies a status change. The order is fixed: check, change in
// memory, record in the audit log, refresh the report, save. If saving fails
// the audit log gets a compensating entry, so it never claims a change that
// did not land.
func (s *Session) Resolve(c Change) (int, error) {
	if err := c.validate(s.Cfg); err != nil {
		return 0, err
	}
	if err := s.mayWrite(c.Project); err != nil {
		return 0, err
	}
	v := s.Ledger.Lookup([]string{strings.ToUpper(strings.TrimSpace(c.ID))})
	if v == nil {
		return 0, fmt.Errorf("unknown vulnerability %q", c.ID)
	}
	now := s.Now()
	n, err := s.Ledger.SetStatus(v.ID, c.Project, c.Env, c.Status, c.Note, now)
	if err != nil {
		return 0, err
	}
	ev := audit.Event{Time: now, Actor: s.Actor, Action: "status", Vuln: v.ID, Project: c.Project,
		Env: string(c.Env), Status: string(c.Status), Note: c.Note}
	if err := s.Audit.Append(ev); err != nil {
		return 0, fmt.Errorf("audit log: %w", err) // never change status without a record
	}
	path, rerr := report.Write(s.Cfg.AlertsDir, v, s.Ledger.FindingsOf(v.ID), now)
	if rerr == nil {
		v.ReportPath = path
	}
	if err := s.Commit(); err != nil {
		ev.Action, ev.Note = "status-failed", "not saved: "+err.Error()
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
	matrix := pipeline.LoadMatrix(s.Cfg, s.Log)
	judge := relevance.New(s.Cfg.Techs)
	now := s.Now()
	relevant := map[string]bool{}
	for _, v := range s.Ledger.Relevant() {
		relevant[v.ID] = true
	}
	ids := make([]string, 0)
	for _, f := range s.Ledger.State().Vulns {
		if !relevant[f.ID] {
			ids = append(ids, f.ID)
		}
	}
	slices.Sort(ids)
	for _, id := range ids {
		v := s.Ledger.Vuln(id)
		it := model.Item{Title: v.Title, Summary: v.Summary, IDs: v.Keys(), Affected: v.Affected,
			Severity: v.Severity, Published: v.Published, TitleOnly: v.Summary == ""}
		verdict := judge.Judge(it, s.Cfg.Projects, matrix)
		if !verdict.Relevant() || len(verdict.Matches) == 0 {
			continue
		}
		c := Candidate{ID: v.ID, Title: query.Clip(v.Title, 120)}
		for _, m := range verdict.Matches {
			c.Projects = append(c.Projects, m.Project)
		}
		out.Candidates = append(out.Candidates, c)
		if !apply {
			continue
		}
		v.Techs = verdict.Techs
		if pipeline.AddFindings(s.Ledger, s.Cfg.Projects, v.ID, verdict.Matches, now) > 0 {
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
	if err := s.mayWrite(""); err != nil {
		return pipeline.Result{}, err
	}
	runner, err := pipeline.NewRunner(s.Cfg, s.Ledger, s.Commit, s.Log)
	if err != nil {
		return pipeline.Result{}, err
	}
	return runner.Run(ctx)
}
