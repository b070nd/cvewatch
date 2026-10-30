package tui

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/b070nd/cvewatch/app/src/audit"
	"github.com/b070nd/cvewatch/app/src/catalog"
	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/discovery"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/ops"
	"github.com/b070nd/cvewatch/app/src/priority"
	"github.com/b070nd/cvewatch/app/src/projectfile"
	"github.com/b070nd/cvewatch/app/src/projectflow"
	"github.com/b070nd/cvewatch/app/src/query"
	"github.com/b070nd/cvewatch/app/src/setup"
	"github.com/b070nd/cvewatch/app/src/status"
)

// snapshot is everything the screens show, read in one go from a read-only
// session. Screens only ever see this copy, never the session.
type snapshot struct {
	At         time.Time
	Root       string
	Issues     []query.Issue // open issues, most urgent first
	Status     status.Report
	Violations []priority.Violation
	Projects   []projectRow
	Warnings   []string       // parts that could not be read; the rest is still shown
	Horizon    config.Horizon // which publication dates the daemon judges and alerts
}

type projectRow struct {
	ops.ProjectView
	HasFile  bool                // has its own file under config/projects, so it can be edited here
	File     string              // that file
	Broken   string              // why the file does not load; the row then shows only its name
	Problems []projectfile.Issue // what is wrong with the file, errors first
	Hints    []projectfile.Hint  // what may not be covered or cause trouble; not errors

	Written []ops.LockEntry // the lockfiles as the file spells them (the loaded ones have resolved paths), for the editor

	Disabled     bool                          // the file is switched off (<name>.yaml.disabled): listed, not loaded
	Environments map[model.Env]model.EnvConfig // deployed versions and image per environment
	EnvsUnset    bool                          // the file has no envs: Envs is the old default
}

func (p projectRow) counts() (errs, warns int) {
	for _, i := range p.Problems {
		if i.Level == "error" {
			errs++
		} else {
			warns++
		}
	}
	return errs, warns
}

// loadSnapshot reads the issue list (fatal when it fails: access denied, no
// state) and the rest best-effort.
func loadSnapshot(s *ops.Session) (*snapshot, error) {
	issues, err := s.List(query.Filter{})
	if err != nil {
		return nil, err
	}
	sn := &snapshot{At: s.Now(), Root: s.Cfg.Root, Issues: issues, Horizon: s.Cfg.Horizon}
	warn := func(what string, err error) { sn.Warnings = append(sn.Warnings, what+": "+oneLine(err.Error())) }
	if sn.Status, err = s.Status(); err != nil {
		warn("status", err)
	}
	if sn.Violations, err = s.Violations(); err != nil {
		warn("policy", err)
	}
	files, err := s.ProjectNames()
	if err != nil {
		warn("project files", err)
	}
	problems, err := s.ProjectProblems("")
	if err != nil {
		warn("project problems", err)
	}
	byProject := map[string][]projectfile.Issue{}
	for _, i := range problems {
		byProject[i.Project] = append(byProject[i.Project], i)
	}
	hints, err := s.ProjectHints("")
	if err != nil {
		warn("project hints", err)
	}
	hintsOf := map[string][]projectfile.Hint{}
	for _, h := range hints {
		hintsOf[h.Project] = append(hintsOf[h.Project], h.Hint)
	}
	fileOf := func(name string) string {
		path, _ := s.ProjectFile(name)
		return path
	}
	allowed, _, open := s.Cfg.Allowed(audit.Actor())
	for _, p := range s.Cfg.Projects {
		if !open && !slices.Contains(allowed, p.Name) {
			continue
		}
		v := ops.ViewOf(p)
		v.Envs = v.Envs[:0]
		for _, e := range p.EffectiveEnvs() {
			v.Envs = append(v.Envs, string(e))
		}
		row := projectRow{ProjectView: v, HasFile: slices.Contains(files, p.Name), File: fileOf(p.Name), Problems: byProject[p.Name], Hints: hintsOf[p.Name], Environments: p.Environments, EnvsUnset: len(p.Envs) == 0}
		if row.HasFile {
			row.Written = writtenLockfiles(row.File)
		}
		sn.Projects = append(sn.Projects, row)
	}
	for _, br := range s.Cfg.Broken {
		if !open && !slices.Contains(allowed, br.Name) {
			continue
		}
		// the parse error is already in Err; the file-level issue would say it twice
		rest := slices.DeleteFunc(slices.Clone(byProject[br.Name]), func(i projectfile.Issue) bool { return i.Field == "file" })
		sn.Projects = append(sn.Projects, projectRow{ProjectView: ops.ProjectView{Name: br.Name}, HasFile: true, File: br.File, Broken: strings.TrimPrefix(br.Err, br.File+": "), Problems: rest})
	}
	off, err := s.DisabledProjects()
	if err != nil {
		warn("disabled projects", err)
	}
	for _, name := range off {
		if slices.ContainsFunc(sn.Projects, func(p projectRow) bool { return p.Name == name }) {
			continue // a live file of the same name wins; the disabled one is a leftover
		}
		file, _ := s.DisabledFile(name)
		sn.Projects = append(sn.Projects, projectRow{ProjectView: ops.ProjectView{Name: name}, HasFile: true, File: file, Disabled: true})
	}
	return sn, nil
}

// writtenLockfiles reads the lockfiles of a project file as they are written
// there, which is what an edit has to name; nil when the file does not parse.
func writtenLockfiles(path string) []ops.LockEntry {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	f, err := projectfile.Parse(data)
	if err != nil {
		return nil
	}
	return ops.ViewOf(f.Project()).Lockfiles
}

// counts is the overview's arithmetic, kept apart so it can be tested.
type counts struct {
	Issues   int
	Findings int
	BySev    map[int]int // by severity rank, open issues
	ByEnv    map[model.Env]int
	KEV      int
	ProdOpen int
	Overdue  int
}

func countsOf(issues []query.Issue) counts {
	c := counts{BySev: map[int]int{}, ByEnv: map[model.Env]int{}, Issues: len(issues)}
	for _, is := range issues {
		c.BySev[is.Severity.Rank()]++
		if is.KEV != nil {
			c.KEV++
		}
		if is.ProdOpen {
			c.ProdOpen++
		}
		for _, t := range is.Targets {
			if t.Status != model.StatusOpen {
				continue
			}
			c.Findings++
			c.ByEnv[t.Env]++
			if t.Overdue {
				c.Overdue++
			}
		}
	}
	return c
}

// ---- messages ----

type (
	tickMsg struct{}
	dataMsg struct {
		snap *snapshot
		err  error
		land *landing // where the Projects screen settles once this snapshot is in
	}
	detailMsg struct {
		id    string
		is    query.Issue
		det   *query.Detail // the same issue with its links, installed versions, evidence and history; nil when not read
		md    string        // its report
		ex    *ops.Explanation
		exErr error
		err   error
	}
	actionMsg struct {
		info string
		warn error // the change landed but a follow-up step failed
		err  error
	}
	bulkMsg struct {
		info string
		warn error
		err  error
		done []string // the issues all of whose changes landed
	}
	flowMsg struct {
		flow     *setup.Flow
		creating bool
		name     string
		note     string
		infra    map[string]bool // the technologies the scan found only in container or orchestration files
		err      error
	}
	scanMsg struct {
		res discovery.Result
		err error
	}
	previewMsg struct {
		f    *form
		seq  int
		prev ops.ProjectPreview
		err  error
	}
	savedMsg struct {
		f    *form
		prev ops.ProjectPreview
		err  error
	}
)

// ---- commands: every Backend call runs here, never in Update ----

func tickCmd(d time.Duration) tea.Cmd {
	return tea.Tick(d, func(time.Time) tea.Msg { return tickMsg{} })
}

func loadCmd(b Backend) tea.Cmd { return loadLandCmd(b, nil) }

// loadLandCmd reads the snapshot and, once it is in, puts the Projects screen
// on a project (see landing).
func loadLandCmd(b Backend, land *landing) tea.Cmd {
	return func() tea.Msg {
		var sn *snapshot
		err := b.Read(func(s *ops.Session) (e error) { sn, e = loadSnapshot(s); return e })
		return dataMsg{snap: sn, err: err, land: land}
	}
}

// detailCmd reads the page of an issue. Reading the audit trail for its
// history makes this the dearest read, so it runs once per open and refresh.
func detailCmd(b Backend, id string) tea.Cmd {
	return func() tea.Msg {
		m := detailMsg{id: id}
		m.err = b.Read(func(s *ops.Session) (e error) {
			full, e := s.IssueDetail(id)
			if e != nil {
				return e
			}
			m.is, m.det, m.md = full.Issue, &full.Detail, full.Markdown
			ex, xe := s.Explain(id)
			if xe != nil {
				m.exErr = xe
			} else {
				m.ex = &ex
			}
			return nil
		})
		return m
	}
}

// attachCmd adds a note and link as evidence in one short write session.
func attachCmd(b Backend, a ops.Attachment) tea.Cmd {
	return func() tea.Msg {
		var n int
		var late error
		err := b.Write(func(s *ops.Session) error {
			var e error
			if n, e = s.Attach(a); n > 0 {
				late = e
				return nil
			}
			return e
		})
		if err != nil {
			return actionMsg{err: err}
		}
		return actionMsg{info: fmt.Sprintf("evidence added to %s in %s (%s)", a.ID, where(a.Project, a.Env), plural(n, "finding", "findings")), warn: late}
	}
}

// desktopMsg is the end of opening or copying a link.
type desktopMsg struct {
	note string
	err  error
}

func openLinkCmd(sys desktop, url string) tea.Cmd {
	return func() tea.Msg {
		if err := sys.Open(url); err != nil {
			return desktopMsg{err: err}
		}
		return desktopMsg{note: "opened " + url + " in the browser"}
	}
}

// copyLinkCmd puts the link on the clipboard. Without a tool for it the link
// is shown in the note, so it can still be read off the screen.
func copyLinkCmd(sys desktop, url string) tea.Cmd {
	return func() tea.Msg {
		tool, err := sys.Copy(url)
		switch {
		case errors.Is(err, errNoClipboard):
			return desktopMsg{note: "no clipboard tool here; the link is " + url}
		case err != nil:
			return desktopMsg{err: fmt.Errorf("could not copy the link (%w); it is %s", err, url)}
		}
		return desktopMsg{note: "copied " + url + " to the clipboard (" + tool + ")"}
	}
}

var changeWords = map[model.Status]string{
	model.StatusFixed: "marked fixed", model.StatusIgnored: "ignored",
	model.StatusNotAffected: "marked not affected", model.StatusOpen: "reopened",
}

func where(project string, env model.Env) string {
	if env == "" {
		return project + " (all environments)"
	}
	return project + "/" + string(env)
}

// resolveCmd applies a status change in one short write session. Resolve can
// save the change and still fail afterwards (the report file); that is a
// warning, not a failure.
func resolveCmd(b Backend, c ops.Change) tea.Cmd {
	return func() tea.Msg {
		var n int
		var late error
		err := b.Write(func(s *ops.Session) error {
			var e error
			if n, e = s.Resolve(c); n > 0 {
				late = e
				return nil
			}
			return e
		})
		if err != nil {
			return actionMsg{err: err}
		}
		return actionMsg{info: fmt.Sprintf("%s %s in %s (%s)", c.ID, changeWords[c.Status], where(c.Project, c.Env), plural(n, "finding", "findings")), warn: late}
	}
}

// bulkCmd applies the changes one after the other in one write session, so
// they share the actor and the audit trail. It stops at the first refusal;
// what landed before it stays.
func bulkCmd(b Backend, cs []ops.Change) tea.Cmd {
	return func() tea.Msg {
		left := map[string]int{}
		for _, c := range cs {
			left[c.ID]++
		}
		var findings, applied int
		var late error
		var done []string
		err := b.Write(func(s *ops.Session) error {
			for _, c := range cs {
				n, e := s.Resolve(c)
				if n == 0 && e != nil {
					return e
				}
				if e != nil {
					late = e // saved, but the report file failed
				}
				findings += n
				applied++
				if left[c.ID]--; left[c.ID] == 0 {
					done = append(done, c.ID)
				}
			}
			return nil
		})
		if err != nil && applied > 0 {
			err = fmt.Errorf("%d of %d changes written, then: %w", applied, len(cs), err)
		}
		if err != nil {
			return bulkMsg{err: err, done: done}
		}
		return bulkMsg{info: fmt.Sprintf("%s: %s in %s", changeWords[cs[0].Status], plural(findings, "finding", "findings"), plural(len(done), "issue", "issues")), warn: late, done: done}
	}
}

func assignCmd(b Backend, a ops.Assignment) tea.Cmd {
	return func() tea.Msg {
		var n int
		var late error
		err := b.Write(func(s *ops.Session) error {
			var e error
			if n, e = s.Assign(a); n > 0 {
				late = e
				return nil
			}
			return e
		})
		if err != nil {
			return actionMsg{err: err}
		}
		return actionMsg{info: fmt.Sprintf("%s assigned in %s (%s)", a.ID, where(a.Project, a.Env), plural(n, "finding", "findings")), warn: late}
	}
}

// catalogOf is the catalog a session offers, never nil.
func catalogOf(s *ops.Session) *catalog.Catalog {
	if s.Cfg.Catalog != nil {
		return s.Cfg.Catalog
	}
	return catalog.New(s.Cfg.Techs)
}

// startFlowCmd builds a setup flow: for a new project when name is empty,
// otherwise for editing the named one. A folder, or a Dockerfile, compose file
// or manifest, is scanned first and merged in. The flow is handed to Update
// only once it is complete, so no goroutine shares it.
func startFlowCmd(b Backend, name, dir string) tea.Cmd {
	return func() tea.Msg {
		var out flowMsg
		out.err = b.Read(func(s *ops.Session) error {
			if name == "" && strings.TrimSpace(dir) != "" { // scanned here, so the infrastructure stays known
				src, err := projectflow.ResolveSource(dir)
				if err != nil {
					return err
				}
				res, err := projectflow.ScanSource(src, catalogOf(s))
				if err != nil {
					return err
				}
				o, err := projectflow.Open(s, projectflow.Request{})
				if err != nil {
					return err
				}
				o.Flow.UseDiscovery(res.Root, res)
				out.flow, out.creating, out.name, out.note, out.infra = o.Flow, o.Creating, o.Name, scanNote(res), infraOf(res)
				return nil
			}
			o, err := projectflow.Open(s, projectflow.Request{Project: name, Folder: dir})
			if err != nil {
				return err
			}
			out.flow, out.creating, out.name, out.note = o.Flow, o.Creating, o.Name, o.Note
			return nil
		})
		return out
	}
}

// infraOf names the technologies of a scan that are infrastructure.
func infraOf(res discovery.Result) map[string]bool {
	out := map[string]bool{}
	for _, t := range res.Techs {
		if t.Infra {
			out[strings.ToLower(t.Tech)] = true
		}
	}
	return out
}

func scanNote(res discovery.Result) string {
	where := res.Root
	if res.File != "" {
		where = res.File
	}
	s := fmt.Sprintf("scanned %s: %s, %s", clean(where), plural(len(res.Techs), "technology", "technologies"), plural(len(res.Lockfiles), "lockfile", "lockfiles"))
	if res.Truncated {
		s += " (scan stopped early)"
	}
	return s
}

// scanCmd scans a folder or a file for merging into a running flow. The merge itself
// happens in Update.
func scanCmd(b Backend, dir string) tea.Cmd {
	return func() tea.Msg {
		var m scanMsg
		src, err := projectflow.ResolveSource(dir)
		if err != nil {
			m.err = err
			return m
		}
		m.err = b.Read(func(s *ops.Session) (e error) {
			m.res, e = projectflow.ScanSource(src, catalogOf(s))
			return e
		})
		return m
	}
}

// previewCmd asks ops what the edits would do, without saving.
func previewCmd(b Backend, f *form, seq int, name string, flow *setup.Flow) tea.Cmd {
	return func() tea.Msg {
		var p ops.ProjectPreview
		err := b.Read(func(s *ops.Session) (e error) {
			p, e = s.EditProject(projectflow.Change(s, flow, false))
			return e
		})
		return previewMsg{f: f, seq: seq, prev: p, err: err}
	}
}

// saveCmd writes the project file in one short write session.
func saveCmd(b Backend, f *form, name string, flow *setup.Flow) tea.Cmd {
	return func() tea.Msg {
		var p ops.ProjectPreview
		err := b.Write(func(s *ops.Session) (e error) {
			p, e = s.EditProject(projectflow.Change(s, flow, true))
			return e
		})
		return savedMsg{f: f, prev: p, err: err}
	}
}
