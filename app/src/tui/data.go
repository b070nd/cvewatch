package tui

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/b070nd/cvewatch/app/src/catalog"
	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/discovery"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/ops"
	"github.com/b070nd/cvewatch/app/src/priority"
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
	ByProject  map[string][]query.Issue // the open issues of each project, most urgent first, read project by project so that no row mixes projects
	Status     status.Report
	Violations []priority.Violation
	Projects   []projectRow
	Warnings   []string       // parts that could not be read; the rest is still shown
	Horizon    config.Horizon // which publication dates the daemon judges and alerts

	Stamp      string        // the files the findings are judged from, as they were when read (see inputStamp)
	Stale      ops.Staleness // whether the findings were judged against something else
	StaleKnown bool          // Stale was read; false when it could not be
}

// projectRow is a project of the workspace with what only this screen works out.
type projectRow struct {
	ops.WorkspaceProject
	Unjudged bool   // its changes are not judged against the stored findings yet
	Updates  string // when it is refreshed: every 1h · next 14:05, paused or manual
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
func loadSnapshot(s *ops.Session) (*snapshot, error) { return loadSnapshotMemo(s, nil) }

// loadSnapshotMemo is loadSnapshot that asks the memo for the staleness, which
// reads lockfiles, so it is only worked out again when the files changed.
// What is in the workspace, and who may see it, is decided by ops.
func loadSnapshotMemo(s *ops.Session, memo *staleMemo) (*snapshot, error) {
	w, err := s.Workspace()
	if err != nil {
		return nil, err // access denied shows here
	}
	sn := &snapshot{At: w.At, Root: w.Root, ByProject: w.Issues, Status: w.Status, Violations: w.Violations, Horizon: w.Horizon,
		Stamp: inputStamp(s.Cfg)}
	for _, warning := range w.Warnings {
		sn.Warnings = append(sn.Warnings, oneLine(warning))
	}
	for _, p := range w.Projects {
		sn.Projects = append(sn.Projects, projectRow{WorkspaceProject: p})
	}
	sn.Stale, sn.StaleKnown = memo.staleness(s, sn.Stamp)
	sn.markUnjudged()
	sn.markUpdates()
	return sn, nil
}

// markUpdates says in words when each project is refreshed.
func (sn *snapshot) markUpdates() {
	for i := range sn.Projects {
		p := &sn.Projects[i]
		if j := slices.IndexFunc(sn.Status.Projects, func(r status.ProjectRow) bool { return r.Name == p.Name }); j >= 0 {
			every, next := sn.Status.Schedule(sn.Status.Projects[j])
			p.Updates = strings.TrimSuffix(every+" · "+next, " · ")
		}
	}
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
		page  *detail // the page it was read for; nil for any
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

func loadCmd(b Backend) tea.Cmd { return loadLandCmd(b, nil, nil) }

// loadLandCmd reads the snapshot and, once it is in, puts the Projects screen
// on a project (see landing).
func loadLandCmd(b Backend, memo *staleMemo, land *landing) tea.Cmd {
	return func() tea.Msg {
		var sn *snapshot
		err := b.Read(func(s *ops.Session) (e error) { sn, e = loadSnapshotMemo(s, memo); return e })
		return dataMsg{snap: sn, err: err, land: land}
	}
}

// detailCmd reads the page of an issue. Reading the audit trail for its
// history makes this the dearest read, so it runs once per open and refresh.
func detailCmd(b Backend, id string, f query.Filter, page *detail) tea.Cmd {
	return func() tea.Msg {
		m := detailMsg{id: id, page: page}
		m.err = b.Read(func(s *ops.Session) (e error) {
			full, e := s.IssueDetailIn(id, f)
			if e != nil {
				return e
			}
			if ps := projectsOf(full.Issue); len(ps) > 1 {
				return fmt.Errorf("%s is open in several projects here (%s): choose the project first (C), so that the page shows one", id, strings.Join(ps, ", "))
			}
			m.is, m.det, m.md = full.Issue, &full.Detail, full.Markdown
			ex, xe := s.ExplainIn(id, f)
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

// bulkCmd applies the changes as one operation of ops: it stops at the first
// refusal, and what landed before it stays.
func bulkCmd(b Backend, cs []ops.Change) tea.Cmd {
	return func() tea.Msg {
		var res ops.BulkResult
		err := b.Write(func(s *ops.Session) (err error) {
			res, err = s.ResolveAll(cs)
			return err
		})
		// an issue of a project is done when every change asked for it landed
		left := map[string]int{}
		for _, c := range cs {
			left[c.Project+"\x00"+c.ID]++
		}
		var done []string
		for _, c := range res.Done {
			key := c.Project + "\x00" + c.ID
			if left[key]--; left[key] == 0 {
				done = append(done, key)
			}
		}
		if err != nil {
			return bulkMsg{err: err, done: done}
		}
		return bulkMsg{info: fmt.Sprintf("%s: %s in %s", changeWords[cs[0].Status], plural(res.Findings, "finding", "findings"), plural(len(done), "issue", "issues")), warn: res.ReportErr, done: done}
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
