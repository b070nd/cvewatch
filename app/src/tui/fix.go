package tui

import (
	"os"
	"os/exec"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/b070nd/cvewatch/app/src/ops"
	"github.com/b070nd/cvewatch/app/src/projectfile"
)

// fixState is the first fix of a project problem on its way to the file:
// first the preview, then the user's yes.
type fixState struct {
	project string
	issue   projectfile.Issue
	fix     projectfile.Fix
	prev    *ops.ProjectPreview
	err     string
	saving  bool
	vp      viewport // scrolls the preview
}

func (f *fixState) waiting() bool { return f.prev == nil && f.err == "" }

type (
	fixPreviewMsg struct {
		fx   *fixState
		prev ops.ProjectPreview
		err  error
	}
	fixSavedMsg struct {
		fx   *fixState
		prev ops.ProjectPreview
		err  error
	}
	editedMsg struct{ err error }
)

// The commands get plain values, never the fixState: Update owns that.
func fixPreviewCmd(b Backend, fx *fixState, project string, edits []projectfile.Op) tea.Cmd {
	return func() tea.Msg {
		var p ops.ProjectPreview
		err := b.Read(func(s *ops.Session) (e error) {
			p, e = s.EditProject(ops.ProjectChange{Project: project, Ops: edits})
			return e
		})
		return fixPreviewMsg{fx: fx, prev: p, err: err}
	}
}

func fixSaveCmd(b Backend, fx *fixState, project string, edits []projectfile.Op) tea.Cmd {
	return func() tea.Msg {
		var p ops.ProjectPreview
		err := b.Write(func(s *ops.Session) (e error) {
			p, e = s.EditProject(ops.ProjectChange{Project: project, Ops: edits, Save: true})
			return e
		})
		return fixSavedMsg{fx: fx, prev: p, err: err}
	}
}

// selectedProject is the project row under the cursor.
func (m *app) selectedProject() (projectRow, bool) {
	if m.data == nil || len(m.data.Projects) == 0 {
		return projectRow{}, false
	}
	return m.data.Projects[m.prj.proj.at()], true
}

// startFix previews the first fix of the selected problem.
func (m *app) startFix() tea.Cmd {
	p, ok := m.selectedProject()
	if !ok || len(p.Problems) == 0 {
		m.fail("no problems to fix here")
		return nil
	}
	is := p.Problems[m.prj.prob.at()]
	if len(is.Fixes) == 0 {
		m.fail("no automatic fix for this problem; press E to edit the file")
		return nil
	}
	fx := &fixState{project: p.Name, issue: is, fix: is.Fixes[0], vp: scrolling()}
	m.prj.fix = fx
	return fixPreviewCmd(m.b, fx, fx.project, fx.fix.Ops)
}

func (m *app) cancelFix() tea.Cmd {
	m.prj.fix = nil
	m.say("cancelled, nothing was saved")
	return nil
}

func (m *app) applyFix() tea.Cmd {
	fx := m.prj.fix
	if fx.prev == nil {
		return nil
	}
	if fx.prev.Blocked() {
		m.fail("this cannot be saved until the errors are fixed")
		return nil
	}
	fx.saving = true
	m.busy = "saving..."
	return fixSaveCmd(m.b, fx, fx.project, fx.fix.Ops)
}

func (m *app) fixPreviewed(msg fixPreviewMsg) {
	if msg.fx != m.prj.fix {
		return // cancelled meanwhile
	}
	if msg.err != nil {
		msg.fx.err = msg.err.Error()
	}
	if msg.prev.Path != "" && msg.err == nil {
		p := msg.prev
		msg.fx.prev = &p
	}
}

func (m *app) fixSaved(msg fixSavedMsg) (tea.Model, tea.Cmd) {
	if msg.fx != m.prj.fix {
		return m, nil
	}
	m.busy, m.prj.fix = "", nil
	switch {
	case msg.err != nil:
		m.fail(msg.err.Error())
	case msg.prev.Saved:
		m.say("fixed " + msg.fx.project + ": " + msg.fx.fix.Label)
	default:
		m.say("no changes to save in " + msg.fx.project)
	}
	return m, m.reload()
}

// frame is the lines above the preview and the room left for it.
func (fx *fixState) frame(w, h int) (head []string, room int) {
	head = []string{stBold.Render(trunc("Fix project: "+oneLine(fx.project), w)),
		section(oneLine(fx.fix.Label)),
		stMuted.Render(trunc(oneLine(fx.issue.Level+": "+fx.issue.Field+": "+fx.issue.Message), w)), ""}
	return head, max(h-len(head)-2, 1)
}

func (fx *fixState) body(w int) []string {
	var body []string
	switch {
	case fx.saving:
		body = append(body, stMuted.Render("Saving..."))
	case fx.waiting():
		body = append(body, stMuted.Render("Loading the preview..."))
	}
	if fx.err != "" {
		body = append(body, stErr.Render("error: ")+trunc(oneLine(fx.err), w-7))
	}
	if fx.prev != nil {
		body = append(body, previewRows(fx.prev, w)...)
	}
	return body
}

func (fx *fixState) layout(w, h int) {
	_, room := fx.frame(w, h)
	fx.vp.refit(len(fx.body(w)), nil)
	fx.vp.fit(room)
}

func (fx *fixState) view(w, h int) []string {
	out, room := fx.frame(w, h)
	body := fx.body(w)
	start, end := fx.vp.window(room)
	start, end = min(start, len(body)), min(end, len(body))
	out = append(out, body[start:end]...)
	return append(out, "", stBold.Render("Apply this fix?")+"  y or enter = apply, esc = cancel")
}

// openEditor runs $EDITOR on the selected project's file; the TUI reloads when it returns.
func (m *app) openEditor() tea.Cmd {
	p, ok := m.selectedProject()
	switch {
	case !ok:
		return nil
	case !p.HasFile:
		m.fail("project " + p.Name + " has no file under config/projects")
		return nil
	}
	ed := strings.Fields(os.Getenv("EDITOR"))
	if len(ed) == 0 {
		m.fail("$EDITOR is not set; the file is " + p.File)
		return nil
	}
	cmd := exec.Command(ed[0], append(ed[1:], p.File)...)
	return tea.ExecProcess(cmd, func(err error) tea.Msg { return editedMsg{err: err} })
}
