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
	scroll  int
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
	return m.data.Projects[clamp(m.prj.cursor, 0, len(m.data.Projects)-1)], true
}

// startFix previews the first fix of the selected problem.
func (m *app) startFix() tea.Cmd {
	p, ok := m.selectedProject()
	if !ok || len(p.Problems) == 0 {
		m.fail("no problems to fix here")
		return nil
	}
	is := p.Problems[clamp(m.prj.issue, 0, len(p.Problems)-1)]
	if len(is.Fixes) == 0 {
		m.fail("no automatic fix for this problem; press o to edit the file")
		return nil
	}
	fx := &fixState{project: p.Name, issue: is, fix: is.Fixes[0]}
	m.prj.fix = fx
	return fixPreviewCmd(m.b, fx, fx.project, fx.fix.Ops)
}

func (m *app) fixKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	fx := m.prj.fix
	if fx.saving {
		return m, nil
	}
	switch s := k.String(); s {
	case "esc", "n":
		m.prj.fix = nil
		m.say("cancelled, nothing was saved")
	case "y", "Y":
		if fx.prev == nil {
			return m, nil
		}
		if fx.prev.Blocked() {
			m.fail("this cannot be saved until the errors are fixed")
			return m, nil
		}
		fx.saving = true
		m.busy = "saving..."
		return m, fixSaveCmd(m.b, fx, fx.project, fx.fix.Ops)
	case "up", "k":
		fx.scroll = max(0, fx.scroll-1)
	case "down", "j":
		fx.scroll++
	case "pgup":
		fx.scroll = max(0, fx.scroll-m.bodyH())
	case "pgdown":
		fx.scroll += m.bodyH()
	case "q":
		return m, tea.Quit
	}
	return m, nil
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

func (fx *fixState) view(w, h int) []string {
	out := []string{stBold.Render(trunc("Fix project: "+oneLine(fx.project), w)),
		section(oneLine(fx.fix.Label)),
		stMuted.Render(trunc(oneLine(fx.issue.Level+": "+fx.issue.Field+": "+fx.issue.Message), w)), ""}
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
	avail := max(h-len(out)-2, 1)
	fx.scroll = clamp(fx.scroll, 0, len(body)-avail)
	out = append(out, body[fx.scroll:min(fx.scroll+avail, len(body))]...)
	return append(out, "", stBold.Render("Apply this fix?")+"  y = apply, n or esc = cancel")
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
