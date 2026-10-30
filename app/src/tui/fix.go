package tui

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/b070nd/cvewatch/app/src/ops"
	"github.com/b070nd/cvewatch/app/src/projectfile"
)

// fixState is one fix of a project problem on its way to the file: first the
// preview, then the user's yes. A problem can have several fixes; ci is the
// one shown.
type fixState struct {
	project string
	issue   projectfile.Issue
	fix     projectfile.Fix
	ci      int
	seq     int // identifies the preview request, so that the answer for another fix is dropped
	prev    *ops.ProjectPreview
	err     string
	saving  bool
	vp      viewport // scrolls the preview

	edit bool   // a change the user made in the field editor, not the fix of a problem
	land string // the project the list settles on once the change is saved (a new project)
}

func (f *fixState) waiting() bool { return f.prev == nil && f.err == "" }

type (
	fixPreviewMsg struct {
		fx   *fixState
		seq  int
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
func fixPreviewCmd(b Backend, fx *fixState, seq int, project string, edits []projectfile.Op) tea.Cmd {
	return func() tea.Msg {
		var p ops.ProjectPreview
		err := b.Read(func(s *ops.Session) (e error) {
			p, e = s.EditProject(ops.ProjectChange{Project: project, Ops: edits})
			return e
		})
		return fixPreviewMsg{fx: fx, seq: seq, prev: p, err: err}
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

// chosenFix is the fix of the problem that is selected: the first, until another is chosen.
func (st *projectsState) chosenFix(is projectfile.Issue) int {
	if st.fixOf != problemID(is) {
		return 0
	}
	return clamp(st.fixAt, 0, max(len(is.Fixes)-1, 0))
}

// chooseFix steps the selected fix of the selected problem.
func (m *app) chooseFix(forward bool) {
	p, ok := m.selectedProject()
	if !ok || len(p.Problems) == 0 {
		return
	}
	is := p.Problems[m.prj.prob.at()]
	if n := len(is.Fixes); n > 1 {
		d := n - 1
		if forward {
			d = 1
		}
		m.prj.fixOf, m.prj.fixAt = problemID(is), (m.prj.chosenFix(is)+d)%n
	}
}

func severalFixes(m *app) bool {
	p, ok := m.selectedProject()
	return ok && m.prj.prob.at() < len(p.Problems) && len(p.Problems[m.prj.prob.at()].Fixes) > 1
}

// fixChoice is whether the preview has another fix to move to.
func fixChoice(m *app) bool {
	return m.prj.fix != nil && len(m.prj.fix.issue.Fixes) > 1 && !m.prj.fix.saving
}

// stepFix previews the next or previous fix of the problem.
func (m *app) stepFix(forward bool) tea.Cmd {
	fx := m.prj.fix
	n := len(fx.issue.Fixes)
	d := n - 1
	if forward {
		d = 1
	}
	fx.ci = (fx.ci + d) % n
	fx.fix = fx.issue.Fixes[fx.ci]
	fx.prev, fx.err = nil, ""
	fx.vp.reset(0)
	fx.seq++
	m.prj.fixOf, m.prj.fixAt = problemID(fx.issue), fx.ci
	return fixPreviewCmd(m.b, fx, fx.seq, fx.project, fx.fix.Ops)
}

// startFix previews the selected fix of the selected problem.
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
	ci := m.prj.chosenFix(is)
	fx := &fixState{project: p.Name, issue: is, fix: is.Fixes[ci], ci: ci, seq: 1, vp: scrolling()}
	m.prj.fix = fx
	return fixPreviewCmd(m.b, fx, fx.seq, fx.project, fx.fix.Ops)
}

func (m *app) cancelFix() tea.Cmd {
	m.prj.fix = nil
	m.say("cancelled, nothing was saved")
	return nil
}

func (m *app) applyFix() tea.Cmd {
	fx := m.prj.fix
	if fx.prev == nil || fx.saving {
		return nil
	}
	if fx.prev.Blocked() {
		m.fail("this cannot be saved until the errors are fixed")
		return nil
	}
	cmd := m.start("saving...", "fix "+fx.project, reList, nil, fixSaveCmd(m.b, fx, fx.project, fx.fix.Ops))
	fx.saving = cmd != nil
	return cmd
}

func (m *app) fixPreviewed(msg fixPreviewMsg) {
	if msg.fx != m.prj.fix || msg.seq != msg.fx.seq {
		return // cancelled meanwhile, or the answer for a fix that is no longer shown
	}
	if msg.err != nil {
		msg.fx.err = msg.err.Error()
	}
	if msg.prev.Path != "" && msg.err == nil {
		p := msg.prev
		msg.fx.prev = &p
	}
}

func (m *app) fixSaved(msg fixSavedMsg) outcome {
	if msg.fx != m.prj.fix {
		return outcome{err: msg.err}
	}
	m.prj.fix = nil
	switch {
	case msg.err != nil:
		return outcome{err: msg.err}
	case msg.prev.Saved && msg.fx.edit:
		return outcome{note: "saved " + msg.fx.project + ": " + msg.fx.fix.Label, then: msg.fx.settle(m)}
	case msg.prev.Saved:
		return outcome{note: "fixed " + msg.fx.project + ": " + msg.fx.fix.Label}
	}
	return outcome{note: "no changes to save in " + msg.fx.project}
}

// frame is the lines above the preview and the room left for it.
func (fx *fixState) frame(w, h int) (head []string, room int) {
	if fx.edit {
		title := "Edit project: "
		if fx.land != "" {
			title = "New project: "
		}
		head = []string{stBold.Render(trunc(title+oneLine(fx.project), w)), section(trunc(oneLine(fx.fix.Label), w)), ""}
		return head, max(h-len(head)-2, 1)
	}
	label := oneLine(fx.fix.Label)
	if n := len(fx.issue.Fixes); n > 1 {
		label = fmt.Sprintf("fix %d of %d: %s", fx.ci+1, n, label)
	}
	problem := fx.issue.Level + ": " + fx.issue.Field + ": " + fx.issue.Message
	if fx.issue.Line > 0 {
		problem += fmt.Sprintf(" (line %d)", fx.issue.Line)
	}
	head = []string{stBold.Render(trunc("Fix project: "+oneLine(fx.project), w)), section(label), stMuted.Render(trunc(oneLine(problem), w)), ""}
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
	if fx.edit {
		return append(out, "", stBold.Render("Save this change?")+"  y or enter = save, esc = cancel")
	}
	return append(out, "", stBold.Render("Apply this fix?")+"  y or enter = apply, esc = cancel")
}

// editorArgv is the command that opens file in the user's $EDITOR, at line
// when the editor is known to take one and line is known.
func editorArgv(editor, file string, line int) []string {
	argv := strings.Fields(editor)
	if len(argv) == 0 {
		return nil
	}
	if line > 0 {
		switch strings.TrimSuffix(strings.ToLower(filepath.Base(argv[0])), ".exe") {
		case "vim", "nvim", "vi", "nano", "emacs", "emacsclient", "micro", "gvim", "mvim", "view":
			return append(argv, fmt.Sprintf("+%d", line), file)
		case "code", "code-insiders", "codium":
			return append(argv, "-g", fmt.Sprintf("%s:%d", file, line))
		case "subl", "sublime_text":
			return append(argv, fmt.Sprintf("%s:%d", file, line))
		}
	}
	return append(argv, file)
}

// editorLine is the line the editor opens at: that of the selected problem
// once the user is inside the project, else the top.
func (m *app) editorLine(p projectRow) int {
	if m.prj.deep && m.prj.prob.at() < len(p.Problems) {
		return p.Problems[m.prj.prob.at()].Line
	}
	return 0
}

// openEditor runs $EDITOR on the selected project's file; the TUI reloads when
// it returns. Inside a project it opens the file at the line of the problem.
func (m *app) openEditor() tea.Cmd {
	p, ok := m.selectedProject()
	switch {
	case !ok:
		return nil
	case !p.HasFile:
		m.fail("project " + p.Name + " has no file under config/projects")
		return nil
	}
	editor := os.Getenv("EDITOR")
	if len(strings.Fields(editor)) == 0 {
		m.fail("$EDITOR is not set; the file is " + p.File)
		return nil
	}
	id, ok := m.begin("editing "+oneLine(p.Name)+"...", "editor", reList|reDetail, nil)
	if !ok {
		return nil
	}
	argv := editorArgv(editor, p.File, m.editorLine(p))
	cmd := exec.Command(argv[0], argv[1:]...)
	return tea.ExecProcess(cmd, func(err error) tea.Msg { return opMsg{id: id, msg: editedMsg{err: err}} })
}
