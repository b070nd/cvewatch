package tui

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/ops"
)

// lifeState is a change to a whole project (rename, duplicate, delete,
// disable, enable) on its way to being applied: first the consequences, then
// the user's confirmation.
type lifeState struct {
	req    ops.LifecycleRequest
	deep   bool // started inside the project, so a rename lands inside it again
	root   string
	prev   *ops.LifecyclePreview
	seq    int // identifies the preview request, so that a stale answer is dropped
	saving bool
	fail   string   // why the last attempt failed; it stays until the user leaves
	vp     viewport // scrolls the consequences
}

type (
	lifePreviewMsg struct {
		life *lifeState
		seq  int
		prev ops.LifecyclePreview
		err  error
	}
	lifeAppliedMsg struct {
		life *lifeState
		prev ops.LifecyclePreview
		err  error
	}
)

func lifePreviewCmd(b Backend, lf *lifeState, seq int, req ops.LifecycleRequest) tea.Cmd {
	return func() tea.Msg {
		var p ops.LifecyclePreview
		err := b.Read(func(s *ops.Session) (e error) { p, e = s.ProjectLifecycle(req); return e })
		return lifePreviewMsg{life: lf, seq: seq, prev: p, err: err}
	}
}

func lifeApplyCmd(b Backend, lf *lifeState, req ops.LifecycleRequest) tea.Cmd {
	return func() tea.Msg {
		var p ops.LifecyclePreview
		err := b.Write(func(s *ops.Session) (e error) { p, e = s.ProjectLifecycle(req); return e })
		return lifeAppliedMsg{life: lf, prev: p, err: err}
	}
}

// lifeError says why a change was refused; a refused access is said as that.
func lifeError(err error) string {
	if errors.Is(err, ops.ErrDenied) {
		return "access refused: " + strings.TrimPrefix(err.Error(), ops.ErrDenied.Error()+": ")
	}
	return err.Error()
}

var verbWords = map[ops.LifecycleVerb]string{
	ops.VerbRename: "Rename", ops.VerbDuplicate: "Duplicate", ops.VerbDelete: "Delete",
	ops.VerbDisable: "Disable", ops.VerbEnable: "Enable",
}

// startLife begins a lifecycle change of the selected project: it asks for a
// name where one is needed, then shows the consequences.
func (m *app) startLife(verb ops.LifecycleVerb) tea.Cmd {
	p, ok := m.selectedProject()
	if !ok {
		return nil
	}
	if verb == ops.VerbDisable && p.Disabled {
		verb = ops.VerbEnable
	}
	switch {
	case verb == ops.VerbEnable && !p.Disabled:
		m.fail(p.Name + " is not disabled")
		return nil
	case p.Disabled && (verb == ops.VerbRename || verb == ops.VerbDuplicate):
		m.fail(p.Name + " is disabled; press Z to enable it first")
		return nil
	case p.Broken != "" && (verb == ops.VerbRename || verb == ops.VerbDuplicate):
		m.fail("the file of " + p.Name + " does not load; press E to fix it first")
		return nil
	}
	switch verb {
	case ops.VerbRename:
		f := field{label: "New name"}
		f.in.set(p.Name)
		m.prm = &prompt{kind: pkRename, title: oneLine("Rename project " + p.Name), fields: []field{f}, project: p.Name,
			hint: "letters, digits, - and _; findings and access rules follow the new name"}
	case ops.VerbDuplicate:
		f := field{label: "Name of the copy"}
		f.in.set(p.Name + "-copy")
		m.prm = &prompt{kind: pkDuplicate, title: oneLine("Duplicate project " + p.Name), fields: []field{f}, project: p.Name,
			hint: "the copy has the same technologies and lockfiles; it is in no access rule"}
	default:
		return m.previewLife(ops.LifecycleRequest{Verb: verb, Project: p.Name}, nil)
	}
	return nil
}

// previewLife asks ops for the consequences of req. A refusal keeps the prompt
// that asked open with the reason.
func (m *app) previewLife(req ops.LifecycleRequest, prm *prompt) tea.Cmd {
	if m.data == nil {
		return nil
	}
	lf := &lifeState{req: req, deep: m.prj.deep, root: m.data.Root, seq: 1, vp: scrolling()}
	return m.start("checking...", "life", 0, prm, lifePreviewCmd(m.b, lf, lf.seq, req))
}

func (m *app) lifePreviewed(msg lifePreviewMsg) outcome {
	lf, cur := msg.life, m.prj.life
	if (cur != nil && cur != lf) || (cur == lf && msg.seq != lf.seq) {
		return outcome{} // another change was started meanwhile, or this is an old answer
	}
	if msg.err != nil {
		if cur == lf {
			lf.fail = lifeError(msg.err)
		}
		return outcome{err: errors.New(lifeError(msg.err))}
	}
	p := msg.prev
	lf.prev, lf.fail = &p, ""
	m.prj.life = lf
	m.prj.ed = nil
	return outcome{}
}

func lifeIdle(m *app) bool { return m.prj.life != nil && !m.prj.life.saving }

func lifeDeleting(m *app) bool {
	return lifeIdle(m) && m.prj.life.req.Verb == ops.VerbDelete
}

func (m *app) cancelLife() tea.Cmd {
	m.prj.life = nil
	m.say("cancelled, nothing was changed")
	return nil
}

// toggleClose flips whether a delete also closes the open findings, and asks again.
func (m *app) toggleClose() tea.Cmd {
	lf := m.prj.life
	lf.req.CloseFindings = !lf.req.CloseFindings
	lf.prev, lf.fail = nil, ""
	lf.seq++
	return m.start("checking...", "life", 0, nil, lifePreviewCmd(m.b, lf, lf.seq, lf.req))
}

// confirmLife is enter or y on the consequences. A delete asks for the name of
// the project first; the others go ahead.
func (m *app) confirmLife() tea.Cmd {
	lf := m.prj.life
	if lf.prev == nil || lf.saving {
		return nil
	}
	if lf.req.Verb == ops.VerbDelete {
		m.prm = &prompt{kind: pkDelete, title: oneLine("Delete " + lf.req.Project + "? Type its name to confirm"), project: lf.req.Project,
			fields: []field{{label: "Name"}}, hint: "the file moves to the project backups; nothing else is erased"}
		return nil
	}
	return m.applyLife(nil)
}

func (m *app) applyLife(prm *prompt) tea.Cmd {
	lf := m.prj.life
	req := lf.req
	req.Apply, req.Confirm = true, true // the user has read the consequences
	lf.fail = ""
	cmd := m.start("applying...", "life", reList, prm, lifeApplyCmd(m.b, lf, req))
	lf.saving = cmd != nil
	return cmd
}

func (m *app) lifeApplied(msg lifeAppliedMsg) outcome {
	lf := msg.life
	if lf != m.prj.life {
		return outcome{err: msg.err}
	}
	lf.saving = false
	if msg.err != nil {
		lf.fail = lifeError(msg.err)
		return outcome{err: errors.New(lf.fail)}
	}
	m.prj.life, m.prj.ed = nil, nil
	req := lf.req
	var note string
	land := &landing{project: req.Project}
	switch req.Verb {
	case ops.VerbRename:
		note = fmt.Sprintf("renamed %s to %s", req.Project, req.NewName)
		land = &landing{project: req.NewName, deep: lf.deep}
		if m.scope == req.Project { // the scope follows the project
			m.scope = req.NewName
		}
	case ops.VerbDuplicate:
		note = fmt.Sprintf("duplicated %s as %s", req.Project, req.NewName)
		land = &landing{project: req.NewName}
	case ops.VerbDelete:
		note = fmt.Sprintf("deleted %s; its file is in the project backups", req.Project)
		land = &landing{}
	case ops.VerbDisable:
		note = "disabled " + req.Project
	default:
		note = "enabled " + req.Project
	}
	return outcome{note: note, then: loadLandCmd(m.b, land)}
}

// ---- drawing ----

func (lf *lifeState) title() string {
	r := lf.req
	switch r.Verb {
	case ops.VerbRename:
		return fmt.Sprintf("Rename project: %s to %s", oneLine(r.Project), oneLine(r.NewName))
	case ops.VerbDuplicate:
		return fmt.Sprintf("Duplicate project: %s as %s", oneLine(r.Project), oneLine(r.NewName))
	}
	return verbWords[r.Verb] + " project: " + oneLine(r.Project)
}

func (lf *lifeState) frame(w, h int) (head []string, room int) {
	head = []string{stBold.Render(trunc(lf.title(), w)), section("Consequences"), ""}
	return head, max(h-len(head)-3, 1)
}

// shown is a path as the preview shows it: under the app folder when it is in it.
func (lf *lifeState) shown(p string) string {
	if p == "" {
		return ""
	}
	if rel, err := filepath.Rel(lf.root, p); err == nil && !strings.HasPrefix(rel, ".."+string(filepath.Separator)+".."+string(filepath.Separator)+"..") {
		p = rel
	}
	return filepath.ToSlash(p)
}

var statusOrder = []model.Status{model.StatusOpen, model.StatusFixed, model.StatusIgnored, model.StatusNotAffected}

func (lf *lifeState) body(w int) []string {
	var body []string
	switch {
	case lf.prev == nil && lf.fail == "":
		body = append(body, stMuted.Render("Working out the consequences..."))
	case lf.prev == nil:
	default:
		body = append(body, lf.consequences(w)...)
	}
	if lf.saving {
		body = append(body, "", stMuted.Render("Applying..."))
	}
	if lf.fail != "" {
		body = append(body, "")
		body = append(body, indentWrap(stErr.Render("error: "), lf.fail, w)...)
	}
	return body
}

func (lf *lifeState) consequences(w int) []string {
	p := lf.prev
	var body []string
	f := p.Findings
	switch {
	case f.Total == 0:
		body = append(body, "Findings: none")
	default:
		var parts []string
		for _, st := range statusOrder {
			if n := f.ByStatus[st]; n > 0 {
				parts = append(parts, fmt.Sprintf("%d %s", n, st))
			}
		}
		body = append(body, "Findings: "+plural(f.Total, "finding", "findings")+" ("+strings.Join(parts, ", ")+")")
	}
	if lf.req.Verb == ops.VerbDelete {
		box := "[ ]"
		if lf.req.CloseFindings {
			box = "[x]"
		}
		body = append(body, box+" close the open findings (mark them ignored)   c toggles")
	}
	if len(p.Access) == 0 {
		body = append(body, "Access rules: none name this project")
	} else {
		body = append(body, "Access rules:")
		for _, a := range p.Access {
			what := "loses the project"
			if a.Action == "rename" {
				what = "follows the new name"
			}
			left := "no project left"
			if len(a.Left) > 0 {
				left = "projects after: " + strings.Join(a.Left, ", ")
			}
			body = append(body, indentWrap("  ", fmt.Sprintf("%s: %s, %s", oneLine(a.Actor), what, left), w)...)
		}
	}
	body = append(body, "Files:")
	for _, fc := range p.Files {
		text := fc.Action
		if len(text) < 8 {
			text += strings.Repeat(" ", 8-len(text))
		}
		text += " " + lf.shown(fc.From)
		if fc.To != "" {
			text += " -> " + lf.shown(fc.To)
		}
		body = append(body, indentWrap("  ", text, w)...)
	}
	if len(p.Warnings) > 0 {
		body = append(body, "Warnings:")
		for _, wn := range p.Warnings {
			body = append(body, indentWrap("  ! ", oneLine(wn), w)...)
		}
	}
	if p.RequiresConfirm {
		body = append(body, stErr.Render("This is destructive: it needs your confirmation."))
	}
	return body
}

func (lf *lifeState) layout(w, h int) {
	_, room := lf.frame(w, h)
	lf.vp.refit(len(lf.body(w)), nil)
	lf.vp.fit(room)
}

func (lf *lifeState) view(w, h int) []string {
	out, room := lf.frame(w, h)
	body := lf.body(w)
	start, end := lf.vp.window(room)
	start, end = min(start, len(body)), min(end, len(body))
	out = append(out, body[start:end]...)
	name := oneLine(lf.req.Project)
	switch {
	case lf.req.Verb == ops.VerbDelete:
		return append(out, "", stBold.Render(trunc("Delete "+name+"?", w)), stMuted.Render(trunc("  enter or y = go on (you then type the name)   c = close open findings too   esc = cancel", w)))
	}
	return append(out, "", stBold.Render(trunc(verbWords[lf.req.Verb]+" "+name+"?", w)), stMuted.Render(trunc("  y or enter = apply   esc = cancel", w)))
}
