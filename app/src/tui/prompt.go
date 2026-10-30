package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/ops"
	"github.com/b070nd/cvewatch/app/src/projectfile"
)

type promptKind int

const (
	pkStatus    promptKind = iota // a note for a status change
	pkAssign                      // owner, due date, ticket
	pkPath                        // a folder to scan
	pkBulk                        // a note for a status change of the selected issues
	pkEvidence                    // a note and a link attached to an environment
	pkEdit                        // the value of one field of a project file
	pkNew                         // a project made from a name, without scanning a folder
	pkRename                      // the new name of a project
	pkDuplicate                   // the name of the copy of a project
	pkDelete                      // the name of the project to delete, typed to confirm
)

type field struct {
	label string
	in    input
}

// prompt is a small inline form shown at the bottom of the screen: one or a
// few single-line fields. Whatever is typed goes to ops unchecked; ops
// decides what is valid. The prompt stays open while the write runs, and
// comes back with its values and the reason when ops refuses.
type prompt struct {
	kind   promptKind
	title  string
	hint   string
	fields []field
	idx    int
	box    *folderBox // pkPath

	submitting bool   // the write is in flight; the prompt stays open until it ends
	problem    string // why the last submit was refused

	change ops.Change     // pkStatus
	assign ops.Assignment // pkAssign
	bulk   model.Status   // pkBulk
	attach ops.Attachment // pkEvidence

	project string                                                                // pkEdit, pkRename, pkDuplicate, pkDelete: the project
	known   []projectfile.Issue                                                   // pkEdit: the problems the file had before
	build   func(vals []string) (label string, edits []projectfile.Op, err error) // pkEdit
}

func (p *prompt) view(w, h int) []string {
	lines := []string{stBold.Render(trunc(p.title, w))}
	if p.box != nil {
		bl := p.box.view(w, h)
		lines = append(lines, bl[:2]...)
		lines = append(lines, stMuted.Render(trunc("  "+p.hint, w)))
		lines = append(lines, p.status(w)...)
		return append(lines, bl[2:]...)
	}
	lw := 0
	for _, f := range p.fields {
		lw = max(lw, width(f.label))
	}
	for i, f := range p.fields {
		mark := "  "
		if i == p.idx {
			mark = "> "
		}
		lines = append(lines, mark+pad(f.label, lw)+": "+p.fields[i].in.view(w-lw-6, i == p.idx))
	}
	if p.hint != "" {
		lines = append(lines, stMuted.Render(trunc("  "+p.hint, w)))
	}
	return append(lines, p.status(w)...)
}

// status is the line about the last submit: still running, or refused.
func (p *prompt) status(w int) []string {
	switch {
	case p.submitting:
		return []string{stMuted.Render("  working...")}
	case p.problem != "":
		return []string{stErr.Render("  problem: ") + trunc(p.problem, w-12)}
	}
	return nil
}

// startStatus asks for a note, then changes the status of the selected
// environment of the open issue (the whole project when whole is set).
// not-affected is a human assertion, so its label says a reason is required;
// ops enforces it.
func (m *app) startStatus(st model.Status, whole bool) {
	d := m.fnd.det
	if d == nil || d.loading || d.err != nil || len(d.is.Targets) == 0 {
		m.fail("nothing selected: open an issue with an environment first")
		return
	}
	t := d.is.Targets[d.sel.at()]
	c := ops.Change{ID: d.is.ID, Project: t.Project, Env: t.Env, Status: st}
	if whole {
		c.Env = ""
	}
	label := "Note (optional)"
	if st == model.StatusNotAffected {
		label = "Reason (required)"
	}
	title := fmt.Sprintf("%s: %s", changeWords[st], where(c.Project, c.Env))
	m.prm = &prompt{kind: pkStatus, title: oneLine(c.ID + " " + title), change: c, fields: []field{{label: label}}, hint: noteHint(st)}
}

// noteHint is what the prompt says about the note: enter saves at once unless
// the status is a human assertion that needs its reason.
func noteHint(st model.Status) string {
	if st == model.StatusNotAffected {
		return "say why it does not apply here; enter saves, an empty reason is refused"
	}
	return "enter saves now; the note is optional (a merge request or ticket link is a good one)"
}

// bulkChanges are the changes that give every selected issue the status st:
// on its open environments, or on the closed ones when reopening.
func (m *app) bulkChanges(st model.Status, note string) []ops.Change {
	var out []ops.Change
	for _, is := range m.dataIssues() {
		if !m.fnd.sel[is.ID] {
			continue
		}
		for _, t := range is.Targets {
			if (st == model.StatusOpen) == (t.Status == model.StatusOpen) {
				continue
			}
			out = append(out, ops.Change{ID: is.ID, Project: t.Project, Env: t.Env, Status: st, Note: note})
		}
	}
	return out
}

// startBulk asks for one note for the status change of every selected issue.
func (m *app) startBulk(st model.Status) {
	n := len(m.fnd.sel)
	cs := m.bulkChanges(st, "")
	if n == 0 || len(cs) == 0 {
		m.fail("nothing to change in the selected issues")
		return
	}
	label := "Note (optional)"
	if st == model.StatusNotAffected {
		label = "Reason (required)"
	}
	title := fmt.Sprintf("%s, %s: %s", plural(n, "issue", "issues"), plural(len(cs), "finding", "findings"), changeWords[st])
	m.prm = &prompt{kind: pkBulk, bulk: st, title: title, fields: []field{{label: label}}, hint: noteHint(st)}
}

// startEvidence asks for a note and a link to attach to the selected
// environment. ops decides whether they are acceptable.
func (m *app) startEvidence() {
	d := m.fnd.det
	if d == nil || d.loading || d.err != nil || len(d.is.Targets) == 0 {
		m.fail("nothing selected: open an issue with an environment first")
		return
	}
	t := d.is.Targets[d.sel.at()]
	a := ops.Attachment{ID: d.is.ID, Project: t.Project, Env: t.Env}
	m.prm = &prompt{kind: pkEvidence, attach: a, title: oneLine("Add evidence to " + a.ID + " in " + where(a.Project, a.Env)),
		hint:   "a note, a link or both; the link must be a plain http(s) address",
		fields: []field{{label: "Note"}, {label: "Link"}}}
}

func (m *app) startAssign(whole bool) {
	d := m.fnd.det
	if d == nil || d.loading || d.err != nil || len(d.is.Targets) == 0 {
		m.fail("nothing selected: open an issue with an environment first")
		return
	}
	t := d.is.Targets[d.sel.at()]
	a := ops.Assignment{ID: d.is.ID, Project: t.Project, Env: t.Env}
	if whole {
		a.Env = ""
	}
	p := &prompt{kind: pkAssign, assign: a, title: oneLine("Assign " + a.ID + " in " + where(a.Project, a.Env)),
		hint:   "empty keeps a value, - clears it; due is YYYY-MM-DD",
		fields: []field{{label: "Owner"}, {label: "Due"}, {label: "Ticket"}}}
	p.fields[0].in.set(t.Owner)
	if !t.Due.IsZero() {
		p.fields[1].in.set(day(t.Due))
	}
	p.fields[2].in.set(t.Ticket)
	m.prm = p
}

func (m *app) startPath() {
	what := "Scan a folder for a new project"
	if m.frm != nil {
		what = "Scan a folder and merge what it finds into this project"
	}
	m.prm = &prompt{kind: pkPath, title: what, hint: "a repository or monorepo folder; nothing in it is executed",
		box: newFolderBox()}
}

// promptEnter moves to the next field, or submits from the last one.
func (m *app) promptEnter() tea.Cmd {
	p := m.prm
	if p.box == nil && p.idx < len(p.fields)-1 {
		p.idx++
		return nil
	}
	return m.promptSubmit()
}

func (m *app) promptSubmit() tea.Cmd {
	p := m.prm
	if p.submitting {
		return nil
	}
	val := func(i int) string { return strings.TrimSpace(p.fields[i].in.String()) }
	switch p.kind {
	case pkStatus:
		c := p.change
		c.Note = val(0)
		return m.start("saving...", "status "+c.ID+" "+where(c.Project, c.Env), reList|reDetail, p, resolveCmd(m.b, c))
	case pkBulk:
		cs := m.bulkChanges(p.bulk, val(0))
		if len(cs) == 0 {
			p.problem = "nothing left to change in the selected issues"
			return nil
		}
		return m.start("saving...", "bulk", reList|reDetail, p, bulkCmd(m.b, cs))
	case pkEvidence:
		a := p.attach
		a.Note, a.URL = val(0), val(1)
		return m.start("saving...", "evidence "+a.ID+" "+where(a.Project, a.Env), reDetail, p, attachCmd(m.b, a))
	case pkAssign:
		a := p.assign
		a.Owner, a.Due, a.Ticket = val(0), val(1), val(2)
		return m.start("saving...", "assign "+a.ID+" "+where(a.Project, a.Env), reList|reDetail, p, assignCmd(m.b, a))
	case pkEdit:
		vals := make([]string, len(p.fields))
		for i := range vals {
			vals[i] = val(i)
		}
		label, edits, err := p.build(vals)
		if err != nil {
			p.problem = err.Error()
			return nil
		}
		return m.previewEdit(p.project, p.known, label, edits, "", p)
	case pkNew:
		return m.submitNew(p, val(0), val(1))
	case pkRename, pkDuplicate:
		verb := ops.VerbRename
		if p.kind == pkDuplicate {
			verb = ops.VerbDuplicate
		}
		if val(0) == "" {
			p.problem = "give the new name"
			return nil
		}
		return m.previewLife(ops.LifecycleRequest{Verb: verb, Project: p.project, NewName: val(0)}, p)
	case pkDelete:
		if val(0) != p.project || m.prj.life == nil {
			p.problem = "type the name of the project exactly, " + p.project + ", to delete it"
			return nil
		}
		return m.applyLife(p)
	}
	path := p.box.chosen()
	if path == "" {
		p.problem = "no folder given"
		m.fail(p.problem)
		return nil
	}
	if m.frm != nil {
		return m.start("scanning...", "scan", 0, p, scanCmd(m.b, path))
	}
	return m.start("scanning...", "flow", 0, p, startFlowCmd(m.b, "", path))
}
