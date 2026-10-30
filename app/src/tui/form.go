package tui

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/b070nd/cvewatch/app/src/ops"
	"github.com/b070nd/cvewatch/app/src/setup"
)

// form renders one setup.Step at a time. The flow decides what is asked, in
// what order and what is valid; the form only draws the step, collects an
// answer and hands it back.
type form struct {
	flow     *setup.Flow
	creating bool
	existing string // the project being edited
	step     setup.Step

	in  input           // KindText
	vp  viewport        // KindChoice and KindMulti: the option rows
	sel map[string]bool // KindMulti: the ticked values
	rev viewport        // review: the scrolling diff

	prev    *ops.ProjectPreview // review: what saving would do
	prevErr string
	seq     int // identifies the preview request, so a stale answer is dropped
	saving  bool
}

func newForm(fl *setup.Flow, creating bool, name string) *form {
	f := &form{flow: fl, creating: creating, existing: name, rev: scrolling()}
	f.load()
	return f
}

// load shows the flow's current step with the flow's own defaults.
func (f *form) load() {
	f.step = f.flow.Current()
	f.sel = map[string]bool{}
	f.vp.reset(len(f.step.Options))
	f.rev.reset(0)
	switch f.step.Kind {
	case setup.KindText:
		f.in.set(f.step.Default)
	case setup.KindChoice:
		for i, o := range f.step.Options {
			if o.Value == f.step.Default {
				f.vp.to(i)
			}
		}
	case setup.KindMulti:
		for _, o := range f.step.Options {
			if o.Selected {
				f.sel[o.Value] = true
			}
		}
	}
	if f.step.ID != "review" {
		f.prev, f.prevErr = nil, ""
	}
}

// enter starts what a freshly shown step needs: on the review step, the
// preview of the file change.
func (f *form) enter(m *app) tea.Cmd {
	if f.step.ID != "review" {
		return nil
	}
	f.seq++
	f.prev, f.prevErr = nil, ""
	return previewCmd(m.b, f, f.seq, f.flow.Draft().Project.Name, f.flow)
}

func (f *form) waiting() bool {
	return f.step.ID == "review" && f.prev == nil && f.prevErr == ""
}

// answer is the value for the current step in the flow's own format.
func (f *form) answer() string {
	switch f.step.Kind {
	case setup.KindText:
		return f.in.String()
	case setup.KindChoice:
		if i := f.vp.at(); i < len(f.step.Options) {
			return f.step.Options[i].Value
		}
	case setup.KindMulti:
		var vs []string
		for _, o := range f.step.Options {
			if f.sel[o.Value] {
				vs = append(vs, o.Value)
			}
		}
		return strings.Join(vs, ",")
	}
	return ""
}

func (f *form) hint() string {
	switch f.step.Kind {
	case setup.KindText:
		return "type  enter next  esc back  ctrl+d scan a folder"
	case setup.KindChoice:
		return "up/down move  enter select  esc back  d scan a folder  ? help"
	case setup.KindMulti:
		return "up/down move  space toggle  a all/none  enter confirm  esc back  d folder  ? help"
	}
	if f.step.ID == "review" {
		return "y save  n do not save  up/down scroll  esc back  ? help"
	}
	return "y yes  n no  esc back  ? help"
}

func (m *app) formKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	f := m.frm
	if f.saving || f.waiting() { // the preview reads the flow in the background
		return m, nil
	}
	s := k.String()
	switch s {
	case "esc":
		return m.formBack()
	case "ctrl+d":
		m.startPath()
		return m, nil
	}
	if f.step.Kind == setup.KindText {
		if s == "enter" {
			return m.formAnswer(f.answer())
		}
		f.in.key(k)
		return m, nil
	}
	switch s { // keys of the steps that are not text
	case "q":
		return m, tea.Quit
	case "d":
		m.startPath()
		return m, nil
	case "?":
		m.openHelp()
		return m, nil
	}
	n := len(f.step.Options)
	switch f.step.Kind {
	case setup.KindChoice:
		if f.vp.handle(s) {
			return m, nil
		}
		if s == "enter" && n > 0 {
			return m.formAnswer(f.answer())
		}
	case setup.KindMulti:
		if f.vp.handle(s) {
			return m, nil
		}
		switch s {
		case " ", "x":
			if n > 0 {
				v := f.step.Options[f.vp.at()].Value
				f.sel[v] = !f.sel[v]
			}
		case "a":
			ticked := 0
			for _, on := range f.sel {
				if on {
					ticked++
				}
			}
			all := ticked < n
			f.sel = map[string]bool{}
			for _, o := range f.step.Options {
				f.sel[o.Value] = all
			}
		case "enter":
			return m.formAnswer(f.answer())
		}
	case setup.KindConfirm:
		switch s {
		case "y", "Y":
			return m.formAnswer("yes")
		case "n", "N":
			return m.formAnswer("no")
		default:
			f.rev.handle(s)
		}
	}
	return m, nil
}

// formAnswer gives the flow an answer. A rejected answer leaves the form
// where it is with the flow's reason on screen; the last accepted one ends
// the flow and saves.
func (m *app) formAnswer(v string) (tea.Model, tea.Cmd) {
	f := m.frm
	if err := f.flow.Answer(v); err != nil {
		f.step = f.flow.Current() // carries the problem; the typed answer stays
		return m, nil
	}
	if f.flow.Done() {
		f.saving = true
		m.busy = "saving..."
		return m, saveCmd(m.b, f, f.flow.Draft().Project.Name, f.flow)
	}
	f.load()
	return m, f.enter(m)
}

// formBack goes one step back, or leaves the form from the first step.
func (m *app) formBack() (tea.Model, tea.Cmd) {
	f := m.frm
	before := f.step.ID
	f.flow.Back()
	if f.flow.Current().ID == before { // the flow stays put only on its first step
		m.frm = nil
		m.say("cancelled, nothing was saved")
		return m, nil
	}
	f.load()
	return m, f.enter(m)
}

func (f *form) title() string {
	if f.creating {
		if n := f.flow.Draft().Project.Name; n != "" {
			return "New project: " + oneLine(n)
		}
		return "New project"
	}
	return "Edit project: " + oneLine(f.existing)
}

// frame is the lines above the step's rows and below them, and the room that
// leaves for the rows.
func (f *form) frame(w, h int) (head, tail []string, room int) {
	head = []string{stBold.Render(trunc(f.title(), w))}
	st := f.step
	head = append(head, section(oneLine(st.Title)))
	if st.ID != "review" && st.Help != "" {
		for _, l := range wrap(oneLine(st.Help), w-2) {
			head = append(head, stMuted.Render(l))
		}
	}
	head = append(head, "")
	if st.Problem != "" {
		tail = append(tail, "", stErr.Render("problem: ")+trunc(oneLine(st.Problem), w-9))
	}
	return head, tail, max(h-len(head)-len(tail), 1)
}

// layout gives the step's list or diff its room; it runs from Update.
func (f *form) layout(w, h int) {
	_, _, room := f.frame(w, h)
	switch f.step.Kind {
	case setup.KindChoice, setup.KindMulti:
		f.vp.fit(room)
	default:
		if f.step.ID == "review" {
			f.rev.refit(len(f.reviewBody(w)), nil)
			f.rev.fit(max(room-2, 1))
		}
	}
}

// view draws the step. Every string from the flow (help, option details,
// problems) can carry repository text, so all of it is cleaned.
func (f *form) view(w, h int) []string {
	out, tail, room := f.frame(w, h)
	st := f.step
	switch st.Kind {
	case setup.KindText:
		out = append(out, "> "+f.in.view(w-2, true))
	case setup.KindChoice, setup.KindMulti:
		out = append(out, f.optionRows(w, room)...)
	default:
		if st.ID == "review" {
			out = append(out, f.reviewRows(w, room)...)
		} else {
			out = append(out, "> y yes, n no")
		}
	}
	return append(out, tail...)
}

func (f *form) optionRows(w, room int) []string {
	opts := f.step.Options
	if len(opts) == 0 {
		return []string{stMuted.Render("  nothing to choose here; press enter to continue")}
	}
	start, end := f.vp.window(room)
	var out []string
	for i := start; i < end; i++ {
		o := opts[i]
		mark := "  "
		if i == f.vp.at() {
			mark = "> "
		}
		box := ""
		if f.step.Kind == setup.KindMulti {
			box = "[ ] "
			if f.sel[o.Value] {
				box = "[x] "
			}
		}
		label := oneLine(o.Label)
		if label == "" {
			label = oneLine(o.Value)
		}
		head, tailTxt := mark+box+label, ""
		if d := oneLine(o.Detail); d != "" {
			if rm := w - width(head) - 4; rm > 6 {
				tailTxt = "  - " + trunc(d, rm)
			}
		}
		var line string
		if i == f.vp.at() {
			line = stSel.Render(pad(head+tailTxt, w))
		} else {
			line = trunc(head, w) + stMuted.Render(tailTxt)
		}
		out = append(out, line)
	}
	return out
}

func (f *form) reviewBody(w int) []string {
	var body []string
	switch {
	case f.saving:
		body = append(body, stMuted.Render("Saving..."))
	case f.prev == nil && f.prevErr == "":
		body = append(body, stMuted.Render("Loading the preview..."))
	}
	if f.prevErr != "" {
		body = append(body, stErr.Render("error: ")+trunc(oneLine(f.prevErr), w-7))
	}
	if f.prev != nil {
		body = append(body, previewRows(f.prev, w)...)
	}
	return body
}

// reviewRows shows the diff ops computed for the project file, the validation
// issues, and the question.
func (f *form) reviewRows(w, room int) []string {
	body := f.reviewBody(w)
	ask := stBold.Render("Save this project?") + "  y = save, n = do not save, esc = back"
	start, end := f.rev.window(max(room-2, 1))
	start, end = min(start, len(body)), min(end, len(body))
	out := append([]string{}, body[start:end]...)
	return append(out, "", ask)
}

func previewRows(p *ops.ProjectPreview, w int) []string {
	var body []string
	if strings.TrimSpace(p.Diff) == "" {
		body = append(body, stMuted.Render("(no changes to the file)"))
	}
	for _, l := range strings.Split(p.Diff, "\n") {
		l = trunc(clean(l), w)
		switch {
		case strings.HasPrefix(l, "+"):
			l = stAdd.Render(l)
		case strings.HasPrefix(l, "-"):
			l = stDel.Render(l)
		case strings.HasPrefix(l, "@@"):
			l = stMuted.Render(l)
		}
		body = append(body, l)
	}
	for _, is := range p.Issues {
		lvl := stMuted.Render(oneLine(is.Level))
		if is.Level == "error" {
			lvl = stErr.Render("error")
		}
		body = append(body, lvl+": "+trunc(oneLine(is.Field)+": "+oneLine(is.Message), w-8))
	}
	if p.Blocked() {
		body = append(body, stErr.Render("this cannot be saved until the errors are fixed"))
	}
	return body
}
