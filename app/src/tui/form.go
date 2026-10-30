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

	in     input           // KindText
	cur    int             // KindChoice and KindMulti: the row under the cursor
	sel    map[string]bool // KindMulti: the ticked values
	scroll int             // review: first visible diff line

	prev    *ops.ProjectPreview // review: what saving would do
	prevErr string
	seq     int // identifies the preview request, so a stale answer is dropped
	saving  bool
}

func newForm(fl *setup.Flow, creating bool, name string) *form {
	f := &form{flow: fl, creating: creating, existing: name}
	f.load()
	return f
}

// load shows the flow's current step with the flow's own defaults.
func (f *form) load() {
	f.step = f.flow.Current()
	f.sel, f.cur, f.scroll = map[string]bool{}, 0, 0
	switch f.step.Kind {
	case setup.KindText:
		f.in.set(f.step.Default)
	case setup.KindChoice:
		for i, o := range f.step.Options {
			if o.Value == f.step.Default {
				f.cur = i
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
		if f.cur >= 0 && f.cur < len(f.step.Options) {
			return f.step.Options[f.cur].Value
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
		return "up/down move  enter select  esc back  d scan a folder"
	case setup.KindMulti:
		return "up/down move  space toggle  a all or none  enter confirm  esc back  d scan a folder"
	}
	if f.step.ID == "review" {
		return "y save  n do not save  up/down scroll  esc back"
	}
	return "y yes  n no  esc back"
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
	}
	n := len(f.step.Options)
	switch f.step.Kind {
	case setup.KindChoice:
		switch s {
		case "up", "k":
			f.cur = clamp(f.cur-1, 0, n-1)
		case "down", "j":
			f.cur = clamp(f.cur+1, 0, n-1)
		case "enter":
			if n > 0 {
				return m.formAnswer(f.answer())
			}
		}
	case setup.KindMulti:
		switch s {
		case "up", "k":
			f.cur = clamp(f.cur-1, 0, n-1)
		case "down", "j":
			f.cur = clamp(f.cur+1, 0, n-1)
		case " ", "x":
			if n > 0 {
				v := f.step.Options[f.cur].Value
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
		case "up", "k":
			f.scroll = max(0, f.scroll-1)
		case "down", "j":
			f.scroll++
		case "pgup":
			f.scroll = max(0, f.scroll-m.bodyH())
		case "pgdown":
			f.scroll += m.bodyH()
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

// view draws the step. Every string from the flow (help, option details,
// problems) can carry repository text, so all of it is cleaned.
func (f *form) view(w, h int) []string {
	out := []string{stBold.Render(trunc(f.title(), w))}
	st := f.step
	out = append(out, section(oneLine(st.Title)))
	if st.ID != "review" && st.Help != "" {
		for _, l := range wrap(oneLine(st.Help), w-2) {
			out = append(out, stMuted.Render(l))
		}
	}
	out = append(out, "")
	var tail []string
	if st.Problem != "" {
		tail = append(tail, "", stErr.Render("problem: ")+trunc(oneLine(st.Problem), w-9))
	}
	room := max(h-len(out)-len(tail), 1)

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
	start := clamp(f.cur-room/2, 0, len(opts)-room)
	end := min(start+room, len(opts))
	var out []string
	for i := start; i < end; i++ {
		o := opts[i]
		mark := "  "
		if i == f.cur {
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
		if i == f.cur {
			line = stSel.Render(pad(head+tailTxt, w))
		} else {
			line = trunc(head, w) + stMuted.Render(tailTxt)
		}
		out = append(out, line)
	}
	return out
}

// reviewRows shows the diff ops computed for the project file, the validation
// issues, and the question.
func (f *form) reviewRows(w, room int) []string {
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
	ask := stBold.Render("Save this project?") + "  y = save, n = do not save, esc = back"
	avail := max(room-2, 1)
	f.scroll = clamp(f.scroll, 0, len(body)-avail)
	end := min(f.scroll+avail, len(body))
	out := append([]string{}, body[f.scroll:end]...)
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
