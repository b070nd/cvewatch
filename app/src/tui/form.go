package tui

import (
	"path/filepath"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/b070nd/cvewatch/app/src/discovery"
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
	touched bool         // an answer was given, so leaving loses something
	pick    *sectionPick // the review is choosing a step to go back to

	infra map[string]bool // the technologies a scan found only in container or orchestration files, by lowercase name
	grp   bool            // the technologies step lists the infrastructure apart, after the others
	split int             // the options before it are the others
}

// groupHeads is the most heading lines the technologies step shows in a window.
const groupHeads = 2

// sectionPick is the list of steps the review can go back to.
type sectionPick struct {
	items []setup.Section
	vp    viewport
}

func newForm(fl *setup.Flow, creating bool, name string) *form {
	f := &form{flow: fl, creating: creating, existing: name, rev: scrolling()}
	f.load()
	return f
}

// load shows the flow's current step with the flow's own defaults.
func (f *form) load() {
	f.step = f.flow.Current()
	f.regroup()
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

// regroup puts the infrastructure technologies after the others on the technologies step.
func (f *form) regroup() {
	f.grp, f.split = false, 0
	if f.step.ID != "techs" || len(f.infra) == 0 {
		return
	}
	var apps, infra []setup.Option
	for _, o := range f.step.Options {
		if f.infra[strings.ToLower(o.Value)] {
			infra = append(infra, o)
		} else {
			apps = append(apps, o)
		}
	}
	if len(infra) == 0 {
		return
	}
	f.step.Options = append(apps, infra...)
	f.grp, f.split = true, len(apps)
}

// reserve is the rows of the list that the headings of its groups take.
func (f *form) reserve() int {
	if f.grp {
		return groupHeads
	}
	return 0
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

func (m *app) formAnswerCurrent() tea.Cmd { return m.formAnswer(m.frm.answer()) }

func (m *app) toggleOption() tea.Cmd {
	f := m.frm
	if len(f.step.Options) > 0 {
		v := f.step.Options[f.vp.at()].Value
		f.sel[v] = !f.sel[v]
	}
	return nil
}

// toggleAll ticks every option, or unticks them all when all are ticked.
func (m *app) toggleAll() tea.Cmd {
	f := m.frm
	ticked := 0
	for _, on := range f.sel {
		if on {
			ticked++
		}
	}
	all := ticked < len(f.step.Options)
	f.sel = map[string]bool{}
	for _, o := range f.step.Options {
		f.sel[o.Value] = all
	}
	return nil
}

func (m *app) openPick() tea.Cmd {
	f := m.frm
	secs := f.flow.Sections()
	if len(secs) == 0 {
		return nil
	}
	f.pick = &sectionPick{items: secs}
	f.pick.vp.reset(len(secs))
	return nil
}

// pickEnter goes to the chosen step; once it is answered the flow is at the review again.
func (m *app) pickEnter() tea.Cmd {
	f := m.frm
	id := f.pick.items[f.pick.vp.at()].ID
	f.pick = nil
	if err := f.flow.Revisit(id); err != nil {
		m.fail(err.Error())
		return nil
	}
	f.load()
	return f.enter(m)
}

// clickPick selects the step drawn on the given body line; a second click goes there.
func (m *app) clickPick(line int) tea.Cmd {
	f := m.frm
	w, _ := m.size()
	head, _, _ := f.frame(w, m.bodyH())
	i := rowAt(&f.pick.vp, line-len(head)-1)
	switch {
	case i < 0:
		return nil
	case i == f.pick.vp.at():
		return m.pickEnter()
	}
	f.pick.vp.to(i)
	return nil
}

func (f *form) pickRows(w, room int) []string {
	out := []string{stMuted.Render(trunc("Go back to which step? The review comes back after it.", w))}
	start, end := f.pick.vp.window(max(room-1, 1))
	for i := start; i < end; i++ {
		line := "  " + oneLine(f.pick.items[i].Title)
		if i == f.pick.vp.at() {
			line = stSel.Render(pad("> "+oneLine(f.pick.items[i].Title), w))
		}
		out = append(out, line)
	}
	return out
}

// clickOption selects the option drawn on the given body line; a second
// click on it answers (a choice) or ticks it (a checklist).
func (m *app) clickOption(line int) tea.Cmd {
	f := m.frm
	w, _ := m.size()
	head, _, room := f.frame(w, m.bodyH())
	i := -1
	if _, lines := f.optionLines(room); line-len(head) >= 0 && line-len(head) < len(lines) {
		i = lines[line-len(head)]
	}
	switch {
	case i < 0:
		return nil
	case i != f.vp.at():
		f.vp.to(i)
	case f.step.Kind == setup.KindMulti:
		return m.toggleOption()
	default:
		return m.formAnswer(f.answer())
	}
	return nil
}

// formAnswer gives the flow an answer. A rejected answer leaves the form
// where it is with the flow's reason on screen; the last accepted one ends
// the flow and saves.
func (m *app) formAnswer(v string) tea.Cmd {
	f := m.frm
	if err := f.flow.Answer(v); err != nil {
		f.step = f.flow.Current() // carries the problem; the typed answer stays
		f.regroup()
		return nil
	}
	f.touched = true
	if f.flow.Done() {
		cmd := m.start("saving...", "form save", reList, nil, saveCmd(m.b, f, f.flow.Draft().Project.Name, f.flow))
		f.saving = cmd != nil
		return cmd
	}
	f.load()
	return f.enter(m)
}

// formBack goes one step back. From the first step it leaves the form, after
// asking when something was entered.
func (m *app) formBack() tea.Cmd {
	f := m.frm
	before := f.step.ID
	f.flow.Back()
	if f.flow.Current().ID == before { // the flow stays put only on its first step
		return m.leaveForm()
	}
	f.load()
	return f.enter(m)
}

// leaveForm closes the form, unless it holds entered data: then it asks.
func (m *app) leaveForm() tea.Cmd {
	if m.frm.saving {
		return nil
	}
	if m.frm.dirty() {
		m.cfm = &confirm{ask: "Discard what you entered? Nothing has been saved.", yes: func(m *app) tea.Cmd { return m.dropForm() }}
		return nil
	}
	return m.dropForm()
}

func (m *app) dropForm() tea.Cmd {
	m.frm = nil
	m.say("cancelled, nothing was saved")
	return nil
}

// dirty is whether leaving would throw away an answer or typed text.
func (f *form) dirty() bool {
	return f.touched || (f.step.Kind == setup.KindText && f.in.String() != f.step.Default)
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
	if f.pick != nil {
		f.pick.vp.fit(max(room-1, 1))
	}
	switch f.step.Kind {
	case setup.KindChoice, setup.KindMulti:
		f.vp.fit(room - f.reserve())
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
	if f.pick != nil {
		return append(append(out, f.pickRows(w, room)...), tail...)
	}
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

// optionLines is the window of options that fit in room lines and what each
// line of it shows: the index of an option, or -1 for the heading of a group.
func (f *form) optionLines(room int) (start int, lines []int) {
	start, end := f.vp.window(max(room-f.reserve(), 1))
	for i := start; i < end; i++ {
		if f.grp && (i == start || i == f.split) {
			lines = append(lines, -1)
		}
		lines = append(lines, i)
	}
	return start, lines
}

func (f *form) optionRows(w, room int) []string {
	opts := f.step.Options
	if len(opts) == 0 {
		return []string{stMuted.Render("  nothing to choose here; press enter to continue")}
	}
	_, lines := f.optionLines(room)
	var out []string
	for _, i := range lines {
		if i < 0 {
			continue
		}
		o := opts[i]
		if f.grp && (i == f.split || len(out) == 0) {
			out = append(out, section(trunc(groupName(i >= f.split), w)))
		}
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

func groupName(infra bool) string {
	if infra {
		return "Infrastructure"
	}
	return "Technologies"
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
	ask := stBold.Render("Save this project?") + "  y = save, esc = back (enter saves too)"
	start, end := f.rev.window(max(room-2, 1))
	start, end = min(start, len(body)), min(end, len(body))
	out := append([]string{}, body[start:end]...)
	return append(out, "", ask)
}

func previewRows(p *ops.ProjectPreview, w int) []string {
	body := diffRows(p.Diff, w)
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

// diffRows draws a unified diff: additions, removals and hunk marks apart.
func diffRows(diff string, w int) []string {
	var body []string
	if strings.TrimSpace(diff) == "" {
		body = append(body, stMuted.Render("(no changes to the file)"))
	}
	for _, l := range strings.Split(diff, "\n") {
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
	return body
}

// ---- lockfiles of the project being set up ----

func onLockStep(m *app) bool { return m.frm != nil && m.frm.step.ID == "lockfiles" }

// onLockStepOrReview is where + adds a lockfile.
func onLockStepOrReview(m *app) bool {
	return m.frm != nil && (m.frm.step.ID == "lockfiles" || m.frm.step.ID == "review")
}

func (m *app) formLockPrompt() tea.Cmd {
	m.startLockPath("")
	return nil
}

// addFormLock puts a lockfile into the draft of the flow, as if the scan had found it.
func (m *app) addFormLock(typ, abs string) tea.Cmd {
	f := m.frm
	if f == nil || f.waiting() || f.saving { // a preview or save is reading the flow right now
		m.fail("the preview is still loading: add the lockfile again in a moment")
		return nil
	}
	ticked := map[string]bool{}
	if f.step.ID == "lockfiles" {
		for _, o := range f.step.Options {
			ticked[o.Label] = f.sel[o.Value]
		}
	}
	f.flow.UseDiscovery(f.flow.Draft().Dir, discovery.Result{Lockfiles: []discovery.LockProposal{{Type: typ, Path: abs}}})
	f.touched = true
	f.load()
	if f.step.ID == "lockfiles" {
		for i, o := range f.step.Options {
			if on, ok := ticked[o.Label]; ok { // the ticks the user set stay; the new one is ticked
				f.sel[o.Value] = on
			}
			if strings.Contains(o.Label, filepath.Base(abs)) {
				f.vp.to(i)
			}
		}
	}
	m.say("added " + typ + " lockfile " + oneLine(filepath.Base(abs)))
	return f.enter(m)
}

// formRemoveLock is - on the lockfiles step: after a question, the lockfile is left out of the project.
func (m *app) formRemoveLock() tea.Cmd {
	f := m.frm
	if len(f.step.Options) == 0 {
		return nil
	}
	o := f.step.Options[f.vp.at()]
	if !f.sel[o.Value] {
		m.fail(oneLine(o.Label) + " is not in the project")
		return nil
	}
	m.cfm = &confirm{ask: "Remove lockfile " + oneLine(o.Label) + " from the project?", yes: func(m *app) tea.Cmd {
		if m.frm == f {
			f.sel[o.Value] = false
			m.say("left out " + oneLine(o.Label))
		}
		return nil
	}}
	return nil
}
