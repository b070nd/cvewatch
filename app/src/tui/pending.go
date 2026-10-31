package tui

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
)

// reloadSet says what to read again once an operation has finished.
type reloadSet uint8

const (
	reList     reloadSet = 1 << iota // the snapshot: issues, status, project rows and their problems
	reDetail                         // the open issue
	reSettings                       // the configuration documents
)

type pendingOp struct {
	id    int
	key   string // what the operation is about; a second one for the same thing is refused
	label string // shown in the header while it runs
	after reloadSet
}

// pending is the operations in flight, a count and not a flag: one that
// finishes leaves the others running. Everything that happens when an
// operation ends (the count, the report, the reloads, the prompt that
// started it) is app.opDone; nothing else clears or reports it.
type pending struct {
	next int
	ops  []pendingOp
}

// begin registers an operation. It is refused while one with the same key is
// still running, which is what keeps a key pressed twice from writing twice.
func (p *pending) begin(label, key string, after reloadSet) (id int, ok bool) {
	for _, o := range p.ops {
		if key != "" && o.key == key {
			return o.id, false
		}
	}
	p.next++
	p.ops = append(p.ops, pendingOp{id: p.next, key: key, label: label, after: after})
	return p.next, true
}

// end removes an operation and returns it; ok is false for one not running.
func (p *pending) end(id int) (op pendingOp, ok bool) {
	for i, o := range p.ops {
		if o.id == id {
			p.ops = append(p.ops[:i], p.ops[i+1:]...)
			return o, true
		}
	}
	return pendingOp{}, false
}

func (p *pending) count() int { return len(p.ops) }

// status is the header text: the oldest operation, and how many more run.
func (p *pending) status() string {
	switch len(p.ops) {
	case 0:
		return ""
	case 1:
		return p.ops[0].label
	}
	return fmt.Sprintf("%s +%d", p.ops[0].label, len(p.ops)-1)
}

// opMsg is the result of a command started with app.start, tagged with the
// operation and the prompt that started it.
type opMsg struct {
	id  int
	prm *prompt
	msg tea.Msg
}

// outcome is what an operation reports: a note, or an error, or a note with a
// follow-up that failed (warn).
type outcome struct {
	note string
	warn error
	err  error
	then tea.Cmd
}

// begin registers an operation for app.start and the commands that return
// their result by other means. The prompt that started it stays open, marked
// as submitting, until opDone.
func (m *app) begin(label, key string, after reloadSet, prm *prompt) (int, bool) {
	id, ok := m.pend.begin(label, key, after)
	if !ok {
		m.fail("still busy: " + label)
		return 0, false
	}
	if prm != nil {
		prm.submitting, prm.problem = true, ""
	}
	return id, true
}

// start runs cmd as an operation; nil when one for the same key is running.
func (m *app) start(label, key string, after reloadSet, prm *prompt, cmd tea.Cmd) tea.Cmd {
	id, ok := m.begin(label, key, after, prm)
	if !ok {
		return nil
	}
	return func() tea.Msg { return opMsg{id: id, prm: prm, msg: cmd()} }
}

// opDone is the one place an operation ends.
func (m *app) opDone(msg opMsg) tea.Cmd {
	op, _ := m.pend.end(msg.id)
	m.stl.invalidate() // what the operation did may change what the findings are judged against
	m.tried = ""
	out := m.result(msg.msg)
	if p := msg.prm; p != nil && p == m.prm { // else it was closed meanwhile: the result is not its to take
		if out.err != nil {
			p.submitting, p.problem = false, oneLine(out.err.Error())
		} else {
			m.prm = nil
		}
	}
	switch {
	case out.err != nil:
		m.fail(out.err.Error())
	case out.warn != nil:
		m.fail(out.note + ", but: " + out.warn.Error())
	case out.note != "":
		m.say(out.note)
	}
	return tea.Batch(out.then, m.refresh(op.after))
}

// result applies what a command returned to the state.
func (m *app) result(msg tea.Msg) outcome {
	switch msg := msg.(type) {
	case actionMsg:
		return outcome{note: msg.info, warn: msg.warn, err: msg.err}
	case bulkMsg:
		for _, id := range msg.done {
			delete(m.fnd.sel, id)
		}
		return outcome{note: msg.info, warn: msg.warn, err: msg.err}
	case desktopMsg:
		return outcome{note: msg.note, err: msg.err}
	case evidenceMsg:
		return m.evidenceLoaded(msg)
	case detailMsg:
		m.detailLoaded(msg)
	case flowMsg:
		return m.flowStarted(msg)
	case scanMsg:
		return m.scanned(msg)
	case savedMsg:
		return m.saved(msg)
	case fixSavedMsg:
		return m.fixSaved(msg)
	case editCheckedMsg:
		return m.editChecked(msg)
	case techAddedMsg:
		return m.techAdded(msg)
	case techLoadedMsg:
		return m.techLoaded(msg)
	case setCheckedMsg:
		return m.setChecked(msg)
	case setSavedMsg:
		return m.setSaved(msg)
	case lifePreviewMsg:
		return m.lifePreviewed(msg)
	case lifeAppliedMsg:
		return m.lifeApplied(msg)
	case revalPreviewMsg:
		return m.revalPreviewed(msg)
	case editedMsg:
		if msg.err != nil {
			return outcome{err: fmt.Errorf("editor: %w", msg.err)}
		}
		return outcome{note: msg.note}
	}
	return outcome{}
}

// refresh reads again what set names.
func (m *app) refresh(set reloadSet) tea.Cmd {
	var cmds []tea.Cmd
	if set&reList != 0 && m.scr == scrSettings {
		set |= reSettings
	}
	if set&reSettings != 0 {
		cmds = append(cmds, m.loadSettings())
	}
	if set&(reList|reSettings) != 0 {
		cmds = append(cmds, tuiCmd(m.b)) // the periods may have been changed in the Settings screen or the file
	}
	if set&reList != 0 {
		m.loading = true
		cmds = append(cmds, loadLandCmd(m.b, m.stl, nil))
	}
	if d := m.fnd.det; set&reDetail != 0 && d != nil {
		cmds = append(cmds, detailCmd(m.b, d.id))
	}
	return tea.Batch(cmds...)
}
