package tui

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// A mode is one layer of the interface: a screen, a level inside it, or a
// popup over them. Its bindings are data, and the top mode alone decides what
// a key does, what the footer says and what the help lists. The layers that
// are open are derived from the state (see stack), so they cannot drift.
type mode struct {
	name  string
	title string // heading of its help
	level bool   // a screen or a level in one: the screen tabs can be clicked
	modal bool   // a popup: clicks outside it do nothing

	binds []binding

	// move handles the shared movement keys (see moveKeys) on the viewport
	// the mode owns, and reports whether it did.
	move      func(m *app, key string) bool
	moveShort string
	moveHelp  string

	// typed makes the mode a text input: it sees printable keys before the
	// bindings, and the editing keys no binding claims.
	typed func(m *app, k tea.KeyMsg) bool

	wheel func(m *app, up bool)
	click func(m *app, x, y int) tea.Cmd // x, y relative to the body
	notes []string
}

type binding struct {
	keys  []string
	disp  string // the keys as shown; the keys joined by "/" when empty
	help  string // label in the help
	short string // label in the footer; empty keeps it out of the footer
	prio  int    // 0 is never dropped from the footer; a higher number goes sooner
	alias bool   // works, but is left out of footer and help
	nav   bool   // only moves around: what is on screen, an error included, stays
	when  func(m *app) bool
	do    func(m *app, k tea.KeyMsg) tea.Cmd
}

func (b *binding) shown() string {
	if b.disp != "" {
		return b.disp
	}
	return strings.Join(b.keys, "/")
}

func (b *binding) on(m *app) bool { return b.when == nil || b.when(m) }

func (b *binding) has(key string) bool {
	for _, k := range b.keys {
		if k == key {
			return true
		}
	}
	return false
}

func ks(keys ...string) []string { return keys }

func plain(f func(m *app) tea.Cmd) func(*app, tea.KeyMsg) tea.Cmd {
	return func(m *app, _ tea.KeyMsg) tea.Cmd { return f(m) }
}

func printable(k tea.KeyMsg) bool { return k.Type == tea.KeyRunes || k.Type == tea.KeySpace }

// dispatch runs a key against the top mode: a text input first for printable
// keys, then the bindings, then the editing keys of the input or the shared
// movement.
//
// moved says the key only moved around (a movement key, a screen switch).
func (m *app) dispatch(k tea.KeyMsg) (cmd tea.Cmd, moved bool) {
	md := m.top()
	s := k.String()
	if md.typed != nil && printable(k) && md.typed(m, k) {
		return nil, false
	}
	for i := range md.binds {
		if b := &md.binds[i]; b.do != nil && b.has(s) && b.on(m) {
			return b.do(m, k), b.nav
		}
	}
	switch {
	case md.typed != nil:
		md.typed(m, k)
	case md.move != nil:
		moved = md.move(m, s)
	}
	return nil, moved
}

// stack is the open layers, the screen at the bottom and the mode that gets
// the keys last. One rule orders them: a popup is above a form or preview,
// that above a level of a screen, that above the screen.
func (m *app) stack() []*mode {
	var s []*mode
	switch {
	case m.data == nil && m.frm == nil:
		s = append(s, mo.noData)
	case m.scr == scrOverview:
		s = append(s, mo.overview)
	case m.scr == scrStatus:
		s = append(s, mo.status)
	case m.scr == scrFindings:
		s = append(s, mo.findings)
		switch {
		case m.fnd.det != nil:
			s = append(s, mo.detail)
		case m.fnd.filtering:
			s = append(s, mo.filter)
		}
	default:
		s = append(s, mo.projects)
		if m.prj.deep {
			s = append(s, mo.project)
		}
	}
	switch {
	case m.frm != nil:
		s = append(s, formMode(m.frm))
	case m.scr == scrProjects && m.prj.fix != nil:
		s = append(s, mo.fix)
	}
	switch {
	case m.prm != nil && m.prm.submitting:
		s = append(s, mo.promptBusy)
	case m.prm != nil && m.prm.box != nil:
		s = append(s, mo.folder)
	case m.prm != nil:
		s = append(s, mo.prompt)
	}
	if m.jmp != nil {
		s = append(s, mo.jump)
	}
	if m.nt != nil {
		s = append(s, mo.notice)
	}
	if m.cfm != nil {
		s = append(s, mo.confirm)
	}
	if m.help {
		s = append(s, mo.help)
	}
	return s
}

func (m *app) top() *mode {
	s := m.stack()
	return s[len(s)-1]
}

// footerLine is the hints of the mode that fit w cells: they stay in the
// order of the table and the least important go first.
func (md *mode) footerLine(m *app, w int) string {
	type item struct {
		text string
		prio int
	}
	var items []item
	if md.move != nil {
		short := md.moveShort
		if short == "" {
			short = "move"
		}
		items = append(items, item{moveDisp + " " + short, 1})
	}
	for i := range md.binds {
		b := &md.binds[i]
		if b.alias || b.short == "" || !b.on(m) {
			continue
		}
		items = append(items, item{strings.TrimSpace(b.shown() + " " + b.short), b.prio})
	}
	size := func() int {
		n := 0
		for _, it := range items {
			n += width(it.text) + 2
		}
		return max(n-2, 0)
	}
	for size() > w {
		drop := -1
		for i, it := range items {
			if it.prio > 0 && (drop < 0 || it.prio >= items[drop].prio) {
				drop = i
			}
		}
		if drop < 0 {
			break
		}
		items = append(items[:drop], items[drop+1:]...)
	}
	texts := make([]string, len(items))
	for i, it := range items {
		texts[i] = it.text
	}
	return trunc(strings.Join(texts, "  "), w)
}

// everywhere are the rules of the whole interface, ended by every help.
var everywhere = [][2]string{
	{"left, backspace", "back one level; on the first level of a screen, the previous screen (right: the next)"},
	{"esc", "close a popup or clear the filter, else back one level"},
	{"q", "quit on the first level of a screen; inside a level or a popup it works like esc"},
	{"ctrl+c", "quit at once, from anywhere"},
	{"tab, shift+tab, 1-4", "switch screen: Overview, Findings, Projects, Status"},
	{"mouse", "wheel scrolls, a click selects (a second click opens), breadcrumb and tabs are clickable"},
}

// helpLines is the help of one mode, written from its table.
func helpLines(md *mode, w int) []string {
	out := []string{section(md.title), ""}
	add := func(k, what string) { out = append(out, indentWrap("  "+pad(k, 16), what, w)...) }
	if md.move != nil {
		what := md.moveHelp
		if what == "" {
			what = moveHelp
		}
		add(moveDisp, what)
	}
	for i := range md.binds {
		if b := &md.binds[i]; !b.alias {
			add(b.shown(), b.help)
		}
	}
	for _, n := range md.notes {
		out = append(out, indentWrap("  ", n, w)...)
	}
	out = append(out, "", section("Everywhere"))
	for _, e := range everywhere {
		add(e[0], e[1])
	}
	return append(out, "", "  Severities and health levels are always written out as words,",
		"  so nothing depends on colour. Set NO_COLOR to turn colour off.")
}

func (m *app) openHelp() {
	m.helpFor = m.top()
	m.help = true
	m.helpVP.reset(0)
}

func (m *app) closeHelp() { m.help = false }

func (m *app) helpText(w int) []string {
	if m.helpFor == nil {
		return nil
	}
	return helpLines(m.helpFor, w)
}

// confirm is a yes/no question that takes the keys until it is answered.
type confirm struct {
	ask string
	yes func(m *app) tea.Cmd
}

func (c *confirm) view(w int) []string {
	return []string{stBold.Render(trunc(c.ask, w)), stMuted.Render(trunc("  y or enter: yes   n or esc: no", w))}
}
