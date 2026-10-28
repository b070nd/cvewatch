// Package tui is the terminal UI of cvewatch: a Bubble Tea program that is a
// thin adapter over ops. It holds no domain logic. Reading uses lock-free
// read-only snapshots, so it never blocks the daemon; every change opens a
// short write session through Backend, does one thing and closes it, so
// validation, access control and the audit log stay in ops and setup.
package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Options configure the program.
type Options struct {
	Refresh time.Duration // how often to re-read the state; default 30s
	Dir     string        // when set, start the setup flow for a new project on this folder
}

func (o Options) refresh() time.Duration {
	if o.Refresh <= 0 {
		return 30 * time.Second
	}
	return o.Refresh
}

// Run shows the TUI full screen until the user quits or ctx ends. A cancelled
// context is a normal way out and returns nil.
func Run(ctx context.Context, b Backend, o Options) error {
	p := tea.NewProgram(New(b, o), tea.WithAltScreen(), tea.WithContext(ctx))
	_, err := p.Run()
	if err != nil && ctx.Err() != nil {
		return nil
	}
	return err
}

// New returns the program's model; it is exported so tests can drive it.
func New(b Backend, o Options) tea.Model {
	m := &app{b: b, o: o, loading: true}
	if o.Dir != "" {
		m.scr = scrProjects
	}
	return m
}

type screen int

const (
	scrOverview screen = iota
	scrFindings
	scrProjects
	scrStatus
	numScreens
)

var screenNames = [numScreens]string{"Overview", "Findings", "Projects", "Status"}

type app struct {
	b Backend
	o Options

	w, h    int
	scr     screen
	help    bool
	scroll  [numScreens]int // for the screens that are plain text
	data    *snapshot
	loadErr error
	loading bool
	busy    string // a write in progress

	flash    string
	flashErr bool

	fnd findingsState
	prj projectsState
	frm *form
	prm *prompt
}

// ---- tea.Model ----

func (m *app) Init() tea.Cmd {
	cmds := []tea.Cmd{loadCmd(m.b), tickCmd(m.o.refresh())}
	if m.o.Dir != "" {
		m.busy = "scanning " + clean(m.o.Dir) + "..."
		cmds = append(cmds, startFlowCmd(m.b, "", m.o.Dir))
	}
	return tea.Batch(cmds...)
}

func (m *app) size() (int, int) {
	w, h := m.w, m.h
	if w <= 0 {
		w = 80
	}
	if h <= 0 {
		h = 24
	}
	return max(w, 30), max(h, 8)
}

// bodyH is the number of lines between the header and the footer.
func (m *app) bodyH() int {
	_, h := m.size()
	return h - 4
}

func (m *app) say(s string)  { m.flash, m.flashErr = oneLine(s), false }
func (m *app) fail(s string) { m.flash, m.flashErr = oneLine(s), true }

func (m *app) reload() tea.Cmd {
	m.loading = true
	return loadCmd(m.b)
}

func (m *app) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
		return m, nil
	case tea.KeyMsg:
		return m.key(msg)
	case tickMsg:
		next := tickCmd(m.o.refresh())
		if m.loading {
			return m, next
		}
		return m, tea.Batch(next, m.reload())
	case dataMsg:
		m.loading = false
		if msg.err != nil {
			m.loadErr = msg.err
			return m, nil
		}
		m.loadErr, m.data = nil, msg.snap
		m.fnd.refit(m.data.Issues)
		m.prj.cursor = clamp(m.prj.cursor, 0, len(m.data.Projects)-1)
		return m, nil
	case detailMsg:
		m.detailLoaded(msg)
		return m, nil
	case actionMsg:
		return m.actionDone(msg)
	case flowMsg:
		return m.flowStarted(msg)
	case scanMsg:
		return m.scanned(msg)
	case previewMsg:
		if msg.f == m.frm && msg.seq == msg.f.seq {
			msg.f.prev, msg.f.prevErr = nil, ""
			if msg.err != nil {
				msg.f.prevErr = msg.err.Error()
			}
			if msg.prev.Path != "" {
				p := msg.prev
				msg.f.prev = &p
			}
		}
		return m, nil
	case savedMsg:
		return m.saved(msg)
	}
	return m, nil
}

func (m *app) actionDone(msg actionMsg) (tea.Model, tea.Cmd) {
	m.busy = ""
	switch {
	case msg.err != nil:
		m.fail(msg.err.Error())
	case msg.warn != nil:
		m.fail(msg.info + ", but: " + msg.warn.Error())
	default:
		m.say(msg.info)
	}
	cmds := []tea.Cmd{m.reload()}
	if d := m.fnd.det; d != nil {
		cmds = append(cmds, detailCmd(m.b, d.id))
	}
	return m, tea.Batch(cmds...)
}

func (m *app) flowStarted(msg flowMsg) (tea.Model, tea.Cmd) {
	m.busy = ""
	if msg.err != nil {
		m.fail(msg.err.Error())
		return m, nil
	}
	m.scr = scrProjects
	m.frm = newForm(msg.flow, msg.creating, msg.name)
	if msg.note != "" {
		m.say(msg.note)
	}
	return m, m.frm.enter(m)
}

func (m *app) scanned(msg scanMsg) (tea.Model, tea.Cmd) {
	m.busy = ""
	if msg.err != nil {
		m.fail(msg.err.Error())
		return m, nil
	}
	if m.frm == nil {
		return m, nil
	}
	m.frm.flow.UseDiscovery(msg.res.Root, msg.res)
	m.frm.load()
	m.say(scanNote(msg.res))
	return m, m.frm.enter(m)
}

func (m *app) saved(msg savedMsg) (tea.Model, tea.Cmd) {
	if msg.f != m.frm {
		return m, nil
	}
	f := m.frm
	f.saving = false
	if msg.err != nil {
		f.flow.Back() // un-finish the review so the user can fix or leave
		f.step = f.flow.Current()
		m.fail(msg.err.Error())
		return m, nil
	}
	m.frm = nil
	if msg.prev.Saved {
		verb := "saved"
		if msg.prev.Created {
			verb = "created"
		}
		m.say(fmt.Sprintf("%s project %s", verb, msg.prev.Project))
	} else {
		m.say("no changes to save in " + msg.prev.Project)
	}
	return m, m.reload()
}

// ---- keys ----

func (m *app) key(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	if k.String() == "ctrl+c" {
		return m, tea.Quit
	}
	m.flash = ""
	switch {
	case m.prm != nil:
		return m.promptKey(k)
	case m.frm != nil:
		return m.formKey(k)
	case m.scr == scrFindings && m.fnd.filtering:
		return m.filterKey(k)
	}
	if m.help {
		switch k.String() {
		case "?", "esc":
			m.help = false
		case "q":
			return m, tea.Quit
		}
		return m, nil
	}
	switch s := k.String(); s {
	case "q":
		return m, tea.Quit
	case "?":
		m.help = true
		return m, nil
	case "r":
		return m, m.reload()
	case "1", "2", "3", "4":
		m.scr = screen(s[0] - '1')
		return m, nil
	case "tab":
		m.scr = (m.scr + 1) % numScreens
		return m, nil
	case "shift+tab":
		m.scr = (m.scr + numScreens - 1) % numScreens
		return m, nil
	}
	switch m.scr {
	case scrFindings:
		return m.findingsKey(k)
	case scrProjects:
		return m.projectsKey(k)
	}
	m.scrollKey(k)
	return m, nil
}

// scrollKey scrolls the plain-text screens.
func (m *app) scrollKey(k tea.KeyMsg) {
	d := 0
	switch k.String() {
	case "up", "k":
		d = -1
	case "down", "j":
		d = 1
	case "pgup":
		d = -m.bodyH()
	case "pgdown":
		d = m.bodyH()
	case "home", "g":
		d = -1 << 20
	}
	m.scroll[m.scr] = max(0, m.scroll[m.scr]+d)
}

// ---- view ----

func (m *app) View() string {
	w, h := m.size()
	bodyH := h - 4
	var prompt []string
	if m.prm != nil {
		prompt = m.prm.view(w)
		bodyH = max(bodyH-len(prompt), 1)
	}
	var body []string
	switch {
	case m.help:
		body = helpView(m.scr, m.frm != nil)
	case m.frm != nil:
		body = m.frm.view(w, bodyH)
	default:
		body = m.screenBody(w, bodyH)
	}
	body = clip(body, bodyH)
	for len(body) < bodyH {
		body = append(body, "")
	}
	body = append(body, prompt...)
	lines := []string{m.header(w), stMuted.Render(strings.Repeat("─", w))}
	lines = append(lines, body...)
	lines = append(lines, m.flashLine(w), m.footer(w))
	for i, l := range lines {
		if width(l) > w {
			lines[i] = lipgloss.NewStyle().MaxWidth(w).Render(l)
		}
	}
	return strings.Join(lines, "\n")
}

func (m *app) screenBody(w, h int) []string {
	if m.data == nil {
		if m.loadErr != nil {
			return []string{stErr.Render("error: ") + oneLine(m.loadErr.Error())}
		}
		return []string{stMuted.Render("Loading...")}
	}
	switch m.scr {
	case scrFindings:
		return m.findingsBody(w, h)
	case scrProjects:
		return renderProjects(m.data.Projects, m.prj.cursor, w, h)
	case scrStatus:
		return m.scrolled(renderStatus(m.data.Status, m.data.At, w), h)
	}
	return m.scrolled(renderOverview(m.data, w), h)
}

func (m *app) scrolled(lines []string, h int) []string {
	off := clamp(m.scroll[m.scr], 0, len(lines)-h)
	m.scroll[m.scr] = off
	return lines[off:]
}

func (m *app) header(w int) string {
	var tabs []string
	for i := screen(0); i < numScreens; i++ {
		label := fmt.Sprintf("%d %s", i+1, screenNames[i])
		if i == scrFindings && m.data != nil {
			label += fmt.Sprintf(" (%d)", len(m.data.Issues))
		}
		if i == m.scr {
			tabs = append(tabs, stTabOn.Render("["+label+"]"))
		} else {
			tabs = append(tabs, stTab.Render(" "+label+" "))
		}
	}
	left := stBold.Render("cvewatch") + "  " + strings.Join(tabs, " ")
	right := ""
	switch {
	case m.busy != "":
		right = m.busy
	case m.loading:
		right = "refreshing..."
	case m.data != nil:
		right = levelText(m.data.Status.Level) + stMuted.Render("  updated "+m.data.At.Local().Format("15:04:05"))
	}
	gap := w - width(left) - width(right)
	if gap < 1 {
		right, gap = "", max(1, w-width(left))
	}
	return left + spaces(gap) + right
}

func (m *app) flashLine(w int) string {
	switch {
	case m.flash != "" && m.flashErr:
		return stErr.Render("error: ") + trunc(m.flash, w-7)
	case m.flash != "":
		return stGood.Render("ok: ") + trunc(m.flash, w-4)
	case m.loadErr != nil:
		return stErr.Render("refresh failed: ") + trunc(oneLine(m.loadErr.Error()), w-16)
	}
	return ""
}

func (m *app) footer(w int) string {
	var hint string
	switch {
	case m.prm != nil:
		hint = "enter confirm  tab next field  esc cancel"
	case m.frm != nil:
		hint = m.frm.hint()
	case m.help:
		hint = "? or esc close help  q quit"
	case m.scr == scrFindings && m.fnd.filtering:
		hint = "type to filter  enter keep  esc clear"
	case m.scr == scrFindings && m.fnd.det != nil:
		hint = "up/down environment  f fixed  i ignore  n not-affected  o reopen  a assign  F/I/N/O whole project  esc back"
	case m.scr == scrFindings:
		hint = "up/down move  enter open  s min severity  / filter  r refresh  ? help  q quit"
	case m.scr == scrProjects:
		hint = "up/down move  e edit  n new  d new from folder  r refresh  ? help  q quit"
	default:
		hint = "1-4 screens  up/down scroll  r refresh  ? help  q quit"
	}
	return stMuted.Render(trunc(hint, w))
}
