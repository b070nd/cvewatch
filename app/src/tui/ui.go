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
	p := tea.NewProgram(New(b, o), tea.WithAltScreen(), tea.WithMouseCellMotion(), tea.WithContext(ctx))
	_, err := p.Run()
	if err != nil && ctx.Err() != nil {
		return nil
	}
	return err
}

// New returns the program's model; it is exported so tests can drive it.
func New(b Backend, o Options) tea.Model {
	m := &app{b: b, o: o, loading: true, helpVP: scrolling(), after: afterCmd}
	for i := range m.txt {
		m.txt[i] = scrolling()
	}
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
	helpFor *mode // the mode the open help describes
	helpVP  viewport
	txt     [numScreens]viewport // the screens that are plain text
	cache   [numScreens]textCache
	data    *snapshot
	loadErr error
	loading bool
	pend    pending // the writes and scans in flight

	flash    string
	flashErr bool
	flashSeq int  // which note is on screen, so that an old timer leaves a newer one alone
	flashDue bool // a note was set and its timer is not started yet
	after    func(d time.Duration, msg tea.Msg) tea.Cmd

	fnd findingsState
	prj projectsState
	frm *form
	prm *prompt
	cfm *confirm
}

// ---- tea.Model ----

func (m *app) Init() tea.Cmd {
	cmds := []tea.Cmd{loadCmd(m.b), tickCmd(m.o.refresh())}
	if m.o.Dir != "" {
		cmds = append(cmds, m.start("scanning "+clean(m.o.Dir)+"...", "flow", 0, nil, startFlowCmd(m.b, "", m.o.Dir)))
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

// flashTTL is how long a success note stays; an error stays until the next
// action that is not just moving around (see key).
const flashTTL = 4 * time.Second

// flashExpiredMsg ends the note numbered seq, if it is still the one shown.
type flashExpiredMsg struct{ seq int }

func afterCmd(d time.Duration, msg tea.Msg) tea.Cmd {
	return tea.Tick(d, func(time.Time) tea.Msg { return msg })
}

func (m *app) say(s string) {
	m.flash, m.flashErr = oneLine(s), false
	m.flashSeq++
	m.flashDue = true
}

func (m *app) fail(s string) {
	m.flash, m.flashErr = oneLine(s), true
	m.flashSeq++
	m.flashDue = false
}

func (m *app) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	model, cmd := m.update(msg)
	m.layout()
	if m.flashDue && m.after != nil {
		cmd = tea.Batch(cmd, m.after(flashTTL, flashExpiredMsg{seq: m.flashSeq}))
	}
	m.flashDue = false
	return model, cmd
}

func (m *app) update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
		return m, nil
	case tea.KeyMsg:
		return m.key(msg)
	case tea.MouseMsg:
		return m, m.mouse(msg)
	case tickMsg:
		next := tickCmd(m.o.refresh())
		if m.loading {
			return m, next
		}
		return m, tea.Batch(next, m.refresh(reList|reDetail))
	case flashExpiredMsg:
		if msg.seq == m.flashSeq && !m.flashErr {
			m.flash = ""
		}
		return m, nil
	case dataMsg:
		m.loading = false
		if msg.err != nil {
			m.loadErr = msg.err
			return m, nil
		}
		before := m.prj.proj.id()
		m.loadErr, m.data = nil, msg.snap
		m.fnd.refit(m.data.Issues)
		m.refitProjects(before)
		return m, nil
	case detailMsg:
		m.detailLoaded(msg)
		return m, nil
	case opMsg:
		return m, m.opDone(msg)
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
	case fixPreviewMsg:
		m.fixPreviewed(msg)
		return m, nil
	}
	return m, nil
}

func (m *app) flowStarted(msg flowMsg) outcome {
	if msg.err != nil {
		return outcome{err: msg.err}
	}
	m.scr = scrProjects
	m.frm = newForm(msg.flow, msg.creating, msg.name)
	return outcome{note: msg.note, then: m.frm.enter(m)}
}

func (m *app) scanned(msg scanMsg) outcome {
	if msg.err != nil {
		return outcome{err: msg.err}
	}
	if m.frm == nil || m.frm.waiting() || m.frm.saving {
		return outcome{} // a preview or save is reading the flow right now
	}
	m.frm.flow.UseDiscovery(msg.res.Root, msg.res)
	m.frm.touched = true
	m.frm.load()
	return outcome{note: scanNote(msg.res), then: m.frm.enter(m)}
}

func (m *app) saved(msg savedMsg) outcome {
	if msg.f != m.frm {
		return outcome{err: msg.err}
	}
	f := m.frm
	f.saving = false
	if msg.err != nil {
		f.flow.Back() // un-finish the review so the user can fix or leave
		f.step = f.flow.Current()
		return outcome{err: msg.err}
	}
	m.frm = nil
	if msg.prev.Saved {
		verb := "saved"
		if msg.prev.Created {
			verb = "created"
		}
		return outcome{note: fmt.Sprintf("%s project %s", verb, msg.prev.Project)}
	}
	return outcome{note: "no changes to save in " + msg.prev.Project}
}

// ---- keys ----

func (m *app) key(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	if k.String() == "ctrl+c" {
		return m, tea.Quit
	}
	seq := m.flashSeq
	cmd, moved := m.dispatch(k)
	if !moved && m.flashSeq == seq { // moving around keeps what is on screen, an action ends it
		m.flash = ""
	}
	return m, cmd
}

func (m *app) stepScreen(d int) { m.scr = (m.scr + numScreens + screen(d)) % numScreens }

// textCache is a plain-text screen rendered for one width and snapshot.
type textCache struct {
	w     int
	snap  *snapshot
	lines []string
}

// text is the lines of the Overview or Status screen.
func (m *app) text(scr screen, w int) []string {
	if c := m.cache[scr]; c.snap == m.data && c.w == w && c.lines != nil {
		return c.lines
	}
	if scr == scrStatus {
		return renderStatus(m.data.Status, m.data.At, w)
	}
	return renderOverview(m.data, w)
}

// body is the area between the header and the footer, and the prompt that
// takes its bottom part.
func (m *app) body() (w, h int, prompt []string) {
	w, th := m.size()
	h = th - 4
	switch {
	case m.cfm != nil:
		prompt = m.cfm.view(w)
	case m.prm != nil:
		prompt = m.prm.view(w, th)
	}
	h = max(h-len(prompt), 1)
	return w, h, prompt
}

// layout runs after every message: it tells the lists and texts how many rows
// the current screen gives them, so that drawing can leave them alone.
func (m *app) layout() {
	w, h, _ := m.body()
	switch {
	case m.help:
		m.helpVP.refit(len(m.helpText(w)), nil)
		m.helpVP.fit(h)
	case m.frm != nil:
		m.frm.layout(w, h)
	case m.data == nil:
	case m.scr == scrFindings && m.fnd.det != nil:
		d := m.fnd.det
		d.lay = d.layout(w)
		d.body.refit(len(d.lay.lines), nil)
		d.body.fit(h)
	case m.scr == scrFindings:
		m.fnd.vp.fit(findingsRoom(h))
	case m.scr == scrProjects && m.prj.fix != nil:
		m.prj.fix.layout(w, h)
	case m.scr == scrProjects && m.prj.deep:
		m.prj.prob.fit(deepRoom(h))
	case m.scr == scrProjects:
		_, room := projectsPanel(m.data.Projects, &m.prj, w, h)
		m.prj.proj.fit(room)
		m.prj.prob.fit(problemRoom)
	default:
		m.cache[m.scr] = textCache{w: w, snap: m.data, lines: m.text(m.scr, w)}
		m.txt[m.scr].refit(len(m.cache[m.scr].lines), nil)
		m.txt[m.scr].fit(h)
	}
	if m.prm != nil && m.prm.box != nil {
		_, th := m.size()
		m.prm.box.vp.fit(folderRows(th))
	}
}

// ---- view ----

func (m *app) View() string {
	w, bodyH, prompt := m.body()
	var body []string
	switch {
	case m.help:
		lines := m.helpText(w)
		start, end := m.helpVP.window(bodyH)
		body = lines[min(start, len(lines)):min(end, len(lines))]
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
	crumbs, _ := m.crumbLine(w)
	lines := []string{m.header(w), crumbs}
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
			return []string{stErr.Render("error: ") + oneLine(m.loadErr.Error()), "", "Press r to try again, or q to quit."}
		}
		return []string{stMuted.Render("Loading...")}
	}
	switch m.scr {
	case scrFindings:
		return m.findingsBody(w, h)
	case scrProjects:
		if m.prj.fix != nil {
			return m.prj.fix.view(w, h)
		}
		if p, ok := m.selectedProject(); ok && m.prj.deep {
			return projectDetail(p, &m.prj.prob, w, deepRoom(h), true)
		}
		return renderProjects(m.data.Projects, &m.prj, w, h)
	}
	lines := m.text(m.scr, w)
	start, end := m.txt[m.scr].window(h)
	return lines[min(start, len(lines)):min(end, len(lines))]
}

// tabs are the screen tabs as drawn, and the cells each one covers.
func (m *app) tabs() (tabs []string, spans [numScreens][2]int) {
	x := width("cvewatch") + 2
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
		spans[i] = [2]int{x, x + width(tabs[i])}
		x += width(tabs[i]) + 1
	}
	return tabs, spans
}

func (m *app) header(w int) string {
	tabs, _ := m.tabs()
	left := stBold.Render("cvewatch") + "  " + strings.Join(tabs, " ")
	right := ""
	switch {
	case m.pend.count() > 0:
		right = m.pend.status()
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

func (m *app) footer(w int) string { return stMuted.Render(m.top().footerLine(m, w)) }
