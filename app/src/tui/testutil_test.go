package tui

import (
	"io"
	"log/slog"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/b070nd/cvewatch/app/src/catalog"
	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/ledger"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/ops"
	"github.com/b070nd/cvewatch/app/src/store"
)

var (
	t0   = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	tNow = t0.Add(48 * time.Hour)

	testTechs = []model.Tech{
		{Name: "php", Title: "PHP", Detect: model.Detect{Versions: []model.VersionHint{{File: ".php-version", Pattern: `^\s*(\S+)`}}}},
		{Name: "nginx", Title: "Nginx"},
		{Name: "express", Title: "Express", Detect: model.Detect{Packages: []model.PackageHint{{Ecosystem: "npm", Name: "express"}}}},
	}
)

// fake is a Backend over an in-memory store, so tests need no files for the
// state. Like the real one it opens a fresh session per call.
type fake struct {
	mu       sync.Mutex
	cfg      *config.Bundle
	st       store.Storage
	reads    int
	writes   int
	settings int          // settings sessions opened
	active   atomic.Int32 // backend calls started and not yet finished
	disk     string       // when set, every session loads the configuration from this folder, like the real backend
}

func (f *fake) busy() bool { return f.active.Load() > 0 }

func (f *fake) session(write bool) (*ops.Session, error) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	var s *ops.Session
	var err error
	cfg := f.cfg
	if f.disk != "" {
		if cfg, err = config.LoadLenient(f.disk); err != nil {
			return nil, err
		}
	}
	if write {
		s, err = ops.OpenWith(cfg, f.st, log)
	} else {
		s, err = ops.OpenReadOnlyWith(cfg, f.st, log)
	}
	if err != nil {
		return nil, err
	}
	s.Actor, s.Now = actor(), func() time.Time { return tNow }
	return s, nil
}

func (f *fake) Read(fn func(*ops.Session) error) error {
	f.active.Add(1)
	defer f.active.Add(-1)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads++
	s, err := f.session(false)
	if err != nil {
		return err
	}
	defer s.Close()
	return fn(s)
}

// Settings opens the documents of the configuration folder, as the real
// backend does: without loading the configuration, so a broken one opens too.
func (f *fake) Settings(fn func(*ops.SettingsSession) error) error {
	f.active.Add(1)
	defer f.active.Add(-1)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.settings++
	root := f.disk
	if root == "" {
		root = f.cfg.Root
	}
	ss, err := ops.OpenSettings(root)
	if err != nil {
		return err
	}
	ss.Actor, ss.Now = actor(), func() time.Time { return tNow }
	return fn(ss)
}

func (f *fake) Write(fn func(*ops.Session) error) error {
	f.active.Add(1)
	defer f.active.Add(-1)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writes++
	s, err := f.session(true)
	if err != nil {
		return err
	}
	defer s.Close()
	return fn(s)
}

// seed builds a ledger with three open issues:
//
//	CVE-2026-3  critical  shop/dev
//	CVE-2026-1  high      shop/prod and mw/prod, with a fix from a feed
//	CVE-2026-4  low       shop/staging
func seed(t *testing.T, mutate func(*ledger.Ledger)) store.Storage {
	t.Helper()
	l := ledger.New(ledger.State{})
	add := func(id, title string, sev model.Severity, p string, env model.Env, reasons []string) *model.Vulnerability {
		v := l.Create(model.Item{Title: title, Summary: "Summary of " + id, URL: "https://a.test/" + id, IDs: []string{id}, Severity: sev,
			Published: t0, SourceID: "hn", SourceType: "hn"}, t0, []string{"php"})
		l.AddFinding(model.Finding{VulnID: v.ID, Project: p, Env: env, Status: model.StatusOpen, Applies: model.AppUnknown,
			Matched: []string{"php@8.2"}, Reasons: reasons})
		return v
	}
	v1 := add("CVE-2026-1", "Tracked PHP bug", model.SevHigh, "shop", model.EnvProd, []string{"php 8.2 is installed"})
	l.AddFinding(model.Finding{VulnID: v1.ID, Project: "mw", Env: model.EnvProd, Status: model.StatusOpen, Applies: model.AppUnknown})
	v1.Fixes = []model.Fix{{Kind: model.FixVersion, Detail: "8.2.9", Source: "hn", Official: true}}
	add("CVE-2026-3", "Critical nginx bug", model.SevCritical, "shop", model.EnvDev, nil)
	add("CVE-2026-4", "Minor thing", model.SevLow, "shop", model.EnvStaging, nil)
	l.RecordCycle(model.CycleRecord{Started: tNow.Add(-time.Hour), Finished: tNow.Add(-time.Hour + 30*time.Second), Items: 40, New: 3, Merged: 1, Findings: 4})
	if mutate != nil {
		mutate(l)
	}
	st := store.NewMemory()
	if err := st.Save(l.State()); err != nil {
		t.Fatal(err)
	}
	return st
}

func newFake(t *testing.T, st store.Storage) *fake {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.Bundle{
		Settings: config.Settings{DataDir: filepath.Join(dir, "data"), AlertsDir: filepath.Join(dir, "alerts")},
		Root:     filepath.Join(dir, "app"),
		Techs:    testTechs,
		Sources:  []model.Source{{ID: "hn", Type: "hn"}},
		Projects: []model.Project{
			{Name: "shop", Techs: []model.ProjectTech{{Name: "php", Version: "8.2"}, {Name: "nginx"}}},
			{Name: "mw", Envs: []model.Env{model.EnvProd}},
		},
		Catalog: catalog.New(testTechs),
	}
	if st == nil {
		st = seed(t, nil)
	}
	return &fake{cfg: cfg, st: st}
}

// driver feeds messages to the model and runs the commands it returns by
// hand, feeding their results back, as the Bubble Tea runtime would.
type driver struct {
	t      *testing.T
	m      tea.Model
	quit   bool
	b      Backend
	timers []tea.Msg // what the model asked a timer to deliver; tests send them by hand
}

func start(t *testing.T, b Backend, o Options) *driver {
	t.Helper()
	if o.Refresh == 0 {
		o.Refresh = time.Hour
	}
	d := &driver{t: t, m: New(b, o), b: b}
	d.m.(*app).sys = &fakeDesktop{}
	d.m.(*app).after = func(_ time.Duration, msg tea.Msg) tea.Cmd { d.timers = append(d.timers, msg); return nil }
	d.send(tea.WindowSizeMsg{Width: 120, Height: 40})
	d.run(loadCmd(b)) // what Init does, minus the timer that would only wait
	return d
}

func (d *driver) send(msg tea.Msg) {
	var cmd tea.Cmd
	d.m, cmd = d.m.Update(msg)
	d.run(cmd)
}

// run executes a command and feeds the message back. A command that takes
// longer than a moment is a timer (the refresh tick) and is dropped.
func (d *driver) run(cmd tea.Cmd) {
	if cmd == nil {
		return
	}
	ch := make(chan tea.Msg, 1)
	go func() { ch <- cmd() }()
	start := time.Now()
	for {
		select {
		case msg := <-ch:
			switch msg := msg.(type) {
			case nil:
			case tea.BatchMsg:
				for _, c := range msg {
					d.run(c)
				}
			case tea.QuitMsg:
				d.quit = true
			default:
				d.send(msg)
			}
			return
		case <-time.After(20 * time.Millisecond):
			// A backend call still running is real work on a slow machine;
			// anything else that takes this long is a timer.
			if f, ok := d.b.(*fake); ok && f.busy() {
				continue
			}
			if time.Since(start) > 400*time.Millisecond {
				return
			}
		}
	}
}

func key(s string) tea.KeyMsg {
	switch s {
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	case "up":
		return tea.KeyMsg{Type: tea.KeyUp}
	case "down":
		return tea.KeyMsg{Type: tea.KeyDown}
	case "pgup":
		return tea.KeyMsg{Type: tea.KeyPgUp}
	case "pgdown":
		return tea.KeyMsg{Type: tea.KeyPgDown}
	case "home":
		return tea.KeyMsg{Type: tea.KeyHome}
	case "end":
		return tea.KeyMsg{Type: tea.KeyEnd}
	case "tab":
		return tea.KeyMsg{Type: tea.KeyTab}
	case "shift+tab":
		return tea.KeyMsg{Type: tea.KeyShiftTab}
	case "left":
		return tea.KeyMsg{Type: tea.KeyLeft}
	case "right":
		return tea.KeyMsg{Type: tea.KeyRight}
	case "f1":
		return tea.KeyMsg{Type: tea.KeyF1}
	case "ctrl+d":
		return tea.KeyMsg{Type: tea.KeyCtrlD}
	case "ctrl+u":
		return tea.KeyMsg{Type: tea.KeyCtrlU}
	case "ctrl+c":
		return tea.KeyMsg{Type: tea.KeyCtrlC}
	case "backspace":
		return tea.KeyMsg{Type: tea.KeyBackspace}
	case " ":
		return tea.KeyMsg{Type: tea.KeySpace, Runes: []rune{' '}}
	}
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

func (d *driver) press(keys ...string) {
	for _, k := range keys {
		d.send(key(k))
	}
}

func (d *driver) typ(s string) {
	for _, r := range s {
		d.send(key(string(r)))
	}
}

var ansi = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07]*\x07`)

// view is the screen as text, colour removed.
func (d *driver) view() string { return ansi.ReplaceAllString(d.m.View(), "") }

func (d *driver) want(parts ...string) {
	d.t.Helper()
	v := d.view()
	for _, p := range parts {
		if !strings.Contains(v, p) {
			d.t.Errorf("screen lacks %q:\n%s", p, v)
		}
	}
}

func (d *driver) wantNot(parts ...string) {
	d.t.Helper()
	v := d.view()
	for _, p := range parts {
		if strings.Contains(v, p) {
			d.t.Errorf("screen has %q:\n%s", p, v)
		}
	}
}

// click presses the left mouse button at a screen cell.
func (d *driver) click(x, y int) {
	d.send(tea.MouseMsg{X: x, Y: y, Action: tea.MouseActionPress, Button: tea.MouseButtonLeft})
}

// wheel turns the mouse wheel once at a screen cell.
func (d *driver) wheel(up bool, x, y int) {
	b := tea.MouseButtonWheelDown
	if up {
		b = tea.MouseButtonWheelUp
	}
	d.send(tea.MouseMsg{X: x, Y: y, Action: tea.MouseActionPress, Button: b})
}

func tea_window(w, h int) tea.WindowSizeMsg { return tea.WindowSizeMsg{Width: w, Height: h} }

// fakeDesktop records what the TUI asked of the machine instead of doing it.
type fakeDesktop struct {
	opened   []string
	copied   []string
	openErr  error
	copyErr  error // errNoClipboard for a machine without a tool
	copyTool string
}

func (f *fakeDesktop) Open(url string) error {
	f.opened = append(f.opened, url)
	return f.openErr
}

func (f *fakeDesktop) Copy(text string) (string, error) {
	if f.copyErr != nil {
		return "", f.copyErr
	}
	f.copied = append(f.copied, text)
	if f.copyTool == "" {
		return "faketool", nil
	}
	return f.copyTool, nil
}
