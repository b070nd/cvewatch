package tui

import (
	"io"
	"log/slog"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
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
	mu     sync.Mutex
	cfg    *config.Bundle
	st     store.Storage
	reads  int
	writes int
}

func (f *fake) session(write bool) (*ops.Session, error) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	var s *ops.Session
	var err error
	if write {
		s, err = ops.OpenWith(f.cfg, f.st, log)
	} else {
		s, err = ops.OpenReadOnlyWith(f.cfg, f.st, log)
	}
	if err != nil {
		return nil, err
	}
	s.Actor, s.Now = actor(), func() time.Time { return tNow }
	return s, nil
}

func (f *fake) Read(fn func(*ops.Session) error) error {
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

func (f *fake) Write(fn func(*ops.Session) error) error {
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
	t    *testing.T
	m    tea.Model
	quit bool
	b    Backend
}

func start(t *testing.T, b Backend, o Options) *driver {
	t.Helper()
	if o.Refresh == 0 {
		o.Refresh = time.Hour
	}
	d := &driver{t: t, m: New(b, o), b: b}
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
	case <-time.After(400 * time.Millisecond):
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
	case "tab":
		return tea.KeyMsg{Type: tea.KeyTab}
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

func tea_window(w, h int) tea.WindowSizeMsg { return tea.WindowSizeMsg{Width: w, Height: h} }

func lock(p string) model.Lockfile { return model.Lockfile{Type: "composer", Path: p} }
