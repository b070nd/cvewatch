package tui

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/b070nd/cvewatch/app/src/ledger"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/ops"
	"github.com/b070nd/cvewatch/app/src/store"
)

func TestStatusScreen(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	d.press("4")
	d.want("[4 Status]", "Feeds (1)", "hn", "UNKNOWN", "never", "Channels (0)", "none active", "Recent cycles (1)", "30s", "daemon")
}

func TestStatusShowsFailingFeed(t *testing.T) {
	st := seed(t, func(l *ledger.Ledger) {
		for i := 0; i < 3; i++ {
			l.SourceOutcome("hn", "hn", tNow, 0, errors.New("boom \x1b[31mred\x1b[0m"))
		}
	})
	d := start(t, newFake(t, st), Options{})
	d.press("4")
	d.want("FAIL", "error: boom red")
	d.wantNot("\x1b")
	d.press("1")
	d.want("Warnings", "feed hn has failed 3 times in a row")
}

func TestUntrustedTextIsStripped(t *testing.T) {
	evil := "Pwn\x1b[31m red\x1b]0;owned-title\x07 ‮evil\x00\x08 end"
	st := seed(t, func(l *ledger.Ledger) {
		v := l.Lookup([]string{"CVE-2026-4"})
		v.Title = evil
		v.Summary = "desc\x1b[2J\x1b[Hscreen"
		v.Fixes = []model.Fix{{Kind: model.FixPatch, Detail: "fix\x1b]52;c;QQ==\x07it", Source: "x\u009b31m"}}
		l.AddFinding(model.Finding{VulnID: v.ID, Project: "mw", Env: model.EnvProd, Status: model.StatusOpen, Note: "n\x1b[1mote", Owner: "ow\x1bner"})
	})
	d := start(t, newFake(t, st), Options{})
	const bad = "\x1b\x07\x00\x08\u202e\u009b\ufffd"
	d.press("2")
	if v := d.view(); strings.ContainsAny(v, bad) {
		t.Fatalf("control characters reached the list: %q", v)
	}
	// Part of the text is already cut by the read model (query.Clip drops ESC
	// and keeps the rest, which can do nothing without it); the TUI removes
	// whole sequences from the fields that arrive raw.
	d.want("Pwn", "evil end")
	d.press("down", "down", "enter")
	d.want("Pwn", "evil end", "desc", "screen", "note: note", "owner ower")
	if v := d.view(); strings.ContainsAny(v, bad) {
		t.Fatalf("control characters reached the detail view: %q", v)
	}
}

func TestCleanText(t *testing.T) {
	for in, want := range map[string]string{
		"plain":                         "plain",
		"a\x1b[31mb\x1b[0mc":            "abc",
		"a\x1b]0;title\x07b":            "ab",
		"a\x1b]8;;http://x\x1b\\link":   "alink",
		"a\x1bPdcs data\x1b\\b":         "ab",
		"a\x1bcb":                       "ab",
		"tab\there\nnew\r\nline":        "tab here new  line",
		"bidi‮txt​":                     "biditxt",
		"nul\x00bell\x07":               "nulbell",
		"bad\xffutf8":                   "bad�utf8",
		"c1\u009b31mx":                  "c131mx",
		"unterminated \x1b]0;never":     "unterminated ",
		"":                              "",
		"emoji ✔ and 日本語":               "emoji ✔ and 日本語",
		"\x1b[?25l\x1b[1;1Hhide cursor": "hide cursor",
	} {
		if got := clean(in); got != want {
			t.Errorf("clean(%q) = %q, want %q", in, got, want)
		}
	}
	if got := oneLine("  a \n\t b  "); got != "a b" {
		t.Errorf("oneLine = %q", got)
	}
}

func TestTextHelpers(t *testing.T) {
	if got := trunc("hello world", 8); got != "hello w…" || width(got) != 8 {
		t.Errorf("trunc = %q", got)
	}
	if got := pad("日本", 6); width(got) != 6 {
		t.Errorf("pad of wide text = %q (%d cells)", got, width(got))
	}
	if got := trunc("日本語日本語", 5); width(got) > 5 {
		t.Errorf("trunc of wide text = %q", got)
	}
	lines := wrap("the quick brown fox jumps over a lazy dog supercalifragilistic", 12)
	for _, l := range lines {
		if width(l) > 12 {
			t.Errorf("wrapped line too long: %q", l)
		}
	}
	if strings.ReplaceAll(strings.Join(lines, ""), " ", "") != strings.ReplaceAll("the quick brown fox jumps over a lazy dog supercalifragilistic", " ", "") {
		t.Errorf("wrap lost text: %q", lines)
	}
	if clamp(5, 0, -1) != 0 || clamp(-3, 0, 4) != 0 || clamp(9, 0, 4) != 4 {
		t.Error("clamp")
	}
}

func TestInputEditing(t *testing.T) {
	var in input
	in.set("hello")
	in.key(key("backspace"))
	in.key(tea.KeyMsg{Type: tea.KeyLeft})
	in.key(key("X"))
	if in.String() != "helXl" {
		t.Fatalf("got %q", in.String())
	}
	in.key(tea.KeyMsg{Type: tea.KeyCtrlW})
	in.insert([]rune("a\x1b[b\nc"))
	if strings.ContainsAny(in.String(), "\x1b\n") {
		t.Fatalf("control characters entered the field: %q", in.String())
	}
	in.set(strings.Repeat("x", 500))
	if len(in.v) != maxInput {
		t.Fatalf("length %d", len(in.v))
	}
	if w := width(in.view(10, true)); w > 10 {
		t.Fatalf("view is %d cells", w)
	}
}

func TestResizeDoesNotPanic(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	sizes := [][2]int{{0, 0}, {1, 1}, {10, 3}, {29, 7}, {30, 8}, {40, 10}, {60, 12}, {80, 24}, {120, 40}, {300, 100}}
	check := func(label string) {
		for _, sz := range sizes {
			d.send(tea.WindowSizeMsg{Width: sz[0], Height: sz[1]})
			v := d.m.View()
			if sz[1] >= 8 {
				if n := strings.Count(v, "\n") + 1; n > sz[1] {
					t.Errorf("%s at %dx%d: %d lines", label, sz[0], sz[1], n)
				}
				for _, l := range strings.Split(ansi.ReplaceAllString(v, ""), "\n") {
					if w := width(l); w > max(sz[0], 30) {
						t.Errorf("%s at %dx%d: line is %d cells: %q", label, sz[0], sz[1], w, l)
					}
				}
			}
		}
	}
	for _, s := range []string{"1", "2", "3", "4"} {
		d.press(s)
		check("screen " + s)
	}
	d.press("2", "down", "enter")
	check("detail")
	d.press("f")
	check("prompt")
	d.press("esc", "esc", "3", "n")
	check("form")
	d.press("esc", "?")
	check("help")
}

func TestQuit(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	d.press("q")
	if !d.quit {
		t.Fatal("q must quit")
	}
	d = start(t, newFake(t, nil), Options{})
	d.press("ctrl+c")
	if !d.quit {
		t.Fatal("ctrl+c must quit")
	}
	d = start(t, newFake(t, nil), Options{})
	d.press("3", "n", "ctrl+u")
	d.typ("q")
	if d.quit {
		t.Fatal("q typed into a text step quit")
	}
	d.want("> q")
	d.press("ctrl+c")
	if !d.quit {
		t.Fatal("ctrl+c quits from a form")
	}
}

func TestHelpToggle(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	d.press("2", "?")
	d.want("Keys on the findings screen", "open the selected issue", "Everywhere", "NO_COLOR")
	d.press("?")
	d.want("3 of 3 open issues")
	d.press("?", "esc")
	d.want("3 of 3 open issues")
	d.press("enter", "?")
	d.want("Keys in an issue", "not-affected needs a reason", "NO_COLOR")
	d.press("q") // q closes a popup, it does not quit
	if d.quit {
		t.Fatal("q in the help quit the program")
	}
	d.wantNot("Keys in an issue")
	d.want("Environments")
}

func TestScreenSwitching(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	d.press("tab")
	d.want("[2 Findings")
	d.press("tab", "tab", "tab")
	d.want("[1 Overview]")
	d.press("shift+tab")
	d.want("[4 Status]")
}

func TestRefreshKeyAndTick(t *testing.T) {
	b := newFake(t, nil)
	d := start(t, b, Options{})
	before := b.reads
	d.press("r")
	if b.reads != before+1 {
		t.Fatalf("r must read once, reads %d -> %d", before, b.reads)
	}

	// a change made by someone else (the daemon, the CLI) shows up on the tick
	if err := b.Write(func(s *ops.Session) error {
		_, err := s.Resolve(ops.Change{ID: "CVE-2026-4", Project: "shop", Status: model.StatusFixed})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	d.press("2")
	d.want("3 of 3 open issues")
	d.send(tickMsg{})
	d.want("2 of 2 open issues")
	d.wantNot("Minor thing")
}

func TestRefreshKeepsTheSelectedIssue(t *testing.T) {
	b := newFake(t, nil)
	d := start(t, b, Options{})
	d.press("2", "down", "down")
	d.want("> low")
	if err := b.Write(func(s *ops.Session) error {
		_, err := s.Resolve(ops.Change{ID: "CVE-2026-3", Project: "shop", Status: model.StatusFixed})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	d.press("r")
	d.want("2 of 2 open issues", "> low") // the cursor followed its issue
}

func TestLoadErrorIsShownAndRecovers(t *testing.T) {
	b := newFake(t, nil)
	bad := &flaky{Backend: b, fail: errors.New("disk on fire")}
	d := start(t, bad, Options{})
	d.want("error: disk on fire")
	bad.fail = nil
	d.press("r")
	d.want("open issues", "[1 Overview]")
	d.wantNot("disk on fire")
	bad.fail = errors.New("later trouble")
	d.press("r")
	d.want("open issues", "refresh failed: later trouble") // stale data stays visible
}

type flaky struct {
	Backend
	fail error
}

func (f *flaky) Read(fn func(*ops.Session) error) error {
	if f.fail != nil {
		return f.fail
	}
	return f.Backend.Read(fn)
}

func TestEmptyLedger(t *testing.T) {
	d := start(t, newFake(t, store.NewMemory()), Options{})
	d.want("open issues", "none") // no violations
	d.press("2")
	d.want("Nothing open. No open vulnerabilities to act on.")
	d.press("enter", "s", "/", "esc")
	d.press("3")
	d.want("shop")
	d.press("4")
	d.want("no cycle has run yet")
}

func TestOptionsDefaults(t *testing.T) {
	if (Options{}).refresh() != 30*time.Second || (Options{Refresh: time.Minute}).refresh() != time.Minute {
		t.Fatal("refresh default is 30s")
	}
}

func TestNewBackendOpensPerCallAsATuiActor(t *testing.T) {
	root := filepath.Join(t.TempDir(), "app")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	b := NewBackend(root, nil)
	if err := b.Read(func(s *ops.Session) error {
		if !strings.HasPrefix(s.Actor, "tui:") {
			t.Errorf("read actor %q", s.Actor)
		}
		if err := s.Commit(); !errors.Is(err, ops.ErrReadOnly) {
			t.Errorf("a read session must be read-only, Commit gave %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := b.Write(func(s *ops.Session) error {
		if !strings.HasPrefix(s.Actor, "tui:") {
			t.Errorf("write actor %q", s.Actor)
		}
		return s.Commit()
	}); err != nil {
		t.Fatal(err)
	}
	// the write session was closed, so a second one can open at once
	if err := b.Write(func(*ops.Session) error { return nil }); err != nil {
		t.Fatalf("the write lock must be released after each call: %v", err)
	}
	if err := b.Read(func(*ops.Session) error { return errors.New("from fn") }); err == nil || err.Error() != "from fn" {
		t.Fatalf("fn errors pass through: %v", err)
	}
}

func TestCountsOf(t *testing.T) {
	b := newFake(t, nil)
	read(t, b, func(s *ops.Session) {
		sn, err := loadSnapshot(s)
		if err != nil {
			t.Fatal(err)
		}
		c := countsOf(sn.Issues)
		if c.Issues != 3 || c.Findings != 4 || c.BySev[4] != 1 || c.BySev[3] != 1 || c.BySev[1] != 1 || c.ByEnv[model.EnvProd] != 2 || c.ProdOpen != 1 || c.KEV != 0 {
			t.Fatalf("%+v", c)
		}
		if len(sn.Projects) != 2 || sn.Projects[0].Name != "shop" || len(sn.Projects[1].Envs) != 1 || len(sn.Projects[0].Envs) != 4 {
			t.Fatalf("projects %+v", sn.Projects)
		}
	})
}
