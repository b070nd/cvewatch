package tui

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// useEditorEnv makes the machine look like goos with the given environment
// variables and programs on the path.
func useEditorEnv(t *testing.T, goos string, env map[string]string, programs ...string) {
	t.Helper()
	old := editorSys
	t.Cleanup(func() { editorSys = old })
	editorSys = testEditorEnv(goos, env, programs...)
}

func testEditorEnv(goos string, env map[string]string, programs ...string) editorEnv {
	return editorEnv{
		goos: goos,
		env:  func(k string) string { return env[k] },
		have: func(name string) bool {
			for _, p := range programs {
				if p == name {
					return true
				}
			}
			return false
		},
	}
}

// noEditor is a machine with no editor to find.
func noEditor(t *testing.T) { t.Helper(); useEditorEnv(t, "linux", nil) }

func TestResolveEditor(t *testing.T) {
	for _, c := range []struct {
		name       string
		goos       string
		configured string
		env        map[string]string
		programs   []string
		want       string
		source     string
		fallback   bool
	}{
		{"setting wins over everything", "linux", "code --wait", map[string]string{"VISUAL": "vim", "EDITOR": "nano"}, []string{"nano"}, "code --wait", "tui.editor", false},
		{"setting is trimmed", "linux", "  micro  ", nil, nil, "micro", "tui.editor", false},
		{"blank setting is not set", "linux", "   ", map[string]string{"VISUAL": "vim"}, nil, "vim", "$VISUAL", false},
		{"visual before editor", "linux", "", map[string]string{"VISUAL": "vim", "EDITOR": "nano"}, nil, "vim", "$VISUAL", false},
		{"blank visual falls to editor", "linux", "", map[string]string{"VISUAL": " ", "EDITOR": "nano -w"}, nil, "nano -w", "$EDITOR", false},
		{"set editor is used even when missing", "linux", "", map[string]string{"EDITOR": "ghost"}, nil, "ghost", "$EDITOR", false},
		{"linux sensible-editor first", "linux", "", nil, []string{"vi", "nano", "sensible-editor"}, "sensible-editor", "fallback", true},
		{"linux editor second", "linux", "", nil, []string{"vi", "editor", "nano"}, "editor", "fallback", true},
		{"linux nano", "linux", "", nil, []string{"vi", "vim", "nano"}, "nano", "fallback", true},
		{"linux vim", "linux", "", nil, []string{"vi", "vim"}, "vim", "fallback", true},
		{"linux vi", "linux", "", nil, []string{"vi"}, "vi", "fallback", true},
		{"freebsd uses the linux chain", "freebsd", "", nil, []string{"nano"}, "nano", "fallback", true},
		{"darwin nano", "darwin", "", nil, []string{"nano", "vim", "open"}, "nano", "fallback", true},
		{"darwin vi", "darwin", "", nil, []string{"vi", "open"}, "vi", "fallback", true},
		{"darwin has no sensible-editor", "darwin", "", nil, []string{"sensible-editor", "editor"}, "", "", false},
		{"darwin last resort is TextEdit", "darwin", "", nil, []string{"open"}, "open -W -t", "fallback", true},
		{"windows notepad", "windows", "", nil, []string{"notepad", "nano"}, "notepad", "fallback", true},
		{"nothing found", "linux", "", nil, nil, "", "", false},
		{"windows nothing found", "windows", "", nil, []string{"vim"}, "", "", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, ok := resolveEditor(c.configured, testEditorEnv(c.goos, c.env, c.programs...))
			if ok != (c.want != "") {
				t.Fatalf("found %v, want %q", ok, c.want)
			}
			if got.Command != c.want || got.Source != c.source || got.Fallback != c.fallback {
				t.Fatalf("got %+v", got)
			}
		})
	}
}

func TestEditorFallbackIsNamedAfterwards(t *testing.T) {
	if n := (editorChoice{Command: "vim", Source: "$EDITOR"}).note(); n != "" {
		t.Errorf("a chosen editor needs no note: %q", n)
	}
	n := editorChoice{Command: "nano", Source: "fallback", Fallback: true}.note()
	if !strings.Contains(n, "nano") || !strings.Contains(n, "tui.editor") {
		t.Errorf("note %q", n)
	}
	// the fallback command still gets the line where the editor takes one
	f := filepath.FromSlash("/p/shop.yaml")
	if got := strings.Join(editorArgv("open -W -t", f, 4), " "); got != "open -W -t "+f {
		t.Errorf("argv %q", got)
	}
	if got := strings.Join(editorArgv("nano", f, 4), " "); got != "nano +4 "+f {
		t.Errorf("argv %q", got)
	}
}

func TestEditorEndsWithTheFallbackNote(t *testing.T) {
	b := newFake(t, nil)
	d := start(t, b, Options{})
	a := d.m.(*app)
	out := a.result(editedMsg{note: "edited with nano, the first editor found"})
	if out.note == "" || out.err != nil {
		t.Fatalf("outcome %+v", out)
	}
	if out = a.result(editedMsg{err: errors.New("boom")}); out.err == nil {
		t.Fatalf("outcome %+v", out)
	}
}

func TestLaunchEditorUsesTheSettingThenTheFallbacks(t *testing.T) {
	file := filepath.Join(t.TempDir(), "shop.yaml")

	b := newFake(t, nil)
	noEditor(t)
	d := start(t, b, Options{})
	a := d.m.(*app)
	if cmd := a.launchEditor(file, 0, "editing shop...", reList); cmd != nil {
		t.Fatal("nothing to run")
	}
	for _, want := range []string{"no editor found", "tui.editor", "EDITOR", file} {
		if !strings.Contains(a.flash, want) {
			t.Errorf("flash %q lacks %q", a.flash, want)
		}
	}
	if len(a.pend.ops) != 0 {
		t.Fatal("nothing is pending when there is no editor")
	}

	useEditorEnv(t, "linux", nil, "vi")
	if cmd := a.launchEditor(file, 0, "editing shop...", reList); cmd == nil {
		t.Fatal("a usual editor is found")
	}
	a.pend.end(a.pend.ops[0].id)

	noEditor(t)
	b.cfg.TUI.Editor = "true"
	if cmd := a.launchEditor(file, 0, "editing shop...", reList); cmd == nil {
		t.Fatal("tui.editor is used")
	}
}
