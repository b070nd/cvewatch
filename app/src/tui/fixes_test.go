package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// shopTwoFixes has a lockfile for an environment that is not monitored: the
// problem can be fixed by monitoring it or by dropping the lockfile.
const shopTwoFixes = "name: shop\nenvs: [prod]\ntechs:\n  - {name: php, version: \"8.2\"}\nlockfiles:\n  - {type: composer, path: x/composer.lock, env: dev}\n"

func twoFixesFake(t *testing.T) (*fake, string) {
	t.Helper()
	b := newFake(t, nil)
	if err := os.MkdirAll(filepath.Join(b.cfg.Root, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(b.cfg.Root, "x", "composer.lock"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	return b, writeProjectFile(t, b.cfg.Root, "shop", shopTwoFixes)
}

func TestProjectLevelShowsEveryFixAndPreviewsTheChosenOne(t *testing.T) {
	b, path := twoFixesFake(t)
	d := start(t, b, Options{})
	d.press("3", "enter")
	d.want("fix 1: monitor environment dev", "fix 2: remove lockfile x/composer.lock for dev", "[ and ] choose another", "[/] fix")
	d.press("]")
	d.want("> fix 2: remove lockfile")
	d.press("x")
	d.want("Fix project: shop", "fix 2 of 2: remove lockfile x/composer.lock for dev", "(line 6)", "Apply this fix?", "[/] fix")
	d.press("[")
	d.want("fix 1 of 2: monitor environment dev", "+ envs: [prod, dev]")
	d.wantNot("fix 2 of 2")
	d.press("right")
	d.want("fix 2 of 2: remove lockfile")
	d.press("left", "left") // wraps around
	d.want("fix 2 of 2")
	d.press("l")
	d.want("fix 1 of 2")
	if b.writes != 0 {
		t.Fatal("choosing wrote")
	}
	d.press("esc")
	d.want("cancelled")
	d.press("x") // the choice is remembered for this problem
	d.want("fix 1 of 2")
	d.press("]", "enter")
	d.want("ok: fixed shop: remove lockfile x/composer.lock for dev")
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "composer.lock") || strings.Contains(string(data), "dev") {
		t.Fatalf("the second fix was applied:\n%s", data)
	}
}

func TestFixPreviewWithOneFixKeepsLeftAsCancel(t *testing.T) {
	b := newFake(t, nil)
	writeProjectFile(t, b.cfg.Root, "shop", shopWithProblems)
	d := start(t, b, Options{})
	d.press("3", "x")
	d.want("Fix project: shop", "esc cancel")
	d.wantNot("fix 1 of")
	d.press("]")
	d.want("Fix project: shop") // nothing to choose
	d.press("left")
	d.want("cancelled")
}

func TestAnAnswerForAnotherFixIsDropped(t *testing.T) {
	b, _ := twoFixesFake(t)
	d := start(t, b, Options{})
	d.press("3", "x")
	a := d.m.(*app)
	fx := a.prj.fix
	d.press("]")
	if fx.seq != 2 || fx.ci != 1 {
		t.Fatalf("seq %d ci %d", fx.seq, fx.ci)
	}
	d.send(fixPreviewMsg{fx: fx, seq: 1, err: os.ErrClosed}) // the first fix's answer, late
	if fx.err != "" {
		t.Fatalf("a stale preview was taken: %q", fx.err)
	}
}

func TestEditorArgv(t *testing.T) {
	f := filepath.FromSlash("/p/shop.yaml")
	for _, c := range []struct {
		editor string
		line   int
		want   string
	}{
		{"vim", 12, "vim +12 " + f},
		{"nvim", 3, "nvim +3 " + f},
		{"/usr/bin/vi", 3, "/usr/bin/vi +3 " + f},
		{"nano", 7, "nano +7 " + f},
		{"emacs -nw", 7, "emacs -nw +7 " + f},
		{"micro", 7, "micro +7 " + f},
		{"vim -u NONE", 5, "vim -u NONE +5 " + f},
		{"code --wait", 12, "code --wait -g " + f + ":12"},
		{"subl", 12, "subl " + f + ":12"},
		{"vim", 0, "vim " + f},   // no line known
		{"code", 0, "code " + f}, // likewise
		{"ed", 12, "ed " + f},    // an editor that is not known to take a line
		{"myeditor -x", 12, "myeditor -x " + f},
		{"VIM.EXE", 4, "VIM.EXE +4 " + f},
	} {
		if got := strings.Join(editorArgv(c.editor, f, c.line), " "); got != c.want {
			t.Errorf("editorArgv(%q, %d) = %q, want %q", c.editor, c.line, got, c.want)
		}
	}
	if editorArgv("  ", f, 3) != nil {
		t.Error("no editor, no command")
	}
}

func TestEditorOpensAtTheLineOfTheProblemOnlyInsideTheProject(t *testing.T) {
	b, _ := twoFixesFake(t)
	d := start(t, b, Options{})
	d.press("3")
	a := d.m.(*app)
	p, _ := a.selectedProject()
	if len(p.Problems) != 1 || p.Problems[0].Line != 6 {
		t.Fatalf("problems %+v", p.Problems)
	}
	t.Setenv("EDITOR", "vim")
	if got := a.editorLine(p); got != 0 {
		t.Fatalf("from the list the file opens at the top: %d", got)
	}
	d.press("enter")
	if got := a.editorLine(p); got != 6 {
		t.Fatalf("inside the project: line %d", got)
	}
	cmd := a.openEditor()
	if cmd == nil || a.pend.count() != 1 {
		t.Fatal("the editor is an operation")
	}
}

func TestProblemLinesAreFilledByOps(t *testing.T) {
	b := newFake(t, nil)
	writeProjectFile(t, b.cfg.Root, "shop", shopWithProblems)
	d := start(t, b, Options{})
	p, _ := d.m.(*app).selectedProject()
	lines := map[string]int{}
	for _, is := range p.Problems {
		lines[is.Field] = is.Line
	}
	if lines["lockfiles[0].path"] != 6 || lines["techs[0]"] != 3 {
		t.Fatalf("lines %v", lines)
	}
}
