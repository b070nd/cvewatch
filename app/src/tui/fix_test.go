package tui

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/b070nd/cvewatch/app/src/ops"
)

func writeProjectFile(t *testing.T, root, name, body string) string {
	t.Helper()
	dir := filepath.Join(root, "config", "projects")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name+".yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const shopWithProblems = "name: shop\ntechs:\n  - {name: pph, version: \"8.2\"}\n  - {name: nginx}\nlockfiles:\n  - {type: composer, path: gone/composer.lock}\n"

func TestProjectsShowProblemBadgeAndIssueList(t *testing.T) {
	b := newFake(t, nil)
	writeProjectFile(t, b.cfg.Root, "shop", shopWithProblems)
	d := start(t, b, Options{})
	d.press("3")
	d.want("PROBLEMS", "1 err 1 warn", "problems (enter to select them, x to fix)",
		"> error", "lockfiles[0].path: lockfile gone/composer.lock does not exist", "fix: remove lockfile gone/composer.lock",
		"warning", "techs[0]")
	d.press("p")
	d.want("> warning", `fix: use technology name "php" instead of "pph"`)
	d.press("p")
	d.want("> error")
	d.press("down")
	d.wantNot("problems (enter")
	if b.reads > 1 {
		t.Fatalf("problems must be computed on load, not per key: %d reads", b.reads)
	}
}

func TestProblemFixShowsTheChangeAndAppliesIt(t *testing.T) {
	b := newFake(t, nil)
	path := writeProjectFile(t, b.cfg.Root, "shop", shopWithProblems)
	d := start(t, b, Options{})
	d.press("3", "f")
	d.want("Fix project: shop", "remove lockfile gone/composer.lock", "-", "composer.lock", "Apply this fix?")
	d.press("esc")
	d.want("cancelled", "1 err 1 warn")
	if b.writes != 0 {
		t.Fatal("cancelling wrote something")
	}

	d.press("f", "y")
	d.want("ok: fixed shop: remove lockfile gone/composer.lock", "1 warn")
	d.wantNot("1 err")
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "composer.lock") || !strings.Contains(string(data), "pph") {
		t.Fatalf("only the lockfile may go:\n%s", data)
	}
	if b.writes != 1 {
		t.Fatalf("applying is one write session, got %d", b.writes)
	}

	d.press("f", "y") // the misspelled technology
	d.want("ok: fixed shop")
	d.wantNot("1 warn", "problems (enter")
	data, _ = os.ReadFile(path)
	if !strings.Contains(string(data), "php") || strings.Contains(string(data), "pph") {
		t.Fatalf("technology not renamed:\n%s", data)
	}
	d.press("f")
	d.want("error: no problems to fix here")
}

func TestProblemWithoutFixPointsToTheEditor(t *testing.T) {
	b := newFake(t, nil)
	writeProjectFile(t, b.cfg.Root, "shop", "name: shop\ntechs:\n  - {name: php, version: latest}\n")
	d := start(t, b, Options{})
	d.press("3")
	d.want("1 warn", "does not look like a version number")
	d.wantNot("fix:")
	d.press("f")
	d.want("error: no automatic fix for this problem; press E to edit the file")
	if d.m.(*app).prj.fix != nil {
		t.Fatal("no fix to preview")
	}
}

func TestBrokenProjectFileDoesNotBlockTheTUI(t *testing.T) {
	root := t.TempDir()
	writeProjectFile(t, root, "good", "name: good\ntechs:\n  - {name: php}\n")
	bad := writeProjectFile(t, root, "bad", "name: [\n")
	t.Setenv("EDITOR", "")
	d := start(t, NewBackend(root, nil), Options{})
	d.want("1 Overview")
	d.wantNot("refresh failed")
	d.press("3")
	d.want("good", "bad", "BROKEN")
	d.press("down")
	d.want("broken: yaml:", "file: ")
	if row, _ := d.m.(*app).selectedProject(); row.File != bad || strings.Contains(row.Broken, bad) {
		t.Fatalf("broken row %+v", row)
	}
	d.press("e")
	d.want("error: the file of bad does not load; press E to edit it")
	d.press("E")
	if f := d.m.(*app).flash; !strings.Contains(f, "$EDITOR is not set; the file is "+bad) {
		t.Fatalf("flash %q", f)
	}

	t.Setenv("EDITOR", "true")
	if cmd := d.m.(*app).openEditor(); cmd == nil {
		t.Fatal("with $EDITOR set the file is opened")
	}

	// the editor returns with a repaired file
	os.WriteFile(bad, []byte("name: bad\ntechs:\n  - {name: php}\n"), 0o600)
	d.send(opMsg{id: d.m.(*app).pend.ops[0].id, msg: editedMsg{}})
	d.wantNot("BROKEN")
	d.want("bad", "good")
	d.press("e")
	d.want("Edit project: ")
}

type failing struct{}

func (failing) Read(func(*ops.Session) error) error  { return errors.New("no config here") }
func (failing) Write(func(*ops.Session) error) error { return errors.New("no config here") }
func (failing) Settings(func(*ops.SettingsSession) error) error {
	return errors.New("no config here")
}

func TestLoadFailureStillOffersRetryAndQuit(t *testing.T) {
	d := start(t, failing{}, Options{})
	d.want("error: no config here", "Press r to try again", "r try again  q quit")
	d.press("3", "n", "d", "f", "o")
	d.want("Press r to try again")
	if d.m.(*app).frm != nil || d.m.(*app).prm != nil {
		t.Fatal("nothing can start without data")
	}
	d.press("q")
	if !d.quit {
		t.Fatal("q must quit")
	}
}
