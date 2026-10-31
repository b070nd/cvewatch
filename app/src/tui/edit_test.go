package tui

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/b070nd/cvewatch/app/src/projectfile"
	"github.com/b070nd/cvewatch/app/src/setup"
)

const (
	editShop = "# the shop\nname: shop   # prod webshop\nenvs: [dev, prod]\ntechs:\n  - {name: php, version: \"8.2\"}   # runtime\n  - {name: nginx}\n" +
		"lockfiles:\n  - {type: composer, path: repos/shop/composer.lock}\nsince: 2026-01-01\nenvironments:\n  prod:\n    techs: {php: \"8.2.30\"}\n    image: reg/shop:1\n"
	editMW = "name: mw\nenvs: [prod]\n"
)

// diskFake is a backend whose configuration is read from files on every
// session, like the real one, so a change made on disk is seen by the next call.
// dropFile as the content of a default file leaves that file out.
const dropFile = "\x00drop"

func diskFake(t *testing.T, files map[string]string) (*fake, string) {
	t.Helper()
	root := t.TempDir()
	all := map[string]string{
		"config/projects/shop.yaml": editShop, "config/projects/mw.yaml": editMW,
		"repos/shop/composer.lock": `{"packages":[]}`, "repos/other/composer.lock": `{"packages":[]}`,
	}
	for k, v := range files {
		if v == dropFile {
			delete(all, k)
			continue
		}
		all[k] = v
	}
	for rel, body := range all {
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return &fake{st: seed(t, nil), disk: root}, root
}

func fileAt(t *testing.T, root, rel string) string {
	t.Helper()
	return readFile(t, filepath.Join(root, filepath.FromSlash(rel)))
}

func (d *driver) exists(root, rel string) bool {
	_, err := os.Stat(filepath.Join(root, filepath.FromSlash(rel)))
	return err == nil
}

// opKinds are the kinds of the edits in the preview that is on screen.
func (d *driver) opKinds() []string {
	d.t.Helper()
	fx := d.m.(*app).prj.fix
	if fx == nil {
		d.t.Fatalf("no preview on screen:\n%s", d.view())
	}
	var ks []string
	for _, o := range fx.fix.Ops {
		ks = append(ks, o.Kind)
	}
	return ks
}

// toField selects the n-th field of the editor (0 environments ... 4 since).
func (d *driver) toField(n int) {
	d.press("home")
	for range n {
		d.press("down")
	}
}

func TestFieldEditorEditsEveryKindOfFieldAndKeepsComments(t *testing.T) {
	b, root := diskFake(t, nil)
	d := start(t, b, Options{})
	seen := map[string]bool{}
	save := func(note string, kinds ...string) {
		t.Helper()
		d.want("Save this change?", "Edit project: shop")
		for _, k := range d.opKinds() {
			seen[k] = true
		}
		if got := d.opKinds(); !slices.Equal(got, kinds) {
			t.Fatalf("ops %v, want %v", got, kinds)
		}
		before := b.writes
		d.press("y")
		d.want("ok: saved shop: " + note)
		if b.writes != before+1 {
			t.Fatalf("saving is one write session, got %d", b.writes-before)
		}
		for _, c := range []string{"# the shop", "# prod webshop", "# runtime"} {
			if !strings.Contains(fileAt(t, root, "config/projects/shop.yaml"), c) {
				t.Fatalf("the comment %q was lost:\n%s", c, fileAt(t, root, "config/projects/shop.yaml"))
			}
		}
	}
	d.press("3", "down", "enter")
	d.want("c edits the fields")
	d.press("c")
	d.want("Edit fields of shop", "FIELD", "Environments", "dev, prod", "Technologies", "php 8.2, nginx", "1 lockfile", "Differences per environment", "prod: php 8.2.30, image reg/shop:1", "2026-01-01")
	if b.writes != 0 {
		t.Fatal("looking wrote something")
	}

	// since: a text prompt that starts with the current value
	d.toField(4)
	d.press("enter")
	d.want("Since date of shop", "> Since", "2026-01-01", "YYYY-MM-DD", "older advisories are ignored", "reopens them")
	d.press("ctrl+u")
	d.typ("2026-03-05")
	d.press("enter")
	if got := fileAt(t, root, "config/projects/shop.yaml"); !strings.Contains(got, "2026-01-01") {
		t.Fatalf("nothing is written before the user says yes:\n%s", got)
	}
	d.want("- since: 2026-01-01", "+ since: 2026-03-05")
	save("set since to 2026-03-05", "set_since")
	d.want("Edit fields of shop", "2026-03-05")
	d.toField(4)
	d.press("enter", "ctrl+u", "enter")
	d.want("clear since")
	save("clear since", "set_since")
	if strings.Contains(fileAt(t, root, "config/projects/shop.yaml"), "since:") {
		t.Fatal("an empty date clears since")
	}

	// environments: free names, added, renamed and removed one at a time
	d.toField(0)
	d.press("enter")
	d.want("ENVIRONMENT", "USED BY", "> dev", "prod", "2 differences", "+ add an environment")
	d.press("+")
	d.want("Add an environment to shop", "suggested: local, int, staging")
	d.typ("QA")
	d.press("enter")
	save("add environment qa", "add_env")
	if got := fileAt(t, root, "config/projects/shop.yaml"); !strings.Contains(got, "qa") {
		t.Fatalf("envs:\n%s", got)
	}
	d.want("ENVIRONMENT", "qa")
	d.press("down", "down", "r")
	d.want("Rename environment qa of shop", "> New name", "qa")
	d.press("ctrl+u")
	d.typ("uat-eu")
	d.press("enter")
	d.want("environment qa becomes uat-eu: 0 findings move with it")
	save("rename environment qa to uat-eu", "rename_env")
	d.want("uat-eu")
	d.press("home", "down", "down", "x")
	d.want("Remove environment uat-eu from shop?")
	d.press("y")
	save("remove environment uat-eu", "remove_env")
	if got := fileAt(t, root, "config/projects/shop.yaml"); strings.Contains(got, "uat-eu") || !strings.Contains(got, "dev, prod") {
		t.Fatalf("envs:\n%s", got)
	}
	d.press("esc")

	// technologies: a list of items
	d.toField(1)
	d.press("enter")
	d.want("TECHNOLOGY", "VERSION", "> php", "nginx", "+ add a technology")
	d.press("enter")
	d.want("Version of php in shop", "8.2")
	d.press("ctrl+u")
	d.typ("8.3")
	d.press("enter")
	save("set php to version 8.3", "set_tech")
	d.want("WHERE", "everywhere")
	d.press("e")
	d.want("Where does php run?", "Everywhere", "Only in the environments I choose")
	d.press("down", "enter")
	d.want("Environments of php", "[ ] dev", "[ ] prod")
	d.press("enter")
	d.want("problem: tick at least one")
	d.press(" ", "enter")
	save("run php only in dev", "set_tech_envs")
	d.want("only in dev")
	if got := fileAt(t, root, "config/projects/shop.yaml"); !strings.Contains(got, "envs: [dev]") {
		t.Fatalf("php is limited to dev:\n%s", got)
	}
	d.press("e", "enter")
	save("run php in every environment", "set_tech_envs")
	d.wantNot("only in dev")
	d.press("e", "enter")
	d.want("php already runs everywhere")
	d.press("a")
	d.want("Add a technology to shop", "Name", "Version")
	d.typ("nodejs")
	d.press("tab")
	d.typ("20")
	d.press("enter")
	save("add technology nodejs 20", "set_tech")
	d.press("down", "x") // nginx
	d.want("Remove technology nginx from shop?")
	d.press("y")
	d.want("remove technology nginx", "- {name: nginx}")
	save("remove technology nginx", "remove_tech")
	if strings.Contains(fileAt(t, root, "config/projects/shop.yaml"), "nginx") {
		t.Fatal("nginx should be gone")
	}

	// lockfiles: toggle dev, add through a choice then a prompt, remove
	d.press("esc")
	d.toField(2)
	d.press("enter")
	d.want("TYPE", "composer", "repos/shop/composer.lock", "+ add a lockfile")
	d.press("enter")
	d.want("mark lockfile repos/shop/composer.lock as a dev lockfile")
	save("mark lockfile repos/shop/composer.lock as a dev lockfile", "set_lockfile_dev")
	d.want("dev")
	d.press("d")
	save("mark lockfile repos/shop/composer.lock as not dev", "set_lockfile_dev")
	d.press("+")
	d.want("Add a lockfile to shop", "Lockfile:")
	d.typ(filepath.Join(root, "repos", "other", "composer.lock"))
	d.want("a composer lockfile")
	d.press("enter")
	d.want("Add a composer lockfile to shop", "Env", "Dev")
	d.wantNot("Path")
	d.typ("prod")
	d.press("tab")
	d.typ("yes")
	d.press("enter")
	d.want("+")
	save("add composer lockfile repos/other/composer.lock", "add_lockfile")
	if got := fileAt(t, root, "config/projects/shop.yaml"); !strings.Contains(got, "repos/other/composer.lock") || !strings.Contains(got, "dev: true") {
		t.Fatalf("lockfile:\n%s", got)
	}
	d.press("down", "-")
	d.want("Remove lockfile repos/other/composer.lock from shop?")
	d.press("y")
	d.want("remove lockfile repos/other/composer.lock")
	save("remove lockfile repos/other/composer.lock", "remove_lockfile")

	// differences per environment: only what differs, listed once; the old environments: block is migrated first
	d.press("esc")
	d.toField(3)
	d.press("enter")
	d.want("ENV", "DIFFERENCE", "NOTE", "prod", "php 8.2.30", "generic: 8.3", "image reg/shop:1", "+ add a difference", "old environments: block")
	d.wantNot("nginx")
	d.press("m")
	d.want("the whole old environments: block becomes when@<env> blocks", "+ when@prod:")
	save("rewrite environments: as when@<env> blocks", "migrate_envs")
	if got := fileAt(t, root, "config/projects/shop.yaml"); strings.Contains(got, "environments:") || !strings.Contains(got, "when@prod:") {
		t.Fatalf("the block is migrated:\n%s", got)
	}
	d.wantNot("old environments: block")

	d.press("home", "enter") // prod php
	d.want("Version of php in prod", "8.2.30")
	d.press("ctrl+u")
	d.typ("8.3")
	d.press("enter")
	save("set php in prod to 8.3", "set_env_tech")

	d.press("+") // an environment, then what differs in it, then how
	d.want("Which environment differs?", "> dev", "prod")
	d.press("enter")
	d.want("What differs in dev?", "php", "generic 8.3", "nodejs", "another technology", "the image")
	d.press("down", "enter")
	d.want("nodejs in dev", "another version", "it does not run there")
	d.press("down", "enter")
	save("nodejs does not run in dev", "exclude_env_tech")
	d.want("-nodejs", "does not run in dev")
	d.press("home", "x")
	d.want("Run nodejs in dev again?")
	d.press("y")
	save("run nodejs in dev again", "include_env_tech")
	d.wantNot("-nodejs")

	d.press("+", "down", "enter", "down", "down", "enter") // prod, another technology
	d.want("Add a technology to prod only", "Name", "Version")
	d.typ("redis")
	d.press("tab", "enter")
	d.want("problem: give the name of the technology and its version")
	d.typ("7")
	d.press("enter")
	save("add redis 7 to prod only", "set_env_tech")
	d.want("+redis 7", "runs only in prod")
	d.press("home", "down", "x")
	d.want("Remove redis from prod? It runs only there")
	d.press("y")
	save("remove redis from prod", "remove_env_tech")

	d.press("home", "x") // prod php: the generic version applies again
	d.want("Remove the prod version of php? The generic one applies in prod again.")
	d.press("y")
	save("remove the prod version of php", "remove_env_tech")

	// the image of an environment
	d.press("home", "enter")
	d.want("Image of shop in prod", "reg/shop:1")
	d.press("ctrl+u")
	d.typ("reg/shop:2")
	d.press("enter")
	save("set the prod image to reg/shop:2", "set_image")
	d.press("x")
	d.want("Clear the prod image of shop?")
	d.press("y")
	d.want("clear the prod image")
	save("clear the prod image", "set_image")
	if strings.Contains(fileAt(t, root, "config/projects/shop.yaml"), "reg/shop") {
		t.Fatal("the image is cleared")
	}
	d.want("+ add a difference")

	// adding an image through the picker
	d.press("+", "down", "enter", "down", "down", "down", "enter") // prod, the image
	d.want("Image of shop in prod")
	d.typ("reg/shop:3")
	d.press("enter")
	save("set the prod image to reg/shop:3", "set_image")

	// a file without envs: f writes the old default into it
	d.press("esc")
	path := filepath.Join(root, "config", "projects", "shop.yaml")
	if err := os.WriteFile(path, []byte(strings.Replace(fileAt(t, root, "config/projects/shop.yaml"), "envs: [dev, prod]\n", "", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	d.press("r")
	d.toField(0)
	d.press("enter", "f", "enter")
	save("write the old default environments into the file", "set_envs")

	for _, k := range OpKinds {
		if !seen[k] {
			t.Errorf("the editor never built a %q op", k)
		}
	}
	for k := range seen {
		if !slices.Contains(OpKinds, k) {
			t.Errorf("the editor built %q, which OpKinds does not list", k)
		}
	}
}

func TestOpKindsAreDeclaredToSetup(t *testing.T) {
	for _, k := range OpKinds {
		if !slices.Contains(setup.OpKinds, k) {
			t.Errorf("%s is built by the TUI editor but missing from setup.OpKinds", k)
		}
	}
}

func TestOpKindsAreKindsProjectfileApplies(t *testing.T) {
	for _, k := range OpKinds {
		f, err := projectfile.New("x")
		if err != nil {
			t.Fatal(err)
		}
		err = f.Apply(projectfile.Op{Kind: k})
		if err != nil && strings.Contains(err.Error(), "unknown kind") {
			t.Errorf("projectfile does not know %q", k)
		}
	}
}

func TestEditRejectionKeepsTheTypedText(t *testing.T) {
	b, root := diskFake(t, nil)
	d := start(t, b, Options{})
	d.press("3", "down", "c")
	d.toField(4)
	d.press("enter", "ctrl+u")
	d.typ("next tuesday")
	d.press("enter")
	d.want("problem:", "Since date of shop", "next tuesday")
	d.wantNot("Save this change?")
	d.press("ctrl+u")
	d.typ("2026-02-01")
	d.press("enter")
	d.want("Save this change?", "+ since: 2026-02-01")

	// an environment that does not exist is refused by the project file edit, text kept
	d.press("esc")
	d.toField(2)
	other := filepath.Join(root, "repos", "other", "composer.lock")
	d.press("enter", "+")
	d.typ(other)
	d.press("enter")
	d.typ("QA")
	d.press("enter", "enter")
	d.want("problem:", "invalid lockfile env", "Add a composer lockfile to shop", "QA")
	d.wantNot("Save this change?")
	d.press("esc")
	d.want("TYPE", "+ add a lockfile")

	// a dev answer that is neither yes nor no
	d.press("+")
	d.typ(other)
	d.press("enter", "tab")
	d.typ("maybe")
	d.press("enter")
	d.want("problem: dev is yes or no", "maybe")
	if b.writes != 0 || fileAt(t, root, "config/projects/shop.yaml") != editShop {
		t.Fatal("a rejected edit must not write")
	}
}

func TestEditPreviewCanBeCancelledAndNothingIsWritten(t *testing.T) {
	b, root := diskFake(t, nil)
	d := start(t, b, Options{})
	d.press("3", "down", "c")
	d.toField(1)
	d.press("enter", "x")
	d.want("Remove technology php from shop?")
	d.press("y")
	d.want("remove technology php", "Save this change?")
	d.press("esc")
	d.want("cancelled, nothing was saved", "TECHNOLOGY", "> php")
	d.press("x", "y")
	d.press("q") // q works like esc in a preview
	d.wantNot("Save this change?")
	if b.writes != 0 || fileAt(t, root, "config/projects/shop.yaml") != editShop {
		t.Fatal("cancelling wrote something")
	}
	d.press("x", "y")
	d.press("y")
	d.want("ok: saved shop: remove technology php")
	if strings.Contains(fileAt(t, root, "config/projects/shop.yaml"), "name: php") {
		t.Fatal("php should be gone")
	}
}

func TestFieldEditorBreadcrumbAndBack(t *testing.T) {
	b, _ := diskFake(t, nil)
	d := start(t, b, Options{})
	d.press("3", "down", "enter")
	if got := crumbOf(d); got != "Projects › shop" {
		t.Errorf("project: %q", got)
	}
	d.press("c")
	if got := crumbOf(d); got != "Projects › shop › Fields" {
		t.Errorf("fields: %q", got)
	}
	d.press("enter")
	if got := crumbOf(d); got != "Projects › shop › Environments › dev" {
		t.Errorf("environments: %q", got)
	}
	d.press("esc")
	d.press("down", "enter")
	if got := crumbOf(d); got != "Projects › shop › Technologies › php" {
		t.Errorf("technologies: %q", got)
	}
	d.press("down", "down")
	if got := crumbOf(d); got != "Projects › shop › Technologies › add a technology" {
		t.Errorf("add row: %q", got)
	}
	d.press("up", "up", "x", "y")
	if got := crumbOf(d); got != "Projects › shop › Technologies › php › review" {
		t.Errorf("review: %q", got)
	}
	d.press("esc")
	// the crumb of the field list goes back one level, the project one goes back to its problems
	d.click(len("Projects › shop › ")+2, 1)
	d.want("Edit fields of shop")
	d.press("enter")
	d.click(len("Projects › ")+1, 1)
	d.wantNot("Edit fields of shop")
	d.want("c edits the fields")
	d.press("c")
	d.press("esc")
	d.wantNot("Edit fields of shop")
	d.want("c edits the fields")
	d.press("esc")
	d.want("PROJECT", "> shop")
	// c on the list goes straight to the fields
	d.press("c")
	d.want("Edit fields of shop")
	d.click(2, 1)
	d.want("PROJECT")
	d.wantNot("Edit fields of shop")
}

func TestFieldEditorMouse(t *testing.T) {
	b, _ := diskFake(t, nil)
	d := start(t, b, Options{})
	d.press("3", "down", "c")
	a := d.m.(*app)
	row := func(n int) int { return bodyTop + fieldHead + n }
	d.click(5, row(2))
	if a.prj.ed.top.at() != 2 || a.prj.ed.open != "" {
		t.Fatalf("a click selects: at %d open %q", a.prj.ed.top.at(), a.prj.ed.open)
	}
	d.click(5, row(2))
	if a.prj.ed.open != fldLocks {
		t.Fatal("a second click opens the field")
	}
	d.click(5, row(0))
	d.click(5, row(0)) // toggles dev of the lockfile: the preview
	d.want("Save this change?", "mark lockfile")
	d.press("esc")
	d.wheel(false, 10, 6)
	if a.prj.ed.sub.at() != 1 {
		t.Fatalf("the wheel moves the cursor: %d", a.prj.ed.sub.at())
	}
	d.press("esc")
	d.click(5, row(0))
	d.click(5, row(0)) // environments: the list
	d.want("ENVIRONMENT", "USED BY")
	d.click(5, row(1))
	if a.prj.ed.sub.at() != 1 {
		t.Fatalf("a click selects the environment: %d", a.prj.ed.sub.at())
	}
	d.click(5, row(1)) // a second click renames it
	d.want("Rename environment prod of shop", "New name")
}

func TestFieldEditorOnProjectsThatCannotBeEdited(t *testing.T) {
	b, root := diskFake(t, map[string]string{"config/projects/bad.yaml": "name: bad\ntechs: [oops\n", "config/projects/off.yaml.disabled": "name: off\n"})
	d := start(t, b, Options{})
	d.press("3")
	d.want("bad", "BROKEN", "off", "disabled")
	d.press("down", "down", "c") // bad
	d.want("error: the file of bad does not load")
	d.press("down", "c") // off
	d.want("error: off is disabled")
	d.want("error:")
	if d.m.(*app).prj.ed != nil {
		t.Fatal("no editor for a project that cannot be edited")
	}
	// the main config's project has no file
	b2 := newFake(t, nil)
	d2 := start(t, b2, Options{})
	d2.press("3", "c")
	d2.want("error: project shop has no file")
	_ = root
}

func TestFieldEditorFitsSmallTerminals(t *testing.T) {
	b, _ := diskFake(t, nil)
	d := start(t, b, Options{})
	for _, size := range [][2]int{{30, 8}, {40, 12}, {60, 14}, {120, 40}} {
		d.send(tea_window(size[0], size[1]))
		for _, keys := range [][]string{{"3", "down", "c"}, {"enter"}, {"esc", "down", "down", "enter"}, {"a"}, {"esc", "esc", "down", "enter"}, {"esc", "esc"}} {
			d.press(keys...)
			lines := strings.Split(d.view(), "\n")
			if len(lines) > size[1] {
				t.Fatalf("%dx%d: %d lines after %v", size[0], size[1], len(lines), keys)
			}
			for _, l := range lines {
				if width(l) > size[0] {
					t.Fatalf("%dx%d: a line is %d cells after %v: %q", size[0], size[1], width(l), keys, l)
				}
			}
		}
		d.press("esc", "esc", "esc")
	}
}

func TestFieldEditorFootersAndHelp(t *testing.T) {
	b, _ := diskFake(t, nil)
	d := start(t, b, Options{})
	d.send(tea_window(80, 24))
	foot := func() string { lines := strings.Split(d.view(), "\n"); return lines[len(lines)-1] }
	d.press("3", "down")
	if f := foot(); !strings.Contains(f, "c fields") {
		t.Errorf("projects footer: %q", f)
	}
	d.want("+ add", "- remove", "c edit fields", "R rename", "D duplicate", "Z disable")
	d.press("?")
	d.want("add a project: from a folder")
	all := strings.Join(helpLines(mo.projects, 80), "\n")
	for _, w := range []string{"duplicate the project", "remove the project", "disable the project"} {
		if !strings.Contains(all, w) {
			t.Errorf("help lacks %q", w)
		}
	}
	d.press("?", "enter")
	d.press("c")
	if f := foot(); !strings.Contains(f, "enter edit") || !strings.Contains(f, "? help") || width(f) > 80 {
		t.Errorf("fields footer: %q", f)
	}
	d.press("?")
	d.want("Keys in the fields of a project", "change the field", "back to the problems")
	d.press("?", "down", "down", "enter")
	if f := foot(); !strings.Contains(f, "toggle dev") || !strings.Contains(f, "+ add") || width(f) > 80 {
		t.Errorf("lockfile list footer: %q", f)
	}
	d.press("?")
	d.want("Keys in the list of a field", "include or leave out development packages")
	d.press("?", "esc", "home", "enter")
	if f := foot(); !strings.Contains(f, "r rename") || !strings.Contains(f, "+ add") || width(f) > 80 {
		t.Errorf("environments footer: %q", f)
	}
	d.press("?")
	d.want("Keys in the list of a field", "environments: rename the selected one")
}
