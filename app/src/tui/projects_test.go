package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/b070nd/cvewatch/app/src/projectfile"
)

func projectFile(t *testing.T, b *fake, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(b.cfg.Root, "config", "projects", name+".yaml"))
	if err != nil {
		t.Fatalf("project file %s: %v", name, err)
	}
	return string(data)
}

func TestProjectsScreenListsDeclaredTechs(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	d.press("3")
	d.want("[3 Projects]", "PROJECT", "LOCKFILES", "TECHNOLOGIES", "> shop", "mw", "php 8.2, nginx", "prod", "technologies: php 8.2, nginx", "defined in the main config")
	d.press("down")
	d.want("> mw", "technologies: -")
}

func TestSetupFormCreatesProjectFromTypedNameAndTechs(t *testing.T) {
	b := newFake(t, nil)
	d := start(t, b, Options{})
	d.press("3", "n")
	d.want("New project", "Project name", "> project") // the flow's own default

	d.press("ctrl+u")
	d.typ("Bad Name")
	d.press("enter")
	d.want("problem: invalid project name") // the flow rejects it, the form stays
	d.press("ctrl+u")
	d.typ("shop") // exists in the config
	d.press("enter")
	d.want("a project with that name already exists")
	d.press("ctrl+u")
	d.typ("blog")
	d.press("enter")
	d.want("New project: blog", "Technologies")
	d.press("enter") // nothing to tick yet
	d.want("Add other technologies")
	d.typ("nope")
	d.press("enter")
	d.want("not in the catalog")
	d.press("ctrl+u")
	d.typ("php")
	d.press("enter")
	d.want("Added so far: php")
	d.press("enter") // done adding
	d.want("Version of PHP")
	d.typ("8.2")
	d.press("enter")
	d.want("Environments", "[x] dev", "[x] prod")
	d.press("enter")
	d.want("Save this project?", `+   - {name: php, version: "8.2"}`)
	d.want("Save this project?  y = save")
	d.press("y")
	d.want("ok: created project blog")
	if d.m.(*app).frm != nil {
		t.Fatal("the form must close after saving")
	}
	f := projectFile(t, b, "blog")
	if !strings.Contains(f, "php") || !strings.Contains(f, "8.2") {
		t.Fatalf("project file:\n%s", f)
	}
	if b.writes != 1 {
		t.Fatalf("saving is one short write session, got %d", b.writes)
	}
	if log, _ := os.ReadFile(filepath.Join(b.cfg.DataDir, "audit.log")); !strings.Contains(string(log), `"action":"project"`) {
		t.Fatalf("the audit log must record the project change:\n%s", log)
	}
}

func TestSetupFormBackAndCancel(t *testing.T) {
	b := newFake(t, nil)
	d := start(t, b, Options{})
	d.press("3", "n", "ctrl+u")
	d.typ("blog")
	d.press("enter")
	d.want("Technologies")
	d.press("esc")
	d.want("Project name", "> blog") // back, the answer is kept
	d.press("esc")
	d.want("ok: cancelled, nothing was saved", "PROJECT")
	d.press("n", "esc")
	d.want("cancelled")
	if b.writes != 0 {
		t.Fatal("cancelling wrote something")
	}
}

func TestSetupFormMultiChoiceAndConfirmKinds(t *testing.T) {
	b := newFake(t, nil)
	d := start(t, b, Options{})
	d.press("3", "n", "ctrl+u")
	d.typ("blog")
	d.press("enter", "enter") // techs (none), then add-techs
	d.typ("php nginx")
	d.press("enter", "enter")
	d.typ("8.2")
	d.press("enter")
	d.typ("1.25")
	d.press("enter")
	d.want("Environments")
	d.press("down", " ") // untick int
	d.want("[ ] int", "[x] dev")
	d.press("a") // all are not ticked now, so "a" ticks all
	d.want("[x] int")
	d.press("a")
	d.want("[ ] dev", "[ ] prod")
	d.press("enter") // none selected: the flow insists on one
	d.want("problem: select at least one environment")
	d.press("j", "j", "j", " ", "enter")
	d.want("Save this project?")
	d.press("n") // not saving goes back to the techs step of the create path
	d.want("Technologies", "[x] PHP")
	if b.writes != 0 {
		t.Fatal("answering no wrote")
	}
}

func TestEditProjectNeedsItsOwnFile(t *testing.T) {
	b := newFake(t, nil)
	d := start(t, b, Options{})
	d.press("3", "e")
	d.want("error: project \"shop\" has no file under config/projects")
	if d.m.(*app).frm != nil {
		t.Fatal("no form for a project without a file")
	}

	dir := filepath.Join(b.cfg.Root, "config", "projects")
	os.MkdirAll(dir, 0o700)
	os.WriteFile(filepath.Join(dir, "shop.yaml"), []byte("name: shop\ntechs:\n  - {name: php, version: \"8.2\"}\n  - {name: nginx}\n"), 0o600)
	d.press("r")
	d.press("e")
	d.want("Edit project: shop", "What do you want to change?", "Technologies", "Versions", "Review and save")
	d.press("esc")
	d.want("cancelled")
}

func TestEditProjectChangesVersionAndSaves(t *testing.T) {
	b := newFake(t, nil)
	dir := filepath.Join(b.cfg.Root, "config", "projects")
	os.MkdirAll(dir, 0o700)
	os.WriteFile(filepath.Join(dir, "shop.yaml"), []byte("# the shop\nname: shop\ntechs:\n  - {name: php, version: \"8.2\"}\n  - {name: nginx}\n"), 0o600)
	d := start(t, b, Options{})
	d.press("3", "e")
	d.want("Edit project: shop")
	d.press("up", "up", "enter") // Versions (the menu starts on Review and save)
	d.want("Version of PHP")
	d.press("ctrl+u")
	d.typ("8.3")
	d.press("enter")
	d.want("Version of Nginx")
	d.press("enter")
	d.want("What do you want to change?")
	d.press("enter") // Review and save
	d.want("Save this project?")
	d.press("y")
	d.want("ok: saved project shop")
	f := projectFile(t, b, "shop")
	if !strings.Contains(f, "8.3") || !strings.Contains(f, "# the shop") {
		t.Fatalf("the edit must keep the file's comments:\n%s", f)
	}
}

func TestDiscoveryOnAFolderProposesAndSavesRelativePaths(t *testing.T) {
	b := newFake(t, nil)
	site := filepath.Join(b.cfg.Root, "apps", "site")
	os.MkdirAll(filepath.Join(site, "web"), 0o755)
	os.WriteFile(filepath.Join(site, ".php-version"), []byte("8.2.1\n"), 0o644)
	os.WriteFile(filepath.Join(site, "web", "package-lock.json"), []byte(`{"lockfileVersion":3,"packages":{"":{},"node_modules/express":{"version":"4.18.2"}}}`), 0o644)

	d := start(t, b, Options{})
	d.press("3", "d")
	d.want("Scan a folder for a new project", "Folder")
	d.press("enter") // nothing typed
	d.want("error: no folder given")
	d.press("d")
	d.typ(site)
	d.press("enter")
	d.want("New project", "Project name", "> site", "ok: scanned")
	d.press("enter")
	d.want("Technologies", "[x] PHP", "high")
	d.press("enter", "enter") // keep the techs, add none
	for i := 0; i < 3 && strings.Contains(d.view(), "Version of"); i++ {
		d.press("enter")
	}
	d.want("Inventory sources", "package-lock.json", "packages")
	d.press("enter")
	d.want("Environments")
	d.press("enter")
	d.want("Save this project?", "apps/site/web/package-lock.json")
	d.wantNot(site)
	d.press("y")
	d.want("ok: created project site")
	f := projectFile(t, b, "site")
	if !strings.Contains(f, "apps/site/web/package-lock.json") || strings.Contains(f, b.cfg.Root) {
		t.Fatalf("lockfile paths must be saved relative to the app root:\n%s", f)
	}
}

func TestDiscoveryInsideARunningFlow(t *testing.T) {
	b := newFake(t, nil)
	site := t.TempDir()
	os.WriteFile(filepath.Join(site, ".php-version"), []byte("8.2.1\n"), 0o644)
	d := start(t, b, Options{})
	d.press("3", "n")
	d.press("ctrl+d")
	d.want("merge what it finds into this project")
	d.typ(site)
	d.press("enter")
	d.want("ok: scanned")
	d.press("enter") // name
	d.want("[x] PHP")
	d.press("ctrl+d", "esc") // a prompt can be left
	d.want("[x] PHP")
	d.press("ctrl+d")
	d.typ(filepath.Join(site, "missing"))
	d.press("enter")
	d.want("error:")
}

func TestOptionsDirStartsTheSetupFlowOnTheFolder(t *testing.T) {
	b := newFake(t, nil)
	site := t.TempDir()
	os.WriteFile(filepath.Join(site, ".php-version"), []byte("8.2.1\n"), 0o644)
	d := &driver{t: t, b: b}
	d.m = New(b, Options{Refresh: time.Hour, Dir: site})
	d.send(tea_window(100, 30))
	d.run(d.m.Init()) // loads, schedules the tick (dropped here) and starts the flow on the folder
	d.want("[3 Projects]", "New project", "Project name", "ok: scanned")
}

func TestRelativize(t *testing.T) {
	root := filepath.Join(string(filepath.Separator), "srv", "app")
	in := []projectfile.Op{
		{Kind: "add_lockfile", Lockfile: lock(filepath.Join(root, "web", "composer.lock"))},
		{Kind: "add_lockfile", Lockfile: lock("already/relative.lock")},
		{Kind: "remove_lockfile", Lockfile: lock(filepath.Join(root, "old.lock"))},
		{Kind: "set_tech", Tech: "php"},
	}
	out := relativize(root, in)
	if out[0].Lockfile.Path != "web/composer.lock" || out[1].Lockfile.Path != "already/relative.lock" ||
		out[2].Lockfile.Path != filepath.Join(root, "old.lock") || out[3].Tech != "php" {
		t.Fatalf("got %+v", out)
	}
	if in[0].Lockfile.Path == "web/composer.lock" {
		t.Fatal("the input ops must not change")
	}
}
