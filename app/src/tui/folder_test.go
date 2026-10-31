package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func folderTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for name, files := range map[string][]string{
		"alpha":    nil,
		"shop":     {"go.mod", "package-lock.json"},
		"shopify":  nil,
		"zeta-app": {"composer.lock"},
	} {
		dir := filepath.Join(root, name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := os.WriteFile(filepath.Join(root, "notes.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
	return root
}

func shiftTab() tea.KeyMsg { return tea.KeyMsg{Type: tea.KeyShiftTab} }

func TestFolderBoxListsProjectFoldersFirst(t *testing.T) {
	folderTree(t)
	d := start(t, newFake(t, nil), Options{})
	d.press("3", "d")
	v := d.view()
	d.want("Scan a folder for a new project", "Folder:", "4 folders", "composer.lock", "go.mod, package-lock.json", "project")
	zeta, shop, alpha := strings.Index(v, "zeta-app"), strings.Index(v, "shop "), strings.Index(v, "alpha")
	if zeta < 0 || shop < 0 || alpha < 0 || shop > alpha || zeta > alpha {
		t.Fatalf("project folders must come first:\n%s", v)
	}
	d.wantNot("notes.txt")
}

func TestFolderBoxTypingNarrowsAndTabCompletes(t *testing.T) {
	folderTree(t)
	d := start(t, newFake(t, nil), Options{})
	d.press("3", "d")
	d.typ("sh")
	d.want("2 folders", "shopify")
	d.wantNot("alpha", "zeta-app")
	d.press("tab")
	d.want("Folder: shop▏")
	d.press("tab")
	d.want("Folder: shop▏")
}

func TestFolderBoxDownTabDescendsAndShiftTabGoesUp(t *testing.T) {
	root := folderTree(t)
	os.MkdirAll(filepath.Join(root, "shop", "web"), 0o755)
	d := start(t, newFake(t, nil), Options{})
	d.press("3", "d")
	d.typ("sh")
	d.press("down", "tab")
	d.want("Folder: shop"+pathSep+"▏", "web")
	d.press("down", "tab")
	d.want("Folder: shop" + pathSep + "web" + pathSep + "▏")
	d.send(shiftTab())
	d.want("Folder: shop" + pathSep + "▏")
	d.send(shiftTab())
	d.want("Folder: ▏", "4 folders")
}

func TestFolderBoxDownEnterSubmitsTheHighlightedFolder(t *testing.T) {
	folderTree(t)
	d := start(t, newFake(t, nil), Options{})
	d.press("3", "d")
	d.typ("zeta")
	d.press("down", "enter")
	d.want("New project", "Project name", "> zeta-app", "ok: scanned")
}

func TestFolderBoxUpMovesTheHighlightBack(t *testing.T) {
	folderTree(t)
	d := start(t, newFake(t, nil), Options{})
	d.press("3", "d")
	d.press("down", "down")
	d.want("> zeta-app", "looks like a project: composer.lock")
	d.press("up", "up")
	d.wantNot("looks like a project: ")
	d.press("up")
	d.want("Scan a folder")
}

func TestFolderBoxKeepsTheHomeForm(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	os.MkdirAll(filepath.Join(home, "work", "shop"), 0o755)
	os.WriteFile(filepath.Join(home, "work", "shop", "go.mod"), []byte("x"), 0o644)
	t.Chdir(t.TempDir())
	d := start(t, newFake(t, nil), Options{})
	d.press("3", "d")
	d.typ(filepath.FromSlash("~/wo"))
	d.press("tab")
	d.want(filepath.FromSlash("Folder: ~/work/▏"), "shop")
	d.press("down", "tab")
	d.want(filepath.FromSlash("Folder: ~/work/shop/▏"))
	d.send(shiftTab())
	d.want(filepath.FromSlash("Folder: ~/work/▏"))
	d.send(shiftTab())
	d.want(filepath.FromSlash("Folder: ~/▏"))
}

func TestFolderBoxStatusLine(t *testing.T) {
	folderTree(t)
	d := start(t, newFake(t, nil), Options{})
	d.press("3", "d")
	d.typ("shop")
	d.want("looks like a project: go.mod, package-lock.json")
	d.press("ctrl+u")
	d.typ("alpha" + pathSep)
	d.want("no lockfiles or manifests found here")
}

func TestFolderBoxMissingFolderStillGoesThroughToTheError(t *testing.T) {
	folderTree(t)
	d := start(t, newFake(t, nil), Options{})
	d.press("3", "d")
	d.typ("nope")
	d.want("no such folder")
	d.press("enter")
	d.want("error: no such folder", "problem: no such folder")
	d.want("Folder: nope") // the prompt stays with what was typed
	d.press("esc")
	d.wantNot("Scan a folder")
}

func TestFolderBoxFilePath(t *testing.T) {
	folderTree(t)
	d := start(t, newFake(t, nil), Options{})
	d.press("3", "d")
	d.typ("notes.txt")
	d.want("that is a file, not a folder")
	d.press("enter")
	d.want("error:", "is a file")
}

func TestFolderBoxEscCancelsAndEmptyIsRejected(t *testing.T) {
	folderTree(t)
	d := start(t, newFake(t, nil), Options{})
	d.press("3", "d")
	d.typ("sh")
	d.press("down", "esc")
	d.wantNot("Scan a folder")
	d.press("d", "enter")
	d.want("error: no folder given")
}

func TestFolderBoxErrorReplacesTheList(t *testing.T) {
	folderTree(t)
	d := start(t, newFake(t, nil), Options{})
	d.press("3", "d")
	d.typ("gone" + pathSep + "x")
	d.want("no such folder: ")
	d.wantNot("4 folders")
}

func TestFolderBoxPure(t *testing.T) {
	root := folderTree(t)
	b := newFolderBox()
	if len(b.entries) != 4 || b.sel() != -1 || b.chosen() != "" {
		t.Fatalf("start: %d entries, sel %d, chosen %q", len(b.entries), b.sel(), b.chosen())
	}
	b.key(key("down"))
	b.key(key("down"))
	if b.sel() != 1 {
		t.Fatalf("sel = %d", b.sel())
	}
	for range 10 {
		b.key(key("down"))
	}
	if b.sel() != 3 {
		t.Fatalf("sel must stop at the last row, got %d", b.sel())
	}
	b.key(key("x"))
	if b.sel() != -1 || b.text() != "x" {
		t.Fatalf("typing resets the highlight: sel %d text %q", b.sel(), b.text())
	}
	b.setText("shop")
	if got := b.chosen(); got != "shop" {
		t.Fatalf("chosen = %q", got)
	}
	b.key(key("down"))
	if got := b.chosen(); got != filepath.Join(root, "shop") {
		t.Fatalf("chosen = %q", got)
	}
}

func TestParentText(t *testing.T) {
	t.Setenv("HOME", filepath.Join(pathSep+"home", "me"))
	t.Setenv("USERPROFILE", filepath.Join(pathSep+"home", "me"))
	for in, want := range map[string]string{
		"~/Projects/shop/": "~/Projects/",
		"~/Projects/sho":   "~/Projects/",
		"~/Projects/":      "~/",
		"~/":               "/home/",
		"~":                "/home/",
		"/a/b/":            "/a/",
		"/a":               "/",
		"/":                "/",
		"shop/":            "",
		"":                 "../",
		"..":               "../../",
	} {
		if got := parentText(filepath.FromSlash(in)); got != filepath.FromSlash(want) {
			t.Errorf("parentText(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFolderOf(t *testing.T) {
	for in, want := range map[string]string{
		"":        "",
		"sh":      "",
		"a/sh":    "a/",
		"a/b/":    "a/b/",
		"~":       "~/",
		"..":      "../",
		"~/work/": "~/work/",
	} {
		if got := folderOf(filepath.FromSlash(in)); got != filepath.FromSlash(want) {
			t.Errorf("folderOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func boxNames(b *folderBox) string {
	var names []string
	for _, e := range b.entries {
		names = append(names, e.Name)
	}
	return strings.Join(names, ",")
}

func TestFolderBoxHidesIgnoredFoldersAndFiles(t *testing.T) {
	root := t.TempDir()
	for name, content := range map[string]string{
		".gitignore":         "generated/\nDockerfile.local\n*.cache\n",
		"app/go.mod":         "x",
		"generated/go.mod":   "x",
		"scratch.cache/x":    "x",
		"Dockerfile":         "FROM nginx",
		"Dockerfile.local":   "FROM nginx",
		"Dockerfile.other":   "FROM nginx",
		"app/.gitignore":     "Dockerfile.other\n",
		"app/Dockerfile.old": "FROM nginx",
		"app/Dockerfile.new": "FROM nginx",
	} {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	b := newFolderBox()
	b.setText(root + pathSep)
	if got := boxNames(b); got != "app,Dockerfile,Dockerfile.other" {
		t.Fatalf("root entries = %s", got)
	}
	b.setText(root + pathSep + "gen")
	if len(b.entries) != 0 {
		t.Fatalf("an ignored folder must not complete: %s", boxNames(b))
	}
	b.tab()
	if b.text() != root+pathSep+"gen" {
		t.Fatalf("tab changed the text to %q", b.text())
	}
	b.setText(root + pathSep + "Dockerfile.")
	if got := boxNames(b); got != "Dockerfile.other" { // Dockerfile.local is ignored
		t.Fatalf("file entries = %s", got)
	}
	b.tab()
	if b.text() != root+pathSep+"Dockerfile.other" {
		t.Fatalf("the only visible file must complete, got %q", b.text())
	}
	b.setText(root + pathSep + "app" + pathSep + "Dockerfile.")
	if got := boxNames(b); got != "Dockerfile.new,Dockerfile.old" { // app/.gitignore hides nothing it does not name
		t.Fatalf("nested entries = %s", got)
	}
	lock := newBox(boxLockfile, "Lockfile")
	lock.setText(root + pathSep)
	if got := boxNames(lock); got != "app" {
		t.Fatalf("lockfile box entries = %s", got)
	}
}
