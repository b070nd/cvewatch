package doctor

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/defaults"
	"github.com/b070nd/cvewatch/app/src/setup"
)

func TestInitWritesLayoutAndSkips(t *testing.T) {
	root := filepath.Join(t.TempDir(), "cw")
	res, err := Init(root, InitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Written) != len(defaults.Layout()) || len(res.Skipped) != 0 {
		t.Fatalf("written %v skipped %v", res.Written, res.Skipped)
	}
	for name, want := range defaults.Layout() {
		got, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil || string(got) != string(want) {
			t.Errorf("%s: err %v, content differs", name, err)
		}
	}
	if len(res.Notes) < 2 || !strings.Contains(res.Notes[len(res.Notes)-1], "doctor") || !strings.Contains(res.Notes[len(res.Notes)-1], "update") {
		t.Errorf("notes = %v", res.Notes)
	}

	// The shipped settings keep data inside the root, and the folder is valid.
	b, err := config.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if b.DataDir != filepath.Join(root, "data") || b.AlertsDir != filepath.Join(root, "alerts") {
		t.Errorf("dirs = %s %s", b.DataDir, b.AlertsDir)
	}

	edited := filepath.Join(root, "config", "techs.yaml")
	if err := os.WriteFile(edited, []byte("techs: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err = Init(root, InitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Written) != 0 || len(res.Skipped) != len(defaults.Layout()) {
		t.Fatalf("second run written %v skipped %v", res.Written, res.Skipped)
	}
	if got, _ := os.ReadFile(edited); string(got) != "techs: []\n" {
		t.Error("existing file was overwritten")
	}

	res, err = Init(root, InitOptions{Force: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Written) != len(defaults.Layout()) || len(res.Skipped) != 0 {
		t.Fatalf("force run written %v skipped %v", res.Written, res.Skipped)
	}
	if got, _ := os.ReadFile(edited); string(got) != string(defaults.UserTechs()) {
		t.Error("Force did not restore the file")
	}
}

// stack is a user catalog that recognises the test repositories, so the tests
// do not depend on what the shipped catalog contains.
const stack = `techs:
  - name: php
    cpe: ["php:php"]
    detect:
      versions: [{file: .php-version, pattern: '^(\d+(?:\.\d+)*)'}]
  - name: nodejs
    cpe: ["nodejs:node.js"]
    detect:
      versions: [{file: .nvmrc, pattern: '^v?(\d+(?:\.\d+)*)'}]
  - name: go
    cpe: ["golang:go"]
`

func TestInitDetectsRepository(t *testing.T) {
	repo := filepath.Join(t.TempDir(), "My Shop_v2")
	files := map[string]string{
		"composer.lock":     `{"packages":[{"name":"monolog/monolog","version":"3.0.0"}]}`,
		"package-lock.json": `{"lockfileVersion":3,"packages":{"node_modules/left-pad":{"version":"1.3.0"}}}`,
		"go.mod":            "module example.com/x\n\ngo 1.22.3\n",
		".nvmrc":            "v20.11.1\n",
		".php-version":      "8.2.4\n",
		"notes.txt":         "ignored",
		"sub/composer.lock": `{"packages":[]}`, // monorepo: found too
	}
	for rel, c := range files {
		put(t, repo, rel, c)
	}
	root := t.TempDir()
	put(t, root, "config/techs.yaml", stack)
	res, err := Init(root, InitOptions{Repo: repo})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(res.Written, "config/projects/my-shop-v2.yaml") {
		t.Fatalf("written = %v", res.Written)
	}
	notes := strings.Join(res.Notes, "\n")
	for _, s := range []string{"composer.lock (composer)", "package-lock.json (npm)", "go.mod (go)", "sub/composer.lock", "go 1.22", "nodejs 20.11.1", "relative to", "doctor", "update"} {
		if !strings.Contains(notes, s) {
			t.Errorf("notes lack %q:\n%s", s, notes)
		}
	}

	// Round trip: the generated file loads and says what was detected.
	b, err := config.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Projects) != 1 || len(b.Warnings) != 0 {
		t.Fatalf("projects %+v warnings %v", b.Projects, b.Warnings)
	}
	p := b.Projects[0]
	if p.Name != "my-shop-v2" {
		t.Errorf("name = %q", p.Name)
	}
	techs := map[string]string{}
	for _, tc := range p.Techs {
		techs[tc.Name] = tc.Version
	}
	if len(techs) != 3 || techs["php"] != "8.2.4" || techs["go"] != "1.22.3" || techs["nodejs"] != "20.11.1" {
		t.Errorf("techs = %v", techs)
	}
	paths := map[string]bool{}
	for _, lf := range p.Lockfiles {
		if !filepath.IsAbs(lf.Path) {
			t.Errorf("path %q should be resolved against the root", lf.Path)
		}
		paths[lf.Type+" "+lf.Path] = true
	}
	if len(p.Lockfiles) != 4 || !paths["composer "+filepath.Join(repo, "composer.lock")] || !paths["composer "+filepath.Join(repo, "sub", "composer.lock")] {
		t.Errorf("lockfiles = %v", p.Lockfiles)
	}
	// The file itself holds relative paths, so it survives a move or a container mount.
	raw, _ := os.ReadFile(filepath.Join(root, "config", "projects", "my-shop-v2.yaml"))
	if strings.Contains(string(raw), repo) {
		t.Errorf("file holds absolute paths:\n%s", raw)
	}

	// And a doctor run on it is clean.
	t.Setenv("SLACK_WEBHOOK_URL", "")
	r := Run(t.Context(), root, Options{})
	want(t, r, "inventory", "my-shop-v2/prod", OK)

	// Re-running skips the project file; Force rewrites it.
	res, err = Init(root, InitOptions{Repo: repo})
	if err != nil || !slices.Contains(res.Skipped, "config/projects/my-shop-v2.yaml") {
		t.Fatalf("res %+v err %v", res, err)
	}
}

func TestInitOffersLowConfidenceTechsOnly(t *testing.T) {
	repo := t.TempDir()
	put(t, repo, "requirements.txt", "flask==1.0\n")
	put(t, repo, "wp-config.php", "<?php")
	root := t.TempDir()
	put(t, root, "config/techs.yaml", "techs:\n  - {name: wordpress, detect: {files: [wp-config.php]}}\n")
	res, err := Init(root, InitOptions{Repo: repo})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(root, "config", "projects", setup.FolderName(repo)+".yaml"))
	if strings.Contains(string(raw), "wordpress") || !strings.Contains(string(raw), "requirements.txt") {
		t.Errorf("project file:\n%s", raw)
	}
	if n := strings.Join(res.Notes, "\n"); !strings.Contains(n, "Possible, not declared") || !strings.Contains(n, "wordpress") {
		t.Errorf("notes = %s", n)
	}
}

func TestInitNothingFound(t *testing.T) {
	repo := filepath.Join(t.TempDir(), "!!!")
	put(t, repo, "README.md", "hi")
	root := t.TempDir()
	res, err := Init(root, InitOptions{Repo: repo})
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range res.Written {
		if strings.HasPrefix(w, "config/projects/") && !strings.HasSuffix(w, ".example") {
			t.Errorf("unexpected project file %s", w)
		}
	}
	if n := strings.Join(res.Notes, "\n"); !strings.Contains(n, "example.yaml.example") || !strings.Contains(n, "project.yaml") {
		t.Errorf("notes = %s", n)
	}

	if _, err := Init(root, InitOptions{Repo: filepath.Join(root, "nope")}); err == nil {
		t.Error("missing repo must be an error")
	}

	res, err = Init(t.TempDir(), InitOptions{Repo: repo, Project: "Given Name"})
	if err != nil || !strings.Contains(strings.Join(res.Notes, "\n"), "given-name") {
		t.Errorf("res %+v err %v", res, err)
	}
}

func projectFile(t *testing.T, root, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, "config", "projects", name+".yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestInitDotRootKeepsLockfilesRelative(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	put(t, root, "config/techs.yaml", stack)
	put(t, root, "repos/app/composer.lock", `{"packages":[{"name":"monolog/monolog","version":"3.0.0"}]}`)
	res, err := Init(".", InitOptions{Repo: "repos/app"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(res.Written, "config/projects/app.yaml") {
		t.Fatalf("written = %v", res.Written)
	}
	raw := projectFile(t, root, "app")
	if !strings.Contains(raw, "path: repos/app/composer.lock") || strings.Contains(raw, root) {
		t.Errorf("lockfile path is not root-relative:\n%s", raw)
	}
}

func TestInitLongFolderNameIsCapped(t *testing.T) {
	long := strings.Repeat("abcdefghij", 10)
	repo := filepath.Join(t.TempDir(), long)
	put(t, repo, "composer.lock", `{"packages":[]}`)
	root := t.TempDir()
	res, err := Init(root, InitOptions{Repo: repo})
	if err != nil {
		t.Fatal(err)
	}
	name := long[:63]
	if !slices.Contains(res.Written, "config/projects/"+name+".yaml") {
		t.Fatalf("written = %v", res.Written)
	}
	b, err := config.Load(root)
	if err != nil || len(b.Projects) != 1 || b.Projects[0].Name != name || len(b.Broken) != 0 {
		t.Errorf("projects %+v broken %v err %v", b.Projects, b.Broken, err)
	}
}

func TestInitRepoWithHomeAndRelativeSpelling(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	put(t, home, "code/shop/composer.lock", `{"packages":[]}`)
	cwd := t.TempDir()
	t.Chdir(cwd)
	put(t, cwd, "other/composer.lock", `{"packages":[]}`)

	root := t.TempDir()
	for repo, name := range map[string]string{"~/code/shop": "shop", "other": "other"} {
		res, err := Init(root, InitOptions{Repo: repo})
		if err != nil || !slices.Contains(res.Written, "config/projects/"+name+".yaml") {
			t.Errorf("%s: res %+v err %v", repo, res, err)
		}
	}
}

func TestInitSymlinkedRoot(t *testing.T) {
	real, links := t.TempDir(), t.TempDir()
	link := filepath.Join(links, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skip("symlinks are not available")
	}
	put(t, real, "config/techs.yaml", stack)
	put(t, real, "repos/app/composer.lock", `{"packages":[]}`)
	if _, err := Init(link, InitOptions{Repo: filepath.Join(link, "repos", "app")}); err != nil {
		t.Fatal(err)
	}
	if raw := projectFile(t, real, "app"); !strings.Contains(raw, "path: repos/app/composer.lock") {
		t.Errorf("project file:\n%s", raw)
	}
}

func TestInitKeepsExistingProjectFileWithoutForce(t *testing.T) {
	repo := filepath.Join(t.TempDir(), "app")
	put(t, repo, "composer.lock", `{"packages":[]}`)
	root := t.TempDir()
	put(t, root, "config/projects/app.yaml", "name: app\n# mine\n")
	res, err := Init(root, InitOptions{Repo: repo})
	if err != nil || !slices.Contains(res.Skipped, "config/projects/app.yaml") || slices.Contains(res.Written, "config/projects/app.yaml") {
		t.Fatalf("res %+v err %v", res, err)
	}
	if raw := projectFile(t, root, "app"); raw != "name: app\n# mine\n" {
		t.Errorf("existing file changed:\n%s", raw)
	}
	if _, err := os.Stat(filepath.Join(root, "data", "audit.log")); err == nil {
		t.Error("a skipped file must not be audited")
	}

	res, err = Init(root, InitOptions{Repo: repo, Force: true})
	if err != nil || !slices.Contains(res.Written, "config/projects/app.yaml") {
		t.Fatalf("force: res %+v err %v", res, err)
	}
	if raw := projectFile(t, root, "app"); !strings.Contains(raw, "# mine") || !strings.Contains(raw, "composer.lock") {
		t.Errorf("forced file:\n%s", raw)
	}
}

func TestInitAuditsAndLeavesNoStateFile(t *testing.T) {
	repo := filepath.Join(t.TempDir(), "app")
	put(t, repo, "composer.lock", `{"packages":[]}`)
	root := t.TempDir()
	if _, err := Init(root, InitOptions{Repo: repo}); err != nil {
		t.Fatal(err)
	}
	log, err := os.ReadFile(filepath.Join(root, "data", "audit.log"))
	if err != nil || !strings.Contains(string(log), `"project"`) || !strings.Contains(string(log), "created project file") {
		t.Fatalf("audit log %q err %v", log, err)
	}
	entries, _ := os.ReadDir(filepath.Join(root, "data"))
	for _, e := range entries {
		if e.Name() != "audit.log" {
			t.Errorf("init left %s in the data folder", e.Name())
		}
	}
}
