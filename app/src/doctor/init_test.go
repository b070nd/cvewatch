package doctor

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/defaults"
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
	if got, _ := os.ReadFile(edited); string(got) != string(defaults.Techs()) {
		t.Error("Force did not restore the file")
	}
}

func TestInitDetectsRepository(t *testing.T) {
	repo := filepath.Join(t.TempDir(), "My Shop_v2")
	files := map[string]string{
		"composer.lock":     `{"packages":[{"name":"monolog/monolog","version":"3.0.0"}]}`,
		"package-lock.json": `{"lockfileVersion":3,"packages":{"node_modules/left-pad":{"version":"1.3.0"}}}`,
		"go.mod":            "module example.com/x\n\ngo 1.22.3\n",
		".nvmrc":            "v20.11.1\n",
		"notes.txt":         "ignored",
		"sub/composer.lock": "{}", // not top level
	}
	for rel, c := range files {
		put(t, repo, rel, c)
	}
	root := t.TempDir()
	res, err := Init(root, InitOptions{Repo: repo})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(res.Written, "config/projects/my-shop-v2.yaml") {
		t.Fatalf("written = %v", res.Written)
	}
	notes := strings.Join(res.Notes, "\n")
	for _, s := range []string{"composer.lock (composer)", "package-lock.json (npm)", "go.mod (go)", "go 1.22", "nodejs 20.11.1", "doctor", "update"} {
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
	if len(techs) != 3 || techs["php"] != "" || techs["go"] != "1.22" || techs["nodejs"] != "20.11.1" {
		t.Errorf("techs = %v", techs)
	}
	types := map[string]string{}
	for _, lf := range p.Lockfiles {
		if !filepath.IsAbs(lf.Path) {
			t.Errorf("path %q is not absolute", lf.Path)
		}
		types[lf.Type] = lf.Path
	}
	if len(types) != 3 || types["composer"] != filepath.Join(repo, "composer.lock") || types["npm"] == "" || types["go"] == "" {
		t.Errorf("lockfiles = %v", p.Lockfiles)
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

func TestInitDetectsMoreTypes(t *testing.T) {
	repo := t.TempDir()
	for rel, c := range map[string]string{
		"requirements.txt": "flask==1.0\n", ".python-version": "3.12.1\n", ".php-version": "8.2\n",
		"gradle.lockfile": "", "pom.xml": "<project/>", "sbom.json": "{}", "app.cdx.json": "{}", "app.spdx.json": "{}",
		".node-version": "lts/*\n", // not a version: ignored
	} {
		put(t, repo, rel, c)
	}
	d, err := detect(repo)
	if err != nil {
		t.Fatal(err)
	}
	var types []string
	for _, f := range d.files {
		types = append(types, f.typ)
	}
	slices.Sort(types)
	if got := strings.Join(types, ","); got != "cyclonedx,cyclonedx,gradle,maven,pip,spdx" {
		t.Errorf("types = %s", got)
	}
	if d.techs["python"] != "3.12.1" || d.techs["php"] != "8.2" {
		t.Errorf("techs = %v", d.techs)
	}
	if _, ok := d.techs["nodejs"]; ok {
		t.Errorf("lts/* must not count: %v", d.techs)
	}
	if !strings.Contains(string(d.projectFile("x", repo)), `{name: python, version: "3.12.1"}`) {
		t.Errorf("project file:\n%s", d.projectFile("x", repo))
	}
}

func TestInitNothingFoundAndSanitize(t *testing.T) {
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

	for in, want := range map[string]string{"Shop & Co.": "shop-co", "ÄÖ": "project", "a--b": "a-b", "": "project"} {
		if got := sanitize(in); got != want {
			t.Errorf("sanitize(%q) = %q, want %q", in, got, want)
		}
	}
	if _, err := Init(root, InitOptions{Repo: filepath.Join(root, "nope")}); err == nil {
		t.Error("missing repo must be an error")
	}

	res, err = Init(t.TempDir(), InitOptions{Repo: repo, Project: "Given Name"})
	if err != nil || !strings.Contains(strings.Join(res.Notes, "\n"), "given-name") {
		t.Errorf("res %+v err %v", res, err)
	}
}
