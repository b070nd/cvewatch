package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/b070nd/cvewatch/app/src/ledger"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/ops"
	"github.com/b070nd/cvewatch/app/src/projectfile"
	"github.com/b070nd/cvewatch/app/src/store"
)

const settingsText = "# my settings\ninterval: 4h   # daemon period\ndata_dir: data\nhttp:\n  timeout: 30s\n"

// fixtureRoot writes a small configuration with one project that has two
// open findings, and returns the root folder.
func fixtureRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	for rel, body := range map[string]string{
		"config/config.yaml":        settingsText,
		"config/techs.yaml":         "techs:\n  - name: php\n",
		"config/projects/shop.yaml": "name: shop\nenvs: [dev, prod]\ntechs: [{name: php}]\nlockfiles: [{type: composer, path: composer.lock, env: prod}]\n",
		"sources/s.yaml":            "sources: []\n",
	} {
		p := filepath.Join(root, filepath.FromSlash(rel))
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	st, err := store.OpenFile(filepath.Join(root, "data"))
	if err != nil {
		t.Fatal(err)
	}
	state, err := st.Load()
	if err != nil {
		t.Fatal(err)
	}
	l := ledger.New(state)
	l.Create(model.Item{Title: "PHP bug", IDs: []string{"CVE-2026-1"}, Severity: model.SevHigh, Published: time.Now(),
		SourceID: "x", SourceType: "rss", URL: "https://x.test/1"}, time.Now(), []string{"php"})
	for _, env := range []model.Env{model.EnvDev, model.EnvProd} {
		l.AddFinding(model.Finding{VulnID: "CVE-2026-1", Project: "shop", Env: env, Status: model.StatusOpen})
	}
	if err := st.Save(l.State()); err != nil {
		t.Fatal(err)
	}
	st.Close()
	return root
}

// capture runs fn and returns what it printed to stdout.
func capture(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan string)
	go func() { b, _ := io.ReadAll(r); done <- string(b) }()
	runErr := fn()
	os.Stdout = old
	w.Close()
	return <-done, runErr
}

func runProject(t *testing.T, root string, args ...string) (string, error) {
	t.Helper()
	return capture(t, func() error {
		log := slog.New(slog.NewTextHandler(io.Discard, nil))
		if verb, ok := lifecycleVerb(args); ok {
			return withSession(root, log, func(s *ops.Session) error { return lifecycleCmd(s, verb, args[1:]) })
		}
		return withSession(root, log, func(s *ops.Session) error { return projectCmd(s, args) })
	})
}

func readFile(t *testing.T, root, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestEveryOpKindHasACLIFlag(t *testing.T) {
	for _, spec := range projectfile.OpTable {
		t.Run(spec.Kind, func(t *testing.T) {
			e, err := parseProjectEdit(append([]string{"shop"}, spec.Args...))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(e.ops, []projectfile.Op{spec.Example}) {
				t.Fatalf("%v built %+v, want %+v", spec.Args, e.ops, spec.Example)
			}
			if e.name != "shop" || e.save {
				t.Fatalf("%+v", e)
			}
		})
	}
}

func TestParseLock(t *testing.T) {
	win := filepath.FromSlash(`C:/repo/composer.lock`)
	for in, want := range map[string]model.Lockfile{
		"composer:composer.lock":              {Type: "composer", Path: "composer.lock"},
		"composer:../shop/composer.lock:prod": {Type: "composer", Path: "../shop/composer.lock", Env: model.EnvProd},
		"npm:package-lock.json:dev":           {Type: "npm", Path: "package-lock.json", Dev: true},
		"npm:package-lock.json:staging:dev":   {Type: "npm", Path: "package-lock.json", Env: model.EnvStaging, Dev: true},
		"composer:" + win:                     {Type: "composer", Path: win},
		"composer:" + win + ":prod":           {Type: "composer", Path: win, Env: model.EnvProd},
		"go:dev":                              {Type: "go", Path: "dev"},
	} {
		got, err := parseLock(in)
		if err != nil || got != want {
			t.Errorf("%q: %+v %v, want %+v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "composer", "composer:", ":path"} {
		if _, err := parseLock(bad); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

func TestProjectFlagsErrors(t *testing.T) {
	for _, args := range [][]string{
		{"shop"},
		{"shop", "-image", "prod"},
		{"shop", "-env-set", "prod:php"},
		{"shop", "-env-unset", "prod"},
		{"shop", "-lock", "bad"},
		{"-since", "2026-01-01"},
	} {
		if _, err := parseProjectEdit(args); err == nil {
			t.Errorf("%v should be rejected", args)
		}
	}
	e, err := parseProjectEdit([]string{"shop", "-since", ""})
	if err != nil || len(e.ops) != 1 || e.ops[0].Kind != "set_since" || e.ops[0].Since != "" {
		t.Fatalf("an empty -since must clear: %+v %v", e, err)
	}
	e, err = parseProjectEdit([]string{"shop", "-lock-nodev", "composer:composer.lock", "-envs", "all"})
	if err != nil || len(e.ops) != 2 || e.ops[0].Kind != "set_envs" || e.ops[1].Kind != "set_lockfile_dev" || e.ops[1].Lockfile.Dev {
		t.Fatalf("%+v %v", e, err)
	}
}

func TestProjectEditPreviewsThenSaves(t *testing.T) {
	root := fixtureRoot(t)
	args := []string{"shop", "-since", "2026-01-31", "-lock-dev", "composer:composer.lock:prod", "-image", "prod=shop:1.4.2", "-env-set", "prod:php=8.3"}
	out, err := runProject(t, root, args...)
	if err != nil || !strings.Contains(out, "not saved: add -save") {
		t.Fatalf("%v\n%s", err, out)
	}
	if strings.Contains(readFile(t, root, "config/projects/shop.yaml"), "since") {
		t.Fatal("a preview wrote the file")
	}
	if out, err = runProject(t, root, append(args, "-save")...); err != nil || !strings.Contains(out, "saved ") {
		t.Fatalf("%v\n%s", err, out)
	}
	got := readFile(t, root, "config/projects/shop.yaml")
	for _, want := range []string{"since: 2026-01-31", "dev: true", "image: shop:1.4.2", `php: "8.3"`} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if _, err = runProject(t, root, "shop", "-since", "yesterday", "-save"); err == nil {
		t.Fatal("a bad date must be an error")
	}
}

func TestProjectListMarksDisabledProjects(t *testing.T) {
	root := fixtureRoot(t)
	if _, err := runProject(t, root, "disable", "shop", "-yes"); err != nil {
		t.Fatal(err)
	}
	out, err := capture(t, func() error {
		return withSession(root, slog.New(slog.NewTextHandler(io.Discard, nil)), func(s *ops.Session) error { return projectCmd(s, nil) })
	})
	if err != nil || !strings.Contains(out, "shop") || !strings.Contains(out, "disabled") {
		t.Fatalf("%v\n%s", err, out)
	}
}

func TestLifecyclePreviewsByDefault(t *testing.T) {
	root := fixtureRoot(t)
	out, err := runProject(t, root, "rename", "shop", "store")
	if err != nil || !strings.Contains(out, "rename shop -> store") || !strings.Contains(out, "findings: 2 (open 2)") || !strings.Contains(out, "add -yes") {
		t.Fatalf("%v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(root, "config", "projects", "store.yaml")); err == nil {
		t.Fatal("the preview applied the rename")
	}

	out, err = runProject(t, root, "delete", "shop")
	if err != nil || !strings.Contains(out, "destructive") {
		t.Fatalf("%v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(root, "config", "projects", "shop.yaml")); err != nil {
		t.Fatal("the preview deleted the project")
	}
}

func TestLifecycleApplies(t *testing.T) {
	root := fixtureRoot(t)
	out, err := runProject(t, root, "rename", "shop", "store", "-yes")
	if err != nil || !strings.Contains(out, "done: rename shop -> store") {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(readFile(t, root, "config/projects/store.yaml"), "name: store") {
		t.Fatal("the new file does not carry the new name")
	}

	if out, err = runProject(t, root, "duplicate", "store", "copy", "-yes"); err != nil || !strings.Contains(out, "done") {
		t.Fatalf("%v\n%s", err, out)
	}
	if out, err = runProject(t, root, "disable", "copy", "-yes"); err != nil || !strings.Contains(out, "done") {
		t.Fatalf("%v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(root, "config", "projects", "copy.yaml.disabled")); err != nil {
		t.Fatal("not disabled")
	}
	if out, err = runProject(t, root, "enable", "copy", "-yes"); err != nil || !strings.Contains(out, "done") {
		t.Fatalf("%v\n%s", err, out)
	}
	out, err = runProject(t, root, "delete", "store", "-yes", "-close-findings", "-json")
	if err != nil || !strings.Contains(out, `"applied": true`) {
		t.Fatalf("%v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(root, "config", "projects", "store.yaml")); err == nil {
		t.Fatal("not deleted")
	}
}

func TestLifecycleUsageAndErrors(t *testing.T) {
	root := fixtureRoot(t)
	if _, err := runProject(t, root, "rename", "shop"); err == nil || !strings.Contains(err.Error(), "NEW_NAME") {
		t.Errorf("rename without a new name: %v", err)
	}
	if _, err := runProject(t, root, "delete", "shop", "extra"); err == nil {
		t.Error("delete with two names must be rejected")
	}
	if _, err := runProject(t, root, "rename", "shop", "shop"); err == nil {
		t.Error("renaming to the same name must fail")
	}
	if _, err := runProject(t, root, "delete", "nope", "-yes"); err == nil {
		t.Error("an unknown project must fail")
	}
	if _, ok := lifecycleVerb([]string{"delete"}); ok {
		t.Error("a lone word is a project name, not a verb")
	}
	if _, ok := lifecycleVerb([]string{"delete", "-set", "php"}); ok {
		t.Error("a project called delete can still be edited")
	}
}

func TestProjectInAFileWithAnotherNameCanBeListedEditedAndDeleted(t *testing.T) {
	root := fixtureRoot(t)
	dir := filepath.Join(root, "config", "projects")
	if err := os.Rename(filepath.Join(dir, "shop.yaml"), filepath.Join(dir, "magento2-shop.yaml")); err != nil {
		t.Fatal(err)
	}
	out, err := runProject(t, root)
	if err != nil || !strings.Contains(out, "shop") {
		t.Fatalf("list: %v\n%s", err, out)
	}
	if out, err = runProject(t, root, "shop", "-since", "2026-01-02", "-save"); err != nil || !strings.Contains(readFile(t, root, "config/projects/magento2-shop.yaml"), "2026-01-02") {
		t.Fatalf("edit: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(dir, "shop.yaml")); err == nil {
		t.Fatal("the edit created shop.yaml")
	}
	if out, err = runProject(t, root, "delete", "shop", "-yes"); err != nil || !strings.Contains(out, "done: delete shop") {
		t.Fatalf("delete: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(dir, "magento2-shop.yaml")); err == nil {
		t.Fatal("the file is still there")
	}
}
