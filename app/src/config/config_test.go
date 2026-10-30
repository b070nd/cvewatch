package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	shipped "github.com/b070nd/cvewatch/app/src/defaults"
	"github.com/b070nd/cvewatch/app/src/model"
)

func put(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, rel)
	os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoadDefaultsAndWarnings(t *testing.T) {
	root := t.TempDir()
	put(t, root, "config/techs.yaml", "techs: [{name: php}]\n")
	put(t, root, "config/projects/a.yaml", "name: a\ntechs: [{name: cobol}]\n")
	b, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if b.Interval.Hours() != 4 || len(b.Warnings) != 1 || len(b.Projects[0].EffectiveEnvs()) != 4 {
		t.Fatalf("%+v", b)
	}
}

func TestLoadRejectsMistakes(t *testing.T) {
	cases := map[string][2]string{
		"unknown key": {"config/config.yaml", "intervall: 1h\n"},
		"bad env":     {"config/projects/a.yaml", "name: a\nenvs: [qa]\n"},
		"bad source":  {"sources/s.yaml", "sources: [{id: x, type: rss}]\n"},
		"http source": {"sources/s.yaml", "sources: [{id: x, type: rss, url: 'http://a.test/f'}]\n"},
		"creds":       {"sources/s.yaml", "sources: [{id: x, type: rss, url: 'https://u:p@a.test/f'}]\n"},
		"retention":   {"config/config.yaml", "lookback: 100h\nretention: 120h\n"},
		"tui refresh": {"config/config.yaml", "tui:\n  refresh: 500ms\n"},
		"tui zero":    {"config/config.yaml", "tui:\n  refresh: 0s\n"},
		"tui fetch":   {"config/config.yaml", "tui:\n  fetch: -1m\n"},
		"bad since":   {"config/projects/a.yaml", "name: a\nsince: soon\n"},
	}
	for name, c := range cases {
		root := t.TempDir()
		put(t, root, c[0], c[1])
		if _, err := Load(root); err == nil {
			t.Errorf("%s: expected an error", name)
		} else if strings.TrimSpace(err.Error()) == "" {
			t.Errorf("%s: empty error", name)
		}
	}
}

func TestProjectSinceIsADateAndFutureDatesWarn(t *testing.T) {
	root := t.TempDir()
	put(t, root, "config/techs.yaml", "techs: [{name: php}]\n")
	put(t, root, "config/projects/a.yaml", "name: a\ntechs: [{name: php}]\nsince: 2026-01-01\n")
	put(t, root, "config/projects/b.yaml", "name: b\ntechs: [{name: php}]\nsince: 2030-01-01\n")
	b, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := b.Projects[0].Since, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC); !got.Equal(want) {
		t.Fatalf("since = %v, want %v", got, want)
	}
	if !b.Projects[1].Since.After(time.Now()) {
		t.Fatalf("since 2030 must be in the future: %v", b.Projects[1].Since)
	}
	if len(b.Warnings) != 1 || b.Warnings[0] != "project b: since 2030-01-01 is in the future, so every dated vulnerability is skipped for now" {
		t.Fatalf("warnings = %v", b.Warnings)
	}
}

func TestLoadLenientDropsBrokenProjects(t *testing.T) {
	root := t.TempDir()
	put(t, root, "config/techs.yaml", "techs: [{name: php}]\n")
	put(t, root, "config/config.yaml", "access:\n  alice: {projects: [yaml, key, env, lock, good]}\n")
	put(t, root, "config/projects/good.yaml", "name: good\ntechs: [{name: php}]\n")
	put(t, root, "config/projects/yaml.yaml", "name: yaml\ntechs: [\n")
	put(t, root, "config/projects/key.yaml", "name: key\nbogus: 1\n")
	put(t, root, "config/projects/env.yaml", "name: env\nenvs: [qa]\n")
	put(t, root, "config/projects/lock.yaml", "name: lock\nlockfiles: [{type: nope, path: x}]\n")
	b, err := LoadLenient(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Projects) != 1 || b.Projects[0].Name != "good" {
		t.Fatalf("projects = %+v", b.Projects)
	}
	want := map[string]string{"yaml": "yaml", "key": "bogus", "env": `unknown env "qa"`, "lock": `lockfile type "nope"`}
	if len(b.Broken) != len(want) {
		t.Fatalf("broken = %+v", b.Broken)
	}
	for _, br := range b.Broken {
		sub, ok := want[br.Name]
		if !ok || !strings.Contains(br.Err, sub) || strings.Contains(br.Err, "\n") {
			t.Errorf("broken %+v, want %q", br, sub)
		}
		if br.File != filepath.Join(root, "config", "projects", br.Name+".yaml") {
			t.Errorf("file = %q", br.File)
		}
	}
}

func TestLoadStillFailsOnBrokenProject(t *testing.T) {
	cases := map[string]struct{ body, want string }{
		"yaml": {"name: a\ntechs: [\n", "a.yaml"},
		"key":  {"name: a\nbogus: 1\n", "bogus"},
		"env":  {"name: a\nenvs: [qa]\n", `unknown env "qa"`},
		"lock": {"name: a\nlockfiles: [{type: nope, path: x}]\n", `lockfile type "nope"`},
	}
	for name, c := range cases {
		root := t.TempDir()
		put(t, root, "config/projects/a.yaml", c.body)
		if _, err := Load(root); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: Load error = %v", name, err)
		}
		b, err := LoadLenient(root)
		if err != nil || len(b.Projects) != 0 || len(b.Broken) != 1 || !strings.Contains(b.Broken[0].Err, c.want) {
			t.Errorf("%s: LoadLenient = %+v, %v", name, b, err)
		}
	}
}

func TestLoadLenientStillFailsOnOtherProblems(t *testing.T) {
	root := t.TempDir()
	put(t, root, "config/config.yaml", "intervall: 1h\n")
	put(t, root, "config/projects/bad.yaml", "name: bad\nenvs: [qa]\n")
	if _, err := LoadLenient(root); err == nil {
		t.Fatal("a broken config.yaml must stay fatal")
	}
}

func TestLoadLenientAccessNamesBrokenProjects(t *testing.T) {
	root := t.TempDir()
	put(t, root, "config/config.yaml", "access:\n  alice: {projects: [env]}\n")
	put(t, root, "config/projects/env.yaml", "name: env\nenvs: [qa]\n")
	if _, err := LoadLenient(root); err != nil {
		t.Fatalf("access to a broken project must stay valid: %v", err)
	}
	put(t, root, "config/config.yaml", "access:\n  alice: {projects: [nope]}\n")
	if _, err := LoadLenient(root); err == nil {
		t.Fatal("access to an unknown project must fail")
	}
}

// uncomment turns the commented example that starts at the line "# <key>:" into live yaml.
func uncomment(t *testing.T, template []byte, key string) string {
	t.Helper()
	var out []string
	on := false
	for _, l := range strings.Split(string(template), "\n") {
		switch {
		case strings.HasPrefix(l, "# "+key+":"):
			on = true
		case !strings.HasPrefix(l, "#"):
			on = false
		}
		if on {
			out = append(out, strings.TrimPrefix(strings.TrimPrefix(l, "#"), " "))
		}
	}
	if len(out) == 0 {
		t.Fatalf("no commented %s example", key)
	}
	return strings.Join(out, "\n") + "\n"
}

func TestShippedExamplesLoadWhenUncommented(t *testing.T) {
	root := t.TempDir()
	put(t, root, "config/techs.yaml", uncomment(t, shipped.UserTechs(), "techs"))
	put(t, root, "sources/custom.yaml", uncomment(t, shipped.UserSources(), "sources"))
	put(t, root, "config/projects/shop.yaml", "name: shop\n")
	put(t, root, "config/config.yaml", uncomment(t, shipped.Settings(), "access")+uncomment(t, shipped.Settings(), "dashboard")+uncomment(t, shipped.Settings(), "tui"))
	b, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if tech, ok := b.Catalog.Get("acme-gateway"); !ok || len(tech.Aliases) != 1 {
		t.Fatalf("example tech not loaded: %+v", tech)
	}
	if _, ok := b.Catalog.Get("wordpress"); ok {
		t.Fatal("the disabled example did not remove the shipped entry")
	}
	if !slices.ContainsFunc(b.Sources, func(s model.Source) bool { return s.ID == "vendor-psirt" }) {
		t.Fatal("example feed not loaded")
	}
}

func TestCheckUsesTheOverlayAndAttributesIssues(t *testing.T) {
	root := t.TempDir()
	put(t, root, "config/config.yaml", "interval: 1h\n")
	put(t, root, "config/projects/shop.yaml", "name: shop\n")
	settings := SettingsPath(root)

	b, issues := Check(root, Overlay{settings: []byte("interval: 0s\naccess:\n  bob: {projects: [nope]}\npolicy:\n  rules: [{name: a}]\n")})
	if b == nil || len(issues) != 3 {
		t.Fatalf("%+v %+v", b, issues)
	}
	got := map[string]string{}
	for _, is := range issues {
		if is.File != settings {
			t.Errorf("file = %q", is.File)
		}
		got[is.Field] = is.Msg
	}
	for _, f := range []string{"interval", "access.bob.projects", "policy.rules.0.fix_within"} {
		if got[f] == "" {
			t.Errorf("no issue for %s: %v", f, got)
		}
	}
	if _, err := Load(root); err != nil {
		t.Fatalf("Check changed what is on disk: %v", err)
	}

	b, issues = Check(root, Overlay{settings: []byte("intervall: 1h\nhttp: {retries: x}\n")})
	if b != nil || len(issues) != 2 || issues[0].Line != 1 || issues[1].Line != 2 || issues[0].File != settings {
		t.Fatalf("%+v", issues)
	}

	b, issues = Check(root, Overlay{filepath.Join(root, "sources", "new.yaml"): []byte("sources: [{id: x, type: rss, url: 'http://a.test/f'}]\n"), filepath.Join(root, "config", "projects", "shop.yaml"): nil})
	if b == nil || len(b.Projects) != 0 || len(issues) != 1 || issues[0].Field != "sources.[id=x].url" || !strings.HasSuffix(issues[0].File, "new.yaml") {
		t.Fatalf("%+v %+v", b, issues)
	}
}

func TestTUISettingsDefaultsAndOverrides(t *testing.T) {
	if d := Defaults().TUI; d.Refresh != 30*time.Second || d.Fetch != 0 {
		t.Fatalf("defaults %+v", d)
	}
	root := t.TempDir()
	b, err := Load(root)
	if err != nil || b.TUI != Defaults().TUI {
		t.Fatalf("no config.yaml: %+v %v", b.TUI, err)
	}
	put(t, root, "config/config.yaml", "tui:\n  fetch: 15m\n")
	b, err = Load(root)
	if err != nil || b.TUI.Refresh != 30*time.Second || b.TUI.Fetch != 15*time.Minute {
		t.Fatalf("a missing key keeps its default: %+v %v", b.TUI, err)
	}
	put(t, root, "config/config.yaml", "tui:\n  refresh: 1s\n  fetch: 0s\n")
	if b, err = Load(root); err != nil || b.TUI.Refresh != time.Second || b.TUI.Fetch != 0 {
		t.Fatalf("the minimum and zero are allowed: %+v %v", b.TUI, err)
	}
}

func TestCheckAttributesTUIIssuesToTheirKeys(t *testing.T) {
	root := t.TempDir()
	_, issues := Check(root, Overlay{SettingsPath(root): []byte("tui:\n  refresh: 200ms\n  fetch: -1s\n")})
	got := map[string]bool{}
	for _, is := range issues {
		got[is.Field] = true
	}
	if !got["tui.refresh"] || !got["tui.fetch"] {
		t.Fatalf("issues %+v", issues)
	}
}

func TestLoadTUIFallsBackPerValue(t *testing.T) {
	root := t.TempDir()
	if got := LoadTUI(root); got != Defaults().TUI {
		t.Fatalf("no file: %+v", got)
	}
	for text, want := range map[string]TUI{
		"tui:\n  refresh: 2m\n  fetch: 1h\n":    {Refresh: 2 * time.Minute, Fetch: time.Hour},
		"tui:\n  refresh: 10ms\n  fetch: -1h\n": Defaults().TUI,
		"tui: [broken\n":                        Defaults().TUI,
		"interval: nope\ntui:\n  refresh: 9s\n": {Refresh: 9 * time.Second},
		"tui:\n  refresh: soon\n":               Defaults().TUI,
	} {
		put(t, root, "config/config.yaml", text)
		if got := LoadTUI(root); got != want {
			t.Errorf("%q: got %+v, want %+v", text, got, want)
		}
	}
}

func TestProjectFilesAreKeyedByTheNameInTheFile(t *testing.T) {
	root := t.TempDir()
	put(t, root, "config/techs.yaml", "techs: [{name: php}]\n")
	put(t, root, "config/projects/magento2-shop.yaml", "name: shop\ntechs: [{name: php}]\n")
	put(t, root, "config/projects/shop-copy.yaml", "name: shop\n") // second claim on a name: broken, the first file keeps it
	put(t, root, "config/projects/bad.yaml", "name: [\n")
	b, err := LoadLenient(root)
	if err != nil {
		t.Fatal(err)
	}
	dir := ProjectsDir(root)
	got := b.ProjectFiles()
	want := map[string]string{
		"shop":      filepath.Join(dir, "magento2-shop.yaml"),
		"shop-copy": filepath.Join(dir, "shop-copy.yaml"),
		"bad":       filepath.Join(dir, "bad.yaml"),
	}
	for name, file := range want {
		if abs, _ := filepath.Abs(got[name]); abs != file && got[name] != file {
			t.Errorf("%s: file %q, want %q (all: %v)", name, got[name], file, got)
		}
	}
	if len(got) != len(want) {
		t.Errorf("files = %v", got)
	}
	got["shop"] = "changed"
	if b.ProjectFiles()["shop"] == "changed" {
		t.Error("ProjectFiles must hand out a copy")
	}
}
