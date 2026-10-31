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
		"bad env":     {"config/projects/a.yaml", "name: a\nenvs: [QA]\n"},
		"env name":    {"config/projects/a.yaml", "name: a\nenvs: [local, 2fast]\n"},
		"lock env":    {"config/projects/a.yaml", "name: a\nlockfiles: [{type: npm, path: p, env: 'a b'}]\n"},
		"env key":     {"config/projects/a.yaml", "name: a\nenvironments: {Prod: {image: i}}\n"},
		"rule env":    {"config/config.yaml", "policy:\n  rules:\n    - {name: r, env: Prod, fix_within: 24h}\n"},
		"digest env":  {"config/config.yaml", "notify:\n  digest:\n    daily_at: '08:00'\n    env: Prod\n"},
		"bad source":  {"sources/s.yaml", "sources: [{id: x, type: rss}]\n"},
		"http source": {"sources/s.yaml", "sources: [{id: x, type: rss, url: 'http://a.test/f'}]\n"},
		"creds":       {"sources/s.yaml", "sources: [{id: x, type: rss, url: 'https://u:p@a.test/f'}]\n"},
		"retention":   {"config/config.yaml", "lookback: 100h\nretention: 120h\n"},
		"tui refresh": {"config/config.yaml", "tui:\n  refresh: 500ms\n"},
		"tui zero":    {"config/config.yaml", "tui:\n  refresh: 0s\n"},
		"tui fetch":   {"config/config.yaml", "tui:\n  fetch: -1m\n"},
		"bad since":   {"config/projects/a.yaml", "name: a\nsince: soon\n"},
		"when key":    {"config/projects/a.yaml", "name: a\nenvs: [prod]\nwhen@Prod: {image: i}\n"},
		"when env":    {"config/projects/a.yaml", "name: a\nenvs: [prod]\nwhen@qa: {image: i}\n"},
		"when field":  {"config/projects/a.yaml", "name: a\nenvs: [prod]\nwhen@prod: {tech: {}}\n"},
		"both":        {"config/projects/a.yaml", "name: a\nenvs: [prod]\nenvironments: {prod: {image: a}}\nwhen@prod: {image: b}\n"},
		"tech envs":   {"config/projects/a.yaml", "name: a\ntechs: [{name: php, envs: [Prod]}]\n"},
		"top key":     {"config/projects/a.yaml", "name: a\nwhens@prod: {}\n"},
		"vendor":      {"config/projects/a.yaml", "name: a\nvendor: Acme Corp\n"},
		"vendor long": {"config/projects/a.yaml", "name: a\nvendor: " + strings.Repeat("a", 64) + "\n"},
		"grant":       {"config/config.yaml", "access:\n  alice: {projects: ['vendor:Acme Corp']}\n"},
		"grant empty": {"config/config.yaml", "access:\n  alice: {projects: ['vendor:']}\n"},
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
	put(t, root, "config/projects/env.yaml", "name: env\nenvs: [QA]\n")
	put(t, root, "config/projects/lock.yaml", "name: lock\nlockfiles: [{type: nope, path: x}]\n")
	b, err := LoadLenient(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Projects) != 1 || b.Projects[0].Name != "good" {
		t.Fatalf("projects = %+v", b.Projects)
	}
	want := map[string]string{"yaml": "yaml", "key": "bogus", "env": `"QA" is not a valid environment name`, "lock": `lockfile type "nope"`}
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
		"env":  {"name: a\nenvs: [QA]\n", `"QA" is not a valid environment name`},
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
	put(t, root, "config/projects/bad.yaml", "name: bad\nenvs: [QA]\n")
	if _, err := LoadLenient(root); err == nil {
		t.Fatal("a broken config.yaml must stay fatal")
	}
}

func TestLoadLenientAccessNamesBrokenProjects(t *testing.T) {
	root := t.TempDir()
	put(t, root, "config/config.yaml", "access:\n  alice: {projects: [env]}\n")
	put(t, root, "config/projects/env.yaml", "name: env\nenvs: [QA]\n")
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
	put(t, root, "config/config.yaml", uncomment(t, shipped.Settings(), "access")+uncomment(t, shipped.Settings(), "dashboard")+uncomment(t, shipped.Settings(), "tui")+uncomment(t, shipped.Settings(), "horizon"))
	b, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if b.Horizon.Window != WindowUnlimited || b.Horizon.From != "2026-01-01" {
		t.Fatalf("example horizon not loaded: %+v", b.Horizon)
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

func TestTUIEditorIsOptionalAndNotBlank(t *testing.T) {
	root := t.TempDir()
	put(t, root, "config/config.yaml", "tui:\n  editor: code --wait\n")
	if b, err := Load(root); err != nil || b.TUI.Editor != "code --wait" || LoadTUI(root).Editor != "code --wait" {
		t.Fatalf("editor %+v %v", b.TUI, err)
	}
	put(t, root, "config/config.yaml", "tui:\n  editor: \"   \"\n")
	if _, err := Load(root); err == nil || !strings.Contains(err.Error(), "tui.editor") {
		t.Fatalf("a blank editor is refused: %v", err)
	}
	if got := LoadTUI(root); got != Defaults().TUI {
		t.Fatalf("the interface still starts: %+v", got)
	}
	put(t, root, "config/config.yaml", "tui:\n  editor: \"\"\n")
	if _, err := Load(root); err != nil {
		t.Fatalf("empty means not set: %v", err)
	}
}

func TestLoadTUIFallsBackPerValue(t *testing.T) {
	root := t.TempDir()
	if got := LoadTUI(root); got != Defaults().TUI {
		t.Fatalf("no file: %+v", got)
	}
	for text, want := range map[string]TUI{
		"tui:\n  refresh: 2m\n  fetch: 1h\n":    {Refresh: 2 * time.Minute, Fetch: time.Hour, Auto: true},
		"tui:\n  auto: false\n":                 {Refresh: 30 * time.Second},
		"tui:\n  refresh: 10ms\n  fetch: -1h\n": Defaults().TUI,
		"tui: [broken\n":                        Defaults().TUI,
		"interval: nope\ntui:\n  refresh: 9s\n": {Refresh: 9 * time.Second, Auto: true},
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

func TestAnyEnvironmentNameLoads(t *testing.T) {
	root := t.TempDir()
	put(t, root, "config/techs.yaml", "techs: [{name: php}]\n")
	put(t, root, "config/projects/a.yaml", "name: a\nenvs: [local, qa-2, production]\ntechs: [{name: php}]\nlockfiles: [{type: npm, path: p, env: qa-2}]\nenvironments: {qa-2: {image: i}}\n")
	put(t, root, "config/projects/b.yaml", "name: b\n")
	put(t, root, "config/config.yaml", "policy:\n  rules:\n    - {name: r, env: production, fix_within: 24h}\nnotify:\n  digest:\n    daily_at: '08:00'\n    env: production\n")
	b, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if got := b.Projects[0].EffectiveEnvs(); !slices.Equal(got, []model.Env{"local", "qa-2", "production"}) {
		t.Errorf("envs = %v", got)
	}
	if got := b.Projects[1].EffectiveEnvs(); !slices.Equal(got, []model.Env{"dev", "int", "staging", "prod"}) {
		t.Errorf("a file without envs keeps the old four: %v", got)
	}
}

func TestProjectDifferencesInEitherSpellingMeanTheSame(t *testing.T) {
	const generic = "name: a\nenvs: [local, prod]\ntechs:\n  - {name: php, version: \"8.2\"}\n  - {name: xdebug, envs: [local]}\n  - {name: mysql, version: \"8.0\"}\n"
	spellings := map[string]string{
		"when@":        generic + "when@prod:\n  techs: {php: \"8.3\", varnish: \"7.4\"}\n  exclude: [mysql]\n  image: shop:1\n",
		"environments": generic + "environments:\n  prod:\n    techs: {php: \"8.3\", varnish: \"7.4\"}\n    exclude: [mysql]\n    image: shop:1\n",
	}
	for name, body := range spellings {
		root := t.TempDir()
		put(t, root, "config/techs.yaml", "techs: [{name: php}, {name: xdebug}, {name: mysql}, {name: varnish}]\n")
		put(t, root, "config/projects/a.yaml", body)
		b, err := Load(root)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		p := b.Projects[0]
		show := func(env model.Env) string {
			var out []string
			for _, tt := range p.TechsIn(env) {
				out = append(out, tt.Name+"="+tt.Version)
			}
			return strings.Join(out, " ")
		}
		if got := show("local"); got != "php=8.2 xdebug= mysql=8.0" {
			t.Errorf("%s local: %q", name, got)
		}
		if got := show("prod"); got != "php=8.3 varnish=7.4" {
			t.Errorf("%s prod: %q", name, got)
		}
		if p.Environments["prod"].Image != "shop:1" || p.Environments["prod"].Old != (name == "environments") {
			t.Errorf("%s: %+v", name, p.Environments["prod"])
		}
		if len(b.Warnings) != 0 {
			t.Errorf("%s: warnings %v", name, b.Warnings)
		}
	}
}

func TestStaleDifferencesBreakOnlyTheirProject(t *testing.T) {
	root := t.TempDir()
	put(t, root, "config/projects/a.yaml", "name: a\nenvs: [prod]\nwhen@qa:\n  image: i\n")
	put(t, root, "config/projects/b.yaml", "name: b\nenvs: [prod]\nenvironments:\n  qa: {image: i}\n")
	b, err := LoadLenient(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Broken) != 1 || b.Broken[0].Name != "a" || !strings.Contains(b.Broken[0].Err, "when@qa") || len(b.Projects) != 1 || b.Projects[0].Name != "b" {
		t.Fatalf("broken = %+v, projects = %d", b.Broken, len(b.Projects))
	}
}

func TestWarningsNameTheSpellingOfTheFile(t *testing.T) {
	root := t.TempDir()
	put(t, root, "config/techs.yaml", "techs: [{name: php}]\n")
	put(t, root, "config/projects/a.yaml", "name: a\nenvs: [prod]\ntechs: [{name: php}]\nwhen@prod:\n  techs: {cobol: \"1\"}\n")
	put(t, root, "config/projects/b.yaml", "name: b\nenvs: [prod]\ntechs: [{name: php}]\nenvironments:\n  prod:\n    techs: {cobol: \"1\"}\n")
	b, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	all := strings.Join(b.Warnings, "\n")
	if !strings.Contains(all, "project a: when@prod: tech \"cobol\"") || !strings.Contains(all, "project b: environments.prod: tech \"cobol\"") {
		t.Errorf("warnings:\n%s", all)
	}
}

func sourceByID(b *Bundle, id string) (model.Source, bool) {
	i := slices.IndexFunc(b.Sources, func(s model.Source) bool { return s.ID == id })
	if i < 0 {
		return model.Source{}, false
	}
	return b.Sources[i], true
}

func TestSourceEntryForAShippedIDOverridesOnlyItsFields(t *testing.T) {
	root := t.TempDir()
	put(t, root, "sources/a.yaml", "sources:\n  - {id: cve-records, disabled: true}\n  - {id: nvd, url: 'https://nvd.test/?s={since}'}\n")
	b, issues := Check(root, nil)
	if len(issues) != 0 {
		t.Fatalf("shorthand rejected: %+v", issues)
	}
	if s, ok := sourceByID(b, "cve-records"); !ok || !s.Disabled || s.Type != "cve" || s.URL == "" || !s.MatchTitleOnly {
		t.Fatalf("cve-records = %+v", s)
	}
	if s, _ := sourceByID(b, "nvd"); s.Disabled || s.Type != "nvd" || s.URL != "https://nvd.test/?s={since}" || !s.MatchStructured || !s.MatchTitleOnly {
		t.Fatalf("nvd = %+v", s)
	}
	if s, _ := sourceByID(b, "kev"); s.Disabled {
		t.Fatalf("an untouched feed changed: %+v", s)
	}
	if b.DefaultSources {
		t.Error("a user file is present")
	}

	put(t, root, "sources/b.yaml", "sources: [{id: cve-records, disabled: false}]\n")
	b, issues = Check(root, nil)
	if s, _ := sourceByID(b, "cve-records"); len(issues) != 0 || s.Disabled {
		t.Fatalf("a later file did not switch it back on: %+v %+v", issues, s)
	}
}

func TestSourceEntryForAnUnknownIDStillNeedsATypeAndURL(t *testing.T) {
	root := t.TempDir()
	put(t, root, "sources/a.yaml", "sources: [{id: nope, disabled: true}]\n")
	if _, issues := Check(root, nil); len(issues) == 0 || issues[0].Field != "sources.[id=nope].type" {
		t.Fatalf("%+v", issues)
	}
	put(t, root, "sources/a.yaml", "sources: [{id: cve-records, disable: true}]\n")
	if _, issues := Check(root, nil); len(issues) == 0 || issues[0].Line != 1 || !strings.Contains(issues[0].Msg, "disable") {
		t.Fatalf("a mistyped key must fail: %+v", issues)
	}
}

func TestSourceEntryCanOverrideAVendorFeedOfATechnology(t *testing.T) {
	root := t.TempDir()
	put(t, root, "config/projects/a.yaml", "name: a\ntechs: [{name: fortios}]\n")
	b, _ := Check(root, nil)
	var feed string
	for _, tc := range b.Techs {
		if tc.Name == "fortios" && len(tc.Feeds) > 0 {
			feed = tc.Feeds[0].ID
		}
	}
	if feed == "" {
		t.Skip("fortios has no shipped feed")
	}
	put(t, root, "sources/a.yaml", "sources: [{id: "+feed+", disabled: true}]\n")
	b, issues := Check(root, nil)
	if s, ok := sourceByID(b, feed); len(issues) != 0 || !ok || !s.Disabled || s.URL == "" {
		t.Fatalf("%+v %+v", issues, s)
	}
}

func TestVendorGrantCoversEveryProjectOfTheVendorAtRequestTime(t *testing.T) {
	root := t.TempDir()
	put(t, root, "config/config.yaml", "access:\n  alice: {projects: ['vendor:acme', blog]}\n  carol: {projects: ['vendor:acme'], write: true}\n  bob: {projects: ['*']}\n")
	put(t, root, "config/projects/shop.yaml", "name: shop\nvendor: acme\n")
	put(t, root, "config/projects/crm.yaml", "name: crm\nvendor: acme\n")
	put(t, root, "config/projects/blog.yaml", "name: blog\n")
	put(t, root, "config/projects/other.yaml", "name: other\nvendor: globex\n")
	b, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if got, write, open := b.Allowed("alice"); open || write || !slices.Equal(slices.Sorted(slices.Values(got)), []string{"blog", "crm", "shop"}) {
		t.Fatalf("alice: %v write=%v open=%v", got, write, open)
	}
	if got, write, _ := b.Allowed("carol"); !write || !slices.Equal(slices.Sorted(slices.Values(got)), []string{"crm", "shop"}) {
		t.Fatalf("carol: %v write=%v", got, write)
	}
	if got, _, open := b.Allowed("bob"); !open || got != nil {
		t.Fatalf("bob: %v open=%v", got, open)
	}

	// a project added later is covered by the next request, and one that left the vendor is not
	put(t, root, "config/projects/erp.yaml", "name: erp\nvendor: acme\n")
	put(t, root, "config/projects/crm.yaml", "name: crm\nvendor: globex\n")
	b, err = Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if got, _, _ := b.Allowed("carol"); !slices.Equal(slices.Sorted(slices.Values(got)), []string{"erp", "shop"}) {
		t.Fatalf("carol after the change: %v", got)
	}

	// a vendor without projects grants nothing, and is no error: its last project may be deleted
	put(t, root, "config/config.yaml", "access:\n  dave: {projects: ['vendor:nobody']}\n")
	b, err = Load(root)
	if err != nil {
		t.Fatalf("a vendor without projects must stay valid: %v", err)
	}
	if got, _, open := b.Allowed("dave"); open || len(got) != 0 {
		t.Fatalf("dave: %v open=%v", got, open)
	}
}

func TestShippedGhsaSourceReadsItsTokenFromTheEnvironment(t *testing.T) {
	b, issues := Check(t.TempDir(), nil)
	if len(issues) != 0 {
		t.Fatalf("%+v", issues)
	}
	if s, ok := sourceByID(b, "ghsa"); !ok || s.AuthEnv != "GITHUB_TOKEN" {
		t.Fatalf("ghsa = %+v", s)
	}
	root := t.TempDir()
	put(t, root, "sources/a.yaml", "sources:\n  - {id: ghsa, auth_env: MY_TOKEN}\n")
	b, _ = Check(root, nil)
	if s, _ := sourceByID(b, "ghsa"); s.AuthEnv != "MY_TOKEN" || s.Type != "ghsa" {
		t.Fatalf("override: %+v", s)
	}
}

func TestSourceAuthEnvMustBeAVariableNameNotAToken(t *testing.T) {
	root := t.TempDir()
	put(t, root, "sources/a.yaml", "sources:\n  - {id: ghsa, auth_env: 'ghp_secret-value 123'}\n")
	_, issues := Check(root, nil)
	if len(issues) == 0 || issues[0].Field != "sources.[id=ghsa].auth_env" {
		t.Fatalf("%+v", issues)
	}
	for _, i := range issues {
		if strings.Contains(i.Msg, "ghp_secret") {
			t.Errorf("the value is echoed: %q", i.Msg)
		}
	}
}
