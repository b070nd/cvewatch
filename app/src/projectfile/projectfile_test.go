package projectfile

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/b070nd/cvewatch/app/src/model"
)

// shopExample is app/config/projects/shop.yaml.example.
const shopExample = `# Copy to <name>.yaml (any *.yaml in this folder is loaded and stays untracked),
# or let ` + "`cvewatch init -repo /path/to/repo`" + ` write one for you.
name: shop
envs: [dev, int, staging, prod]   # omit for all four
techs:                            # names must exist in techs.yaml
  - {name: php, version: "8.2"}
  - {name: elasticsearch, version: "8.11"}
  - {name: magento, version: "2.4.7"}
lockfiles:                        # re-read every run
  - {type: composer, path: /path/to/shop/composer.lock}
  - {type: npm, path: /path/to/shop/package-lock.json}
  # - {type: cyclonedx, path: /path/to/shop-prod.cdx.json, env: prod}   # an SBOM for one environment
environments:                     # what actually runs where
  prod:
    techs: {php: "8.2.30"}
    image: registry.example/shop@sha256:...   # recorded only
`

const blockStyle = `name: blog
# runtimes
techs:
  - name: php
    version: 8.2   # plain, on purpose
  - name: mysql

lockfiles:
  - type: composer
    path: composer.lock

# deployed
environments:
  prod:
    techs:
      php: "8.2.30"
`

func mustParse(t *testing.T, s string) *File {
	t.Helper()
	f, err := Parse([]byte(s))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return f
}

func mustBytes(t *testing.T, f *File) string {
	t.Helper()
	b, err := f.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	return string(b)
}

func mustApply(t *testing.T, s string, ops ...Op) string {
	t.Helper()
	f := mustParse(t, s)
	if err := f.Apply(ops...); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	return mustBytes(t, f)
}

// changed keeps only the added and removed lines of a diff.
func changed(d string) []string {
	var out []string
	for _, l := range strings.Split(d, "\n") {
		if strings.HasPrefix(l, "+ ") || strings.HasPrefix(l, "- ") {
			out = append(out, l)
		}
	}
	return out
}

func TestRoundTripKeepsEverything(t *testing.T) {
	for name, src := range map[string]string{"shop": shopExample, "block": blockStyle} {
		if got := mustBytes(t, mustParse(t, src)); got != src {
			t.Errorf("%s: round trip changed the file:\n%s", name, Diff([]byte(src), []byte(got)))
		}
	}
}

func TestParse(t *testing.T) {
	tests := []struct {
		name, src, wantErr string
	}{
		{"empty", "", "empty"},
		{"comments only", "# nothing\n", "empty"},
		{"not a mapping", "- a\n- b\n", "mapping"},
		{"unknown key", "name: x\nenviroments: {}\n", "enviroments"},
		{"bad type", "name: x\ntechs: oops\n", "oops"},
		{"two documents", "name: a\n---\nname: b\n", "one project"},
		{"broken yaml", "name: [x\n", "projectfile"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.src))
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want it to mention %q", err, tt.wantErr)
			}
		})
	}
	t.Run("crlf and bom become LF", func(t *testing.T) {
		got := mustBytes(t, mustParse(t, "\xef\xbb\xbfname: x\r\ntechs: []\r\n"))
		if got != "name: x\ntechs: []\n" {
			t.Fatalf("got %q", got)
		}
	})
}

func TestNew(t *testing.T) {
	f, err := New("my-shop2")
	if err != nil {
		t.Fatal(err)
	}
	got := mustBytes(t, f)
	want := "# A cvewatch project: what one system runs, so advisories can be matched to it.\nname: my-shop2\ntechs: []\nlockfiles: []\n"
	if got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
	if p := f.Project(); p.Name != "my-shop2" || len(p.Techs) != 0 {
		t.Fatalf("project = %+v", p)
	}
	for _, bad := range []string{"", "Shop", "-shop", "a/b", "a b", "../x", strings.Repeat("a", 64)} {
		if _, err := New(bad); err == nil {
			t.Errorf("New(%q) should fail", bad)
		}
	}
	if _, err := New(strings.Repeat("a", 63)); err != nil {
		t.Errorf("63 characters should be fine: %v", err)
	}
}

func TestApplyOnExample(t *testing.T) {
	tests := []struct {
		name string
		ops  []Op
		want []string // the added and removed lines, in order
	}{
		{"deployed version updated", []Op{{Kind: "set_env_tech", Env: "prod", Tech: "php", Version: "8.2.31"}},
			[]string{`-     techs: {php: "8.2.30"}`, `+     techs: {php: "8.2.31"}`}},
		{"deployed version in a new env", []Op{{Kind: "set_env_tech", Env: "staging", Tech: "php", Version: "8.2.30"}},
			[]string{`+   staging:`, `+     techs: {php: "8.2.30"}`}},
		{"second tech in an env", []Op{{Kind: "set_env_tech", Env: "prod", Tech: "node", Version: "20"}},
			[]string{`-     techs: {php: "8.2.30"}`, `+     techs: {php: "8.2.30", node: "20"}`}},
		{"image", []Op{{Kind: "set_image", Env: "prod", Image: "reg.example/shop:1.4"}},
			[]string{`-     image: registry.example/shop@sha256:...   # recorded only`, `+     image: reg.example/shop:1.4 # recorded only`}},
		{"image in a new env", []Op{{Kind: "set_image", Env: "dev", Image: "shop:dev"}},
			[]string{`+   dev:`, `+     image: shop:dev`}},
		{"lockfile with env", []Op{{Kind: "add_lockfile", Lockfile: model.Lockfile{Type: "cyclonedx", Path: "/p/shop-prod.cdx.json", Env: "prod"}}},
			[]string{`+   - {type: cyclonedx, path: /p/shop-prod.cdx.json, env: prod}`}},
		{"lockfile with dev", []Op{{Kind: "add_lockfile", Lockfile: model.Lockfile{Type: "pip", Path: "req.txt", Dev: true}}},
			[]string{`+   - {type: pip, path: req.txt, dev: true}`}},
		{"duplicate lockfile is ignored", []Op{{Kind: "add_lockfile", Lockfile: model.Lockfile{Type: "npm", Path: "/path/to/shop/package-lock.json"}}}, nil},
		{"remove lockfile", []Op{{Kind: "remove_lockfile", Lockfile: model.Lockfile{Path: "/path/to/shop/package-lock.json"}}},
			[]string{`-   - {type: npm, path: /path/to/shop/package-lock.json}`}},
		{"new tech", []Op{{Kind: "set_tech", Tech: "redis", Version: "7.2"}},
			[]string{`+   - {name: redis, version: "7.2"}`}},
		{"new tech without version", []Op{{Kind: "set_tech", Tech: "redis"}},
			[]string{`+   - {name: redis}`}},
		{"tech version changed, name matched ignoring case", []Op{{Kind: "set_tech", Tech: "PHP", Version: "8.3"}},
			[]string{`-   - {name: php, version: "8.2"}`, `+   - {name: php, version: "8.3"}`}},
		{"tech with empty version keeps the old one", []Op{{Kind: "set_tech", Tech: "php"}}, nil},
		{"remove tech", []Op{{Kind: "remove_tech", Tech: "Magento"}},
			[]string{`-   - {name: magento, version: "2.4.7"}`}},
		{"envs narrowed", []Op{{Kind: "set_envs", Envs: []model.Env{"staging", "prod"}}},
			[]string{`- envs: [dev, int, staging, prod]   # omit for all four`, `+ envs: [staging, prod] # omit for all four`}},
		{"remove env tech and prune", []Op{{Kind: "remove_env_tech", Env: "prod", Tech: "php"}},
			[]string{`-     techs: {php: "8.2.30"}`}},
		{"clear image", []Op{{Kind: "set_image", Env: "prod", Image: ""}},
			[]string{`-     image: registry.example/shop@sha256:...   # recorded only`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mustApply(t, shopExample, tt.ops...)
			if d := changed(Diff([]byte(shopExample), []byte(got))); !reflect.DeepEqual(d, tt.want) {
				t.Fatalf("changed lines\n got %q\nwant %q\nfull:\n%s", d, tt.want, got)
			}
			// the result must still be a valid project file
			if _, err := Parse([]byte(got)); err != nil {
				t.Fatalf("result does not parse: %v\n%s", err, got)
			}
		})
	}
}

func TestApplyResultsAreRight(t *testing.T) {
	f := mustParse(t, shopExample)
	err := f.Apply(
		Op{Kind: "set_env_tech", Env: "prod", Tech: "php", Version: "8.2.31"},
		Op{Kind: "set_env_tech", Env: "int", Tech: "node", Version: "20"},
		Op{Kind: "set_image", Env: "int", Image: "shop:int"},
		Op{Kind: "add_lockfile", Lockfile: model.Lockfile{Type: "cyclonedx", Path: "/x.json", Env: "prod", Dev: true}},
		Op{Kind: "set_tech", Tech: "redis", Version: "7.2"},
		Op{Kind: "set_envs", Envs: []model.Env{"int", "prod", "int"}},
	)
	if err != nil {
		t.Fatal(err)
	}
	p := f.Project()
	if !reflect.DeepEqual(p.Envs, []model.Env{"int", "prod"}) {
		t.Errorf("envs = %v", p.Envs)
	}
	if got := p.Environments["prod"].Techs["php"]; got != "8.2.31" {
		t.Errorf("prod php = %q", got)
	}
	if got := p.Environments["int"]; got.Techs["node"] != "20" || got.Image != "shop:int" {
		t.Errorf("int = %+v", got)
	}
	if got := p.Lockfiles[len(p.Lockfiles)-1]; got != (model.Lockfile{Type: "cyclonedx", Path: "/x.json", Env: "prod", Dev: true}) {
		t.Errorf("last lockfile = %+v", got)
	}
	if got := p.Techs[len(p.Techs)-1]; got != (model.ProjectTech{Name: "redis", Version: "7.2"}) {
		t.Errorf("last tech = %+v", got)
	}
	if got := p.Lockfiles[0].Path; got != "/path/to/shop/composer.lock" {
		t.Errorf("paths must not be rewritten, got %q", got)
	}
}

func TestVersionsAreQuoted(t *testing.T) {
	got := mustApply(t, "name: x\ntechs: []\n", Op{Kind: "set_tech", Tech: "php", Version: "8.2"},
		Op{Kind: "set_env_tech", Env: "dev", Tech: "php", Version: "8.20"})
	for _, want := range []string{`- {name: php, version: "8.2"}`, `techs: {php: "8.20"}`} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	// an existing plain version is rewritten quoted when it changes, and left alone otherwise
	got = mustApply(t, blockStyle, Op{Kind: "set_tech", Tech: "php", Version: "8.3"})
	if !strings.Contains(got, `version: "8.3"`) {
		t.Errorf("changed version not quoted:\n%s", got)
	}
	if same := mustApply(t, blockStyle, Op{Kind: "set_tech", Tech: "php", Version: "8.2"}); same != blockStyle {
		t.Errorf("setting the same version changed the file:\n%s", same)
	}
}

func TestBlockStyleFile(t *testing.T) {
	got := mustApply(t, blockStyle,
		Op{Kind: "set_tech", Tech: "redis", Version: "7"},
		Op{Kind: "set_tech", Tech: "mysql", Version: "8.0"},
		Op{Kind: "add_lockfile", Lockfile: model.Lockfile{Type: "npm", Path: "package-lock.json"}},
		Op{Kind: "set_env_tech", Env: "prod", Tech: "mysql", Version: "8.0.35"},
	)
	want := strings.NewReplacer(
		"  - name: mysql\n", "  - name: mysql\n    version: \"8.0\"\n  - {name: redis, version: \"7\"}\n",
		"    path: composer.lock\n", "    path: composer.lock\n  - {type: npm, path: package-lock.json}\n",
		"      php: \"8.2.30\"\n", "      php: \"8.2.30\"\n      mysql: \"8.0.35\"\n",
	).Replace(blockStyle)
	if got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
}

func TestBlankLinesAndCommentsSurviveEdits(t *testing.T) {
	got := mustApply(t, blockStyle, Op{Kind: "set_env_tech", Env: "prod", Tech: "php", Version: "8.2.31"})
	want := strings.Replace(blockStyle, `php: "8.2.30"`, `php: "8.2.31"`, 1)
	if got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
}

func TestSetEnvs(t *testing.T) {
	t.Run("empty list removes the key", func(t *testing.T) {
		got := mustApply(t, shopExample, Op{Kind: "set_envs"})
		if strings.Contains(got, "envs:") {
			t.Fatalf("envs still there:\n%s", got)
		}
		f := mustParse(t, got)
		if !reflect.DeepEqual(f.Project().EffectiveEnvs(), model.AllEnvs) {
			t.Fatalf("effective envs = %v", f.Project().EffectiveEnvs())
		}
	})
	t.Run("keeps the line comment", func(t *testing.T) {
		got := mustApply(t, shopExample, Op{Kind: "set_envs", Envs: []model.Env{"prod"}})
		if !strings.Contains(got, "envs: [prod] # omit for all four\n") {
			t.Fatalf("got\n%s", got)
		}
	})
	t.Run("new key goes after name", func(t *testing.T) {
		got := mustApply(t, "name: x\ntechs: []\n", Op{Kind: "set_envs", Envs: []model.Env{"dev", "prod"}})
		if got != "name: x\nenvs: [dev, prod]\ntechs: []\n" {
			t.Fatalf("got %q", got)
		}
	})
}

func TestApplyErrors(t *testing.T) {
	tests := []struct {
		name    string
		op      Op
		wantErr string
	}{
		{"unknown kind", Op{Kind: "explode"}, `unknown kind "explode"`},
		{"empty kind", Op{}, "unknown kind"},
		{"invalid env in set_envs", Op{Kind: "set_envs", Envs: []model.Env{"dev", "qa"}}, `"qa"`},
		{"invalid env in set_env_tech", Op{Kind: "set_env_tech", Env: "qa", Tech: "php", Version: "8"}, `"qa"`},
		{"missing env", Op{Kind: "set_image", Image: "x"}, "invalid env"},
		{"empty tech in set_tech", Op{Kind: "set_tech", Tech: "  "}, "empty"},
		{"empty tech in remove_tech", Op{Kind: "remove_tech"}, "empty"},
		{"empty tech in set_env_tech", Op{Kind: "set_env_tech", Env: "dev", Version: "1"}, "empty"},
		{"empty version in set_env_tech", Op{Kind: "set_env_tech", Env: "dev", Tech: "php"}, "version"},
		{"remove absent tech", Op{Kind: "remove_tech", Tech: "ruby"}, `"ruby"`},
		{"remove absent env tech", Op{Kind: "remove_env_tech", Env: "dev", Tech: "php"}, "environments.dev.techs.php"},
		{"remove absent env tech in known env", Op{Kind: "remove_env_tech", Env: "prod", Tech: "node"}, "environments.prod.techs.node"},
		{"remove absent lockfile", Op{Kind: "remove_lockfile", Lockfile: model.Lockfile{Path: "/nope"}}, `"/nope"`},
		{"remove lockfile for the wrong env", Op{Kind: "remove_lockfile", Lockfile: model.Lockfile{Path: "/path/to/shop/composer.lock", Env: "dev"}}, "dev"},
		{"lockfile without path", Op{Kind: "add_lockfile", Lockfile: model.Lockfile{Type: "npm"}}, "path"},
		{"lockfile with bad env", Op{Kind: "add_lockfile", Lockfile: model.Lockfile{Type: "npm", Path: "p", Env: "qa"}}, "qa"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := mustParse(t, shopExample)
			err := f.Apply(tt.op)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want it to mention %q", err, tt.wantErr)
			}
			if got := mustBytes(t, f); got != shopExample {
				t.Fatalf("a failed op changed the file:\n%s", got)
			}
		})
	}
}

func TestApplyIsAtomic(t *testing.T) {
	f := mustParse(t, shopExample)
	before := f.Project()
	err := f.Apply(
		Op{Kind: "set_tech", Tech: "redis", Version: "7"},
		Op{Kind: "set_env_tech", Env: "int", Tech: "php", Version: "8.2"},
		Op{Kind: "remove_tech", Tech: "does-not-exist"},
	)
	if err == nil || !strings.Contains(err.Error(), "op 3") {
		t.Fatalf("err = %v, want it to name op 3", err)
	}
	if got := mustBytes(t, f); got != shopExample {
		t.Fatalf("file changed after a failed Apply:\n%s", got)
	}
	if !reflect.DeepEqual(f.Project(), before) {
		t.Fatal("project changed after a failed Apply")
	}
}

func TestApplyIsIdempotent(t *testing.T) {
	ops := []Op{
		{Kind: "set_tech", Tech: "redis", Version: "7.2"},
		{Kind: "set_env_tech", Env: "int", Tech: "php", Version: "8.2.1"},
		{Kind: "set_image", Env: "int", Image: "shop:int"},
		{Kind: "add_lockfile", Lockfile: model.Lockfile{Type: "pip", Path: "r.txt", Env: "dev"}},
		{Kind: "set_envs", Envs: []model.Env{"dev", "prod"}},
	}
	once := mustApply(t, shopExample, ops...)
	twice := mustApply(t, once, ops...)
	if once != twice {
		t.Fatalf("second application changed the file:\n%s", Diff([]byte(once), []byte(twice)))
	}
}

func TestEmptyContainersAreFilled(t *testing.T) {
	// a key with nothing after it, and empty flow lists and maps
	src := "name: x\ntechs:\nlockfiles: []\nenvironments:\n  dev: {}\n"
	got := mustApply(t, src,
		Op{Kind: "set_tech", Tech: "php", Version: "8.2"},
		Op{Kind: "add_lockfile", Lockfile: model.Lockfile{Type: "npm", Path: "p"}},
		Op{Kind: "set_env_tech", Env: "dev", Tech: "php", Version: "8.2.1"},
	)
	want := "name: x\ntechs:\n  - {name: php, version: \"8.2\"}\nlockfiles:\n  - {type: npm, path: p}\nenvironments:\n  dev:\n    techs: {php: \"8.2.1\"}\n"
	if got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
	// removing the last item leaves a valid empty list
	got = mustApply(t, got, Op{Kind: "remove_tech", Tech: "php"}, Op{Kind: "remove_env_tech", Env: "dev", Tech: "php"})
	if want := "name: x\ntechs: []\nlockfiles:\n  - {type: npm, path: p}\n"; got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
}

func TestDiff(t *testing.T) {
	tests := []struct {
		name          string
		before, after string
		want          string
	}{
		{"equal", "a\nb\n", "a\nb\n", "(no changes)"},
		{"one line changed", "a\nb\nc\n", "a\nB\nc\n", "  a\n- b\n+ B\n  c\n"},
		{"added at the end", "a\nb\n", "a\nb\nc\n", "  a\n  b\n+ c\n"},
		{"removed at the start", "a\nb\nc\n", "b\nc\n", "- a\n  b\n  c\n"},
		{"context is limited and hunks are separated", "1\n2\n3\n4\n5\n6\n7\n8\n9\n", "1\n2\n3\nx\n5\n6\n7\n8\n9\n9b\n",
			"  2\n  3\n- 4\n+ x\n  5\n  6\n...\n  8\n  9\n+ 9b\n"},
		{"from nothing", "", "a\n", "+ a\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Diff([]byte(tt.before), []byte(tt.after)); got != tt.want {
				t.Fatalf("got\n%q\nwant\n%q", got, tt.want)
			}
		})
	}
}

func TestValidate(t *testing.T) {
	known := func(s string) bool { return s == "php" || s == "magento" }
	src := `name: ""
envs: [dev, qa]
techs:
  - {name: php, version: "8.2"}
  - {name: PHP}
  - {name: ruby, version: latest}
  - {name: ""}
lockfiles:
  - {type: composer, path: composer.lock}
  - {type: nope, path: x}
  - {type: npm, path: ""}
  - {type: npm, path: p, env: qa}
environments:
  prod:
    techs: {php: "8.2.30", node: "20"}
  uat: {}
`
	// "uat" and "qa" are not valid environments; the file still parses because
	// the model keys are plain strings
	issues := mustParse(t, src).Validate(known)
	got := map[string]string{}
	for _, i := range issues {
		got[i.Level+" "+i.Field] = i.Message
	}
	for _, want := range []string{
		"error name",
		"error envs[1]",
		"error techs[1].name", // duplicate of php, ignoring case
		"error techs[3].name", // empty
		"error lockfiles[1].type",
		"error lockfiles[2].path",
		"error lockfiles[3].env",
		"error environments.uat",
		"warning techs[2]",                     // ruby unknown and version "latest"
		"warning environments.prod",            // prod not in envs
		"warning environments.prod.techs.node", // unknown tech
	} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing issue %q; got %v", want, got)
		}
	}
	if n := len(issues); n != 12 {
		t.Errorf("got %d issues, want 12: %+v", n, issues)
	}

	// warnings: unknown tech, odd version, environment not in envs
	warn := mustParse(t, "name: x\nenvs: [dev]\ntechs:\n  - {name: ruby, version: \"8.2\"}\n  - {name: php, version: v2}\n  - {name: magento, version: x1}\nenvironments:\n  prod: {image: i}\n").Validate(known)
	var fields []string
	for _, i := range warn {
		if i.Level != "warning" {
			t.Errorf("unexpected %+v", i)
		}
		fields = append(fields, i.Field)
	}
	if want := []string{"techs[0]", "techs[2]", "environments.prod"}; !reflect.DeepEqual(fields, want) {
		t.Errorf("warning fields = %v, want %v", fields, want)
	}

	// nil known skips the catalog check; the shipped example is clean
	if got := mustParse(t, shopExample).Validate(nil); len(got) != 0 {
		t.Errorf("example has issues: %+v", got)
	}
	if got := mustParse(t, "name: x\ntechs: [{name: weird}]\n").Validate(nil); len(got) != 0 {
		t.Errorf("nil known should accept any tech: %+v", got)
	}
}

func TestWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "projects", "shop.yaml")
	backups := filepath.Join(dir, "projects", ".backup")
	t0 := time.Date(2026, 10, 28, 9, 30, 5, 0, time.UTC)

	read := func(p string) string {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	backupNames := func() []string {
		entries, _ := os.ReadDir(backups)
		var out []string
		for _, e := range entries {
			out = append(out, e.Name())
		}
		return out
	}

	if err := Write(path, []byte("name: shop\n"), backups, t0); err != nil {
		t.Fatal(err)
	}
	if read(path) != "name: shop\n" || len(backupNames()) != 0 {
		t.Fatalf("a new file needs no backup: %v", backupNames())
	}
	if err := Write(path, []byte("name: shop\n"), backups, t0); err != nil || len(backupNames()) != 0 {
		t.Fatalf("same content must not back up: %v %v", err, backupNames())
	}
	if err := Write(path, []byte("name: shop2\n"), backups, t0); err != nil {
		t.Fatal(err)
	}
	want := []string{"shop-20261028-093005.yaml"}
	if got := backupNames(); !reflect.DeepEqual(got, want) {
		t.Fatalf("backups = %v, want %v", got, want)
	}
	if read(filepath.Join(backups, want[0])) != "name: shop\n" || read(path) != "name: shop2\n" {
		t.Fatal("backup should hold the old content and the file the new")
	}
	// a second change in the same second keeps both backups
	if err := Write(path, []byte("name: shop3\n"), backups, t0); err != nil {
		t.Fatal(err)
	}
	if got := backupNames(); len(got) != 2 {
		t.Fatalf("backups = %v", got)
	}
	// no temp files anywhere
	for _, d := range []string{filepath.Dir(path), backups} {
		entries, _ := os.ReadDir(d)
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), ".tmp") {
				t.Errorf("temp file left behind: %s", e.Name())
			}
		}
	}
	if info, err := os.Stat(backups); err != nil || runtime.GOOS != "windows" && info.Mode().Perm() != 0o700 { // Windows has no owner-only modes
		t.Errorf("backup dir should be private: %v %v", info, err)
	}
}

func TestPath(t *testing.T) {
	got, err := Path("/etc/projects", "shop")
	if err != nil || got != filepath.Join("/etc/projects", "shop.yaml") {
		t.Fatalf("got %q, %v", got, err)
	}
	for _, bad := range []string{"../x", "a/b", `a\b`, "", ".hidden", "Shop", "shop.yaml"} {
		if _, err := Path("/etc/projects", bad); err == nil {
			t.Errorf("Path(%q) should fail", bad)
		}
	}
}

func TestList(t *testing.T) {
	dir := t.TempDir()
	if got, err := List(filepath.Join(dir, "missing")); err != nil || len(got) != 0 {
		t.Fatalf("missing dir: %v %v", got, err)
	}
	for _, f := range []string{"shop.yaml", "blog.yaml", "notes.txt", "shop.yaml.example", ".hidden.yaml", ".backup/old-20260101-000000.yaml", "sub.yaml/x.yaml"} {
		p := filepath.Join(dir, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("name: x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := List(dir)
	if err != nil || !reflect.DeepEqual(got, []string{"blog", "shop"}) {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestEndToEndEditAndSave(t *testing.T) {
	dir := t.TempDir()
	path, err := Path(dir, "shop")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(shopExample), 0o600); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	f := mustParse(t, string(raw))
	if err := f.Apply(Op{Kind: "set_env_tech", Env: "prod", Tech: "php", Version: "8.2.31"}); err != nil {
		t.Fatal(err)
	}
	out, _ := f.Bytes()
	if err := Write(path, out, filepath.Join(dir, ".backup"), time.Now()); err != nil {
		t.Fatal(err)
	}
	names, _ := List(dir)
	if !reflect.DeepEqual(names, []string{"shop"}) {
		t.Fatalf("names = %v", names)
	}
	if got, _ := os.ReadFile(path); string(got) != strings.Replace(shopExample, "8.2.30", "8.2.31", 1) {
		t.Fatalf("saved file:\n%s", got)
	}
}
