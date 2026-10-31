package projectfile

import (
	"slices"
	"strings"
	"testing"

	"github.com/b070nd/cvewatch/app/src/model"
)

const envsSample = `name: shop
envs: [dev, prod]   # where it runs
techs:
  - {name: php, version: "8.2"}
lockfiles:
  - {type: composer, path: composer.lock, env: prod}
  - {type: npm, path: package-lock.json}
when@prod:
  techs: {php: "8.3"}
  image: shop:1
when@dev:
  image: shop:dev
`

func envsOf(t *testing.T, src string) []model.Env {
	t.Helper()
	return mustParse(t, src).Project().Envs
}

func TestAddEnv(t *testing.T) {
	got := mustApply(t, envsSample, Op{Kind: "add_env", Env: "qa-2"})
	if e := envsOf(t, got); !slices.Equal(e, []model.Env{"dev", "prod", "qa-2"}) {
		t.Fatalf("envs = %v\n%s", e, got)
	}
	if !strings.Contains(got, "# where it runs") {
		t.Errorf("the comment is gone:\n%s", got)
	}
	if again := mustApply(t, got, Op{Kind: "add_env", Env: "qa-2"}); again != got {
		t.Errorf("adding a name twice changed the file:\n%s", again)
	}
	// a file without envs meant the old four: the first edit writes them out and adds the new one
	got = mustApply(t, "name: x\n", Op{Kind: "add_env", Env: "local"})
	if e := envsOf(t, got); !slices.Equal(e, []model.Env{"dev", "int", "staging", "prod", "local"}) {
		t.Fatalf("legacy + local = %v", e)
	}
	// a name the old default already holds changes nothing
	if got := mustApply(t, "name: x\n", Op{Kind: "add_env", Env: "prod"}); strings.Contains(got, "envs") {
		t.Errorf("file gained envs:\n%s", got)
	}
}

func TestRemoveEnv(t *testing.T) {
	got := mustApply(t, envsSample, Op{Kind: "remove_env", Env: "dev"})
	if e := envsOf(t, got); !slices.Equal(e, []model.Env{"prod"}) {
		t.Fatalf("envs = %v", e)
	}
	if strings.Contains(got, "when@dev:") || !strings.Contains(got, "when@prod:") {
		t.Errorf("the differences of the removed environment go with it, the others stay:\n%s", got)
	}
	got = mustApply(t, "name: x\n", Op{Kind: "remove_env", Env: "int"})
	if e := envsOf(t, got); !slices.Equal(e, []model.Env{"dev", "staging", "prod"}) {
		t.Fatalf("legacy minus int = %v", e)
	}
	for name, c := range map[string]struct {
		src string
		op  Op
		msg string
	}{
		"not there":  {envsSample, Op{Kind: "remove_env", Env: "qa"}, "not in envs"},
		"last one":   {"name: x\nenvs: [prod]\n", Op{Kind: "remove_env", Env: "prod"}, "at least one"},
		"bad name":   {envsSample, Op{Kind: "remove_env", Env: "Prod"}, "invalid"},
		"empty name": {envsSample, Op{Kind: "add_env"}, "invalid"},
	} {
		if err := mustParse(t, c.src).Apply(c.op); err == nil || !strings.Contains(err.Error(), c.msg) {
			t.Errorf("%s: err = %v, want %q", name, err, c.msg)
		}
	}
}

func TestRenameEnv(t *testing.T) {
	got := mustApply(t, envsSample, Op{Kind: "rename_env", Env: "prod", To: "production"})
	p := mustParse(t, got).Project()
	if !slices.Equal(p.Envs, []model.Env{"dev", "production"}) {
		t.Fatalf("envs = %v\n%s", p.Envs, got)
	}
	if p.Lockfiles[0].Env != "production" || p.Lockfiles[1].Env != "" {
		t.Errorf("lockfiles = %+v", p.Lockfiles)
	}
	if _, ok := p.Environments["prod"]; ok || p.Environments["production"].Image != "shop:1" || p.Environments["production"].Techs["php"] != "8.3" {
		t.Errorf("environments = %+v", p.Environments)
	}
	if !strings.Contains(got, "when@production:") || !strings.Contains(got, "# where it runs") {
		t.Errorf("layout lost:\n%s", got)
	}
	// without an envs key the old four are renamed and written out
	got = mustApply(t, "name: x\nlockfiles:\n  - {type: npm, path: p, env: staging}\n", Op{Kind: "rename_env", Env: "staging", To: "stage"})
	p = mustParse(t, got).Project()
	if !slices.Equal(p.Envs, []model.Env{"dev", "int", "stage", "prod"}) || p.Lockfiles[0].Env != "stage" {
		t.Errorf("legacy rename = %v %+v", p.Envs, p.Lockfiles)
	}
	// a name only versions or lockfiles use is renamed there
	got = mustApply(t, "name: x\nenvs: [local]\nenvironments:\n  prod: {image: i}\n", Op{Kind: "rename_env", Env: "prod", To: "live"})
	if p = mustParse(t, got).Project(); p.Environments["live"].Image != "i" || !slices.Equal(p.Envs, []model.Env{"local"}) {
		t.Errorf("orphan rename = %v %+v", p.Envs, p.Environments)
	}
	for name, c := range map[string]struct {
		op  Op
		msg string
	}{
		"same name":      {Op{Kind: "rename_env", Env: "dev", To: "dev"}, "same"},
		"unknown":        {Op{Kind: "rename_env", Env: "qa", To: "uat"}, "not used"},
		"target in envs": {Op{Kind: "rename_env", Env: "dev", To: "prod"}, "already in envs"},
		"bad new name":   {Op{Kind: "rename_env", Env: "dev", To: "Dev 2"}, "invalid new env"},
		"no new name":    {Op{Kind: "rename_env", Env: "dev"}, "invalid new env"},
	} {
		if err := mustParse(t, envsSample).Apply(c.op); err == nil || !strings.Contains(err.Error(), c.msg) {
			t.Errorf("%s: err = %v, want %q", name, err, c.msg)
		}
	}
	// the target already has its own versions
	src := "name: x\nenvs: [dev]\nenvironments:\n  dev: {image: a}\n  qa: {image: b}\n"
	if err := mustParse(t, src).Apply(Op{Kind: "rename_env", Env: "dev", To: "qa"}); err == nil || !strings.Contains(err.Error(), "own differences") {
		t.Errorf("err = %v", err)
	}
}

func TestAnyEnvNameWorksInOps(t *testing.T) {
	got := mustApply(t, "name: x\nenvs: [local, qa-2]\n",
		Op{Kind: "set_env_tech", Env: "qa-2", Tech: "php", Version: "8.2"},
		Op{Kind: "set_image", Env: "local", Image: "x:1"},
		Op{Kind: "add_lockfile", Lockfile: model.Lockfile{Type: "npm", Path: "p", Env: "qa-2"}})
	p := mustParse(t, got).Project()
	if p.Environments["qa-2"].Techs["php"] != "8.2" || p.Environments["local"].Image != "x:1" || p.Lockfiles[0].Env != "qa-2" {
		t.Fatalf("project = %+v", p)
	}
	if issues := mustParse(t, got).Validate(nil); len(issues) != 0 {
		t.Errorf("issues = %+v", issues)
	}
}

func TestEnvHints(t *testing.T) {
	legacy := EnvHints(model.Project{Name: "x"})
	if len(legacy) != 1 || legacy[0].Level != "warn" || legacy[0].Field != "envs" ||
		!strings.Contains(legacy[0].Message, "old default dev, int, staging, prod") || len(legacy[0].Fix) != 1 || legacy[0].Fix[0].Kind != "set_envs" {
		t.Errorf("legacy hints = %+v", legacy)
	}
	noProd := EnvHints(model.Project{Envs: []model.Env{"local"}})
	if len(noProd) != 1 || noProd[0].Level != "info" || !strings.Contains(noProd[0].Message, "add prod") ||
		len(noProd[0].Fix) != 1 || noProd[0].Fix[0].Kind != "add_env" || noProd[0].Fix[0].Env != "prod" {
		t.Errorf("no-prod hints = %+v", noProd)
	}
	for _, envs := range [][]model.Env{{"local", "prod"}, {"production"}, {"local", "prod-eu", "prod-us"}} {
		if h := EnvHints(model.Project{Envs: envs}); len(h) != 0 {
			t.Errorf("%v should have no hints: %+v", envs, h)
		}
	}
	// the fix applies
	fixed := mustApply(t, "name: x\nenvs: [local]\n", noProd[0].Fix...)
	if e := envsOf(t, fixed); !slices.Equal(e, []model.Env{"local", "prod"}) {
		t.Errorf("after the fix: %v", e)
	}
}
