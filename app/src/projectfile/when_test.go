package projectfile

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/b070nd/cvewatch/app/src/model"
)

const whenSample = `# the shop
name: shop
envs: [local, dev, prod]
techs:
  - {name: php, version: "8.2"}
  - {name: mysql, version: "8.0"}
  - {name: xdebug}
lockfiles: []
when@prod:
  techs: {php: "8.3"}
  image: shop:1
`

func TestMigrateEnvsRewritesTheOldKeyOnly(t *testing.T) {
	got := mustApply(t, legacyExample, Op{Kind: "migrate_envs"})
	if strings.Contains(got, "environments:") || !strings.Contains(got, "when@prod:") {
		t.Fatalf("not migrated:\n%s", got)
	}
	if !strings.Contains(got, "# what actually runs where") || !strings.Contains(got, "# recorded only") {
		t.Errorf("comments lost:\n%s", got)
	}
	before, after := mustParse(t, legacyExample).Project(), mustParse(t, got).Project()
	if before.Environments[model.EnvProd].Image != after.Environments[model.EnvProd].Image || !reflect.DeepEqual(before.Environments[model.EnvProd].Techs, after.Environments[model.EnvProd].Techs) {
		t.Errorf("meaning changed: %+v -> %+v", before.Environments, after.Environments)
	}
	if after.Environments[model.EnvProd].Old || !before.Environments[model.EnvProd].Old {
		t.Errorf("old flags: before %v, after %v", before.Environments[model.EnvProd].Old, after.Environments[model.EnvProd].Old)
	}
	for _, line := range []string{"name: shop", "  - {name: php, version: \"8.2\"}"} {
		if !strings.Contains(got, line) {
			t.Errorf("untouched line %q changed:\n%s", line, got)
		}
	}
	if again := mustApply(t, got, Op{Kind: "migrate_envs"}); again != got {
		t.Errorf("a second migration changed the file:\n%s", again)
	}
	if same := mustApply(t, whenSample, Op{Kind: "migrate_envs"}); same != whenSample {
		t.Errorf("a file without the old key changed:\n%s", same)
	}
}

func TestMigrateEnvsKeepsEveryEnvironmentInOrder(t *testing.T) {
	src := "name: x\nenvs: [local, dev, prod]\nenvironments:\n  prod: {image: p}\n  # dev runs the latest\n  dev:\n    techs: {php: \"8.4\"}\nlockfiles: []\n"
	got := mustApply(t, src, Op{Kind: "migrate_envs"})
	if strings.Index(got, "when@prod:") > strings.Index(got, "when@dev:") || strings.Index(got, "when@dev:") > strings.Index(got, "lockfiles:") {
		t.Errorf("order or place changed:\n%s", got)
	}
	if !strings.Contains(got, "# dev runs the latest") {
		t.Errorf("comment lost:\n%s", got)
	}
	p := mustParse(t, got).Project()
	if p.Environments["prod"].Image != "p" || p.Environments["dev"].Techs["php"] != "8.4" {
		t.Errorf("%+v", p.Environments)
	}
}

func TestMigrateEnvsRefusesToMergeTwoSpellings(t *testing.T) {
	src := "name: x\nenvironments:\n  prod: {image: a}\nwhen@prod:\n  image: b\n"
	if _, err := Parse([]byte(src)); err == nil || !strings.Contains(err.Error(), "both environments: and when@prod") {
		t.Fatalf("Parse err = %v", err)
	}
	f := mustParse(t, "name: x\nenvironments:\n  prod: {image: a}\n")
	f.doc.Content[0].Content = append(f.doc.Content[0].Content, str("when@prod", 0), str("x", 0))
	if err := f.Apply(Op{Kind: "migrate_envs"}); err == nil || !strings.Contains(err.Error(), "exists already") {
		t.Fatalf("err = %v", err)
	}
}

func TestEditsToDifferencesMigrateTheOldBlock(t *testing.T) {
	for _, op := range []Op{
		{Kind: "set_env_tech", Env: "prod", Tech: "php", Version: "8.4"},
		{Kind: "set_image", Env: "dev", Image: "x:1"},
		{Kind: "exclude_env_tech", Env: "prod", Tech: "magento"},
		{Kind: "rename_env", Env: "prod", To: "live"},
	} {
		got := mustApply(t, legacyExample, op)
		if strings.Contains(got, "environments:") || !strings.Contains(got, "when@") {
			t.Errorf("%s did not migrate:\n%s", op.Kind, got)
		}
	}
	// ops that do not touch the differences leave the old spelling alone
	got := mustApply(t, legacyExample, Op{Kind: "set_tech", Tech: "php", Version: "8.3"}, Op{Kind: "set_since", Since: "2026-01-01"})
	if !strings.Contains(got, "environments:") {
		t.Errorf("unrelated edits migrated:\n%s", got)
	}
	// a failing op leaves the file as it was
	f := mustParse(t, legacyExample)
	if err := f.Apply(Op{Kind: "set_image", Env: "prod", Image: "i"}, Op{Kind: "remove_env_tech", Env: "int", Tech: "php"}); err == nil {
		t.Fatal("expected an error")
	}
	if b, _ := f.Bytes(); string(b) != legacyExample {
		t.Errorf("file changed after a failed apply:\n%s", b)
	}
}

func TestExcludeAndIncludeEnvTech(t *testing.T) {
	got := mustApply(t, whenSample, Op{Kind: "exclude_env_tech", Env: "prod", Tech: "xdebug"})
	if !strings.Contains(got, "  exclude: [xdebug]\n") || strings.Index(got, "exclude:") > strings.Index(got, "image:") || strings.Index(got, "techs: {php") > strings.Index(got, "exclude:") {
		t.Fatalf("exclude not written between techs and image:\n%s", got)
	}
	if ex := mustParse(t, got).Project().Environments["prod"].Exclude; !reflect.DeepEqual(ex, []string{"xdebug"}) {
		t.Errorf("exclude = %v", ex)
	}
	if again := mustApply(t, got, Op{Kind: "exclude_env_tech", Env: "prod", Tech: "XDEBUG"}); again != got {
		t.Errorf("excluding twice changed the file:\n%s", again)
	}
	// a block that did not exist is created
	got2 := mustApply(t, whenSample, Op{Kind: "exclude_env_tech", Env: "local", Tech: "mysql"})
	if !strings.Contains(got2, "when@local:\n  exclude: [mysql]\n") {
		t.Errorf("new block:\n%s", got2)
	}
	// including removes it and prunes the block it created
	back := mustApply(t, got2, Op{Kind: "include_env_tech", Env: "local", Tech: "MySQL"})
	if back != whenSample {
		t.Errorf("include did not undo exclude:\n%s", back)
	}
	for name, c := range map[string]Op{
		"not excluded":  {Kind: "include_env_tech", Env: "prod", Tech: "php"},
		"no block":      {Kind: "include_env_tech", Env: "dev", Tech: "php"},
		"empty tech":    {Kind: "exclude_env_tech", Env: "prod"},
		"bad env":       {Kind: "exclude_env_tech", Env: "Prod", Tech: "php"},
		"empty include": {Kind: "include_env_tech", Env: "prod"},
	} {
		if err := mustParse(t, whenSample).Apply(c); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestSetTechEnvs(t *testing.T) {
	got := mustApply(t, whenSample, Op{Kind: "set_tech_envs", Tech: "XDebug", Envs: []model.Env{"local", "dev", "local"}})
	if !strings.Contains(got, "  - {name: xdebug, envs: [local, dev]}\n") {
		t.Fatalf("got:\n%s", got)
	}
	p := mustParse(t, got).Project()
	if !slices.Equal(p.Techs[2].Envs, []model.Env{"local", "dev"}) || len(p.Techs[0].Envs) != 0 {
		t.Errorf("techs = %+v", p.Techs)
	}
	narrowed := mustApply(t, got, Op{Kind: "set_tech_envs", Tech: "xdebug", Envs: []model.Env{"local"}})
	if !strings.Contains(narrowed, "envs: [local]}") {
		t.Errorf("narrowed:\n%s", narrowed)
	}
	if lifted := mustApply(t, got, Op{Kind: "set_tech_envs", Tech: "xdebug"}); lifted != whenSample {
		t.Errorf("no envs should lift the limit:\n%s", lifted)
	}
	for name, c := range map[string]Op{
		"unknown tech": {Kind: "set_tech_envs", Tech: "nope", Envs: []model.Env{"dev"}},
		"empty tech":   {Kind: "set_tech_envs", Envs: []model.Env{"dev"}},
		"bad env":      {Kind: "set_tech_envs", Tech: "php", Envs: []model.Env{"Dev"}},
	} {
		if err := mustParse(t, whenSample).Apply(c); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestRemoveEnvTakesItsDifferencesAlong(t *testing.T) {
	got := mustApply(t, whenSample, Op{Kind: "remove_env", Env: "prod"})
	if strings.Contains(got, "when@prod") {
		t.Errorf("block stays:\n%s", got)
	}
	if issues := mustParse(t, got).Validate(nil); len(issues) != 0 {
		t.Errorf("the result should be valid: %+v", issues)
	}
	// the old spelling keeps its entry and warns, as before
	old := mustApply(t, legacyExample, Op{Kind: "remove_env", Env: "prod"})
	if !strings.Contains(old, "environments:") {
		t.Errorf("old block removed:\n%s", old)
	}
}

func TestRenameEnvMovesDifferencesAndScopes(t *testing.T) {
	src := whenSample + "when@dev:\n  exclude: [mysql]\n"
	src = strings.Replace(src, "{name: xdebug}", "{name: xdebug, envs: [local, prod]}", 1)
	got := mustApply(t, src, Op{Kind: "rename_env", Env: "prod", To: "live"})
	p := mustParse(t, got).Project()
	if p.Environments["live"].Image != "shop:1" || len(p.Environments["prod"].Techs) != 0 || !slices.Equal(p.Techs[2].Envs, []model.Env{"local", "live"}) ||
		!slices.Equal(p.Envs, []model.Env{"local", "dev", "live"}) {
		t.Errorf("project = %+v\n%s", p, got)
	}
	if issues := mustParse(t, got).Validate(nil); len(issues) != 0 {
		t.Errorf("issues = %+v", issues)
	}
	if err := mustParse(t, src).Apply(Op{Kind: "rename_env", Env: "prod", To: "dev"}); err == nil {
		t.Error("renaming onto an environment that exists should fail")
	}
}

func TestProjectIsTheSameInEitherSpelling(t *testing.T) {
	a := mustParse(t, legacyExample).Project()
	b := mustParse(t, mustApply(t, legacyExample, Op{Kind: "migrate_envs"})).Project()
	for _, env := range model.LegacyEnvs {
		if !reflect.DeepEqual(a.TechsIn(env), b.TechsIn(env)) {
			t.Errorf("%s: %+v vs %+v", env, a.TechsIn(env), b.TechsIn(env))
		}
	}
}

func TestValidateDifferences(t *testing.T) {
	src := `name: shop
envs: [local, prod]
techs:
  - {name: php, version: "8.2"}
  - {name: xdebug, envs: [local, qa, Bad]}
when@prod:
  techs: {php: "8.3", mysql: "8"}
  exclude: [php, redis]
when@staging:
  techs: {php: "8.1"}
  image: s:1
`
	issues := mustParse(t, src).Validate(nil)
	got := map[string]Issue{}
	for _, i := range issues {
		got[i.Level+" "+i.Field] = i
	}
	for _, want := range []string{
		"error techs[1].envs",   // Bad
		"warning techs[1].envs", // qa is not an environment of the project
		"error when@staging",    // block of an environment the project does not have
		"warning when@prod.exclude",
	} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing %q in %v", want, issues)
		}
	}
	staging := got["error when@staging"]
	if len(staging.Fixes) != 2 || staging.Fixes[0].Ops[0].Kind != "set_envs" {
		t.Fatalf("fixes of the stale block: %+v", staging.Fixes)
	}
	if staging.Line == 0 {
		t.Errorf("the issue should be located: %+v", staging)
	}
	// both fixes make the problem go away
	for _, fix := range staging.Fixes {
		after := mustApply(t, src, fix.Ops...)
		for _, i := range mustParse(t, after).Validate(nil) {
			if i.Field == "when@staging" {
				t.Errorf("fix %q leaves %+v:\n%s", fix.Label, i, after)
			}
		}
	}
	// the exclusion of a tech with a version in the same block is explained, and redis is not declared
	var msgs []string
	for _, i := range issues {
		if i.Field == "when@prod.exclude" {
			msgs = append(msgs, i.Message)
		}
	}
	if len(msgs) != 2 || !strings.Contains(strings.Join(msgs, "|"), "also has a version") || !strings.Contains(strings.Join(msgs, "|"), "does not declare it") {
		t.Errorf("messages = %q", msgs)
	}
	// the old spelling keeps its warning for an environment that is not monitored
	old := mustParse(t, "name: x\nenvs: [dev]\nenvironments:\n  prod: {image: i}\n").Validate(nil)
	if len(old) != 1 || old[0].Level != "warning" || old[0].Field != "environments.prod" {
		t.Errorf("old = %+v", old)
	}
}

func TestEnvHintsOfTheOldSpelling(t *testing.T) {
	hs := EnvHints(mustParse(t, legacyExample).Project())
	var h EnvHint
	for _, c := range hs {
		if c.Field == "environments" {
			h = c
		}
	}
	if h.Level != "info" || !strings.Contains(h.Message, "old spelling of the when@<env> blocks") || len(h.Fix) != 1 || h.Fix[0].Kind != "migrate_envs" {
		t.Fatalf("hints = %+v", hs)
	}
	fixed := mustParse(t, mustApply(t, legacyExample, h.Fix...)).Project()
	for _, c := range EnvHints(fixed) {
		if c.Field == "environments" {
			t.Errorf("the hint stays after its fix: %+v", c)
		}
	}
	for _, c := range EnvHints(mustParse(t, whenSample).Project()) {
		if c.Field == "environments" {
			t.Errorf("the new spelling should not be hinted: %+v", c)
		}
	}
	// the project hints carry it, with the field name of the file's own spelling
	all := hintsOf(t, legacyExample, HintOptions{})
	if _, ok := hintAt(all, "environments", "old spelling"); !ok {
		t.Errorf("Hints lack it: %+v", all)
	}
	unknown := hintsOf(t, "name: x\nenvs: [prod]\nsince: 2026-01-01\nwhen@prod:\n  techs: {algolia: \"1\"}\n", HintOptions{})
	if _, ok := hintAt(unknown, "when@prod.techs.algolia", "not in the catalog"); !ok {
		t.Errorf("unknown tech in a when block: %+v", unknown)
	}
}

func TestMisspelledTechInAWhenBlockGetsAFixThatApplies(t *testing.T) {
	src := "name: x\nenvs: [prod]\nsince: 2026-01-01\ntechs:\n  - {name: php, version: \"8\"}\nwhen@prod:\n  techs: {myssql: \"8.0\"}\n"
	issues := mustParse(t, src).ValidateCatalog(hintCatalog)
	var fix *Fix
	for _, i := range issues {
		if i.Field == "when@prod.techs.myssql" && len(i.Fixes) > 0 {
			fix = &i.Fixes[0]
		}
	}
	if fix == nil {
		t.Fatalf("no fix in %+v", issues)
	}
	after := mustParse(t, mustApply(t, src, fix.Ops...)).Project()
	if after.Environments["prod"].Techs["mysql"] != "8.0" || len(after.Environments["prod"].Techs) != 1 {
		t.Errorf("after the fix: %+v", after.Environments)
	}
}
