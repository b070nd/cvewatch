package projectfile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/b070nd/cvewatch/app/src/catalog"
	"github.com/b070nd/cvewatch/app/src/model"
)

var testCatalog = catalog.New([]model.Tech{{Name: "php"}, {Name: "mysql", Aliases: []string{"mariadb"}}, {Name: "ruby"}})

func validateCatalog(f *File) []Issue { return f.ValidateCatalog(testCatalog) }

// issueWith finds the issue whose field and message start as given.
func issueWith(issues []Issue, field, msg string) (Issue, bool) {
	for _, i := range issues {
		if i.Field == field && strings.Contains(i.Message, msg) {
			return i, true
		}
	}
	return Issue{}, false
}

// checkFixes applies every fix of the issue to a fresh copy of src and expects
// the issue to be gone afterwards.
func checkFixes(t *testing.T, src string, check func(*File) []Issue, field, msg string, labels ...string) *File {
	t.Helper()
	issue, ok := issueWith(check(mustParse(t, src)), field, msg)
	if !ok {
		t.Fatalf("no issue %s %q", field, msg)
	}
	var got []string
	for _, fix := range issue.Fixes {
		got = append(got, fix.Label)
	}
	if strings.Join(got, "|") != strings.Join(labels, "|") {
		t.Fatalf("%s: fix labels = %q, want %q", field, got, labels)
	}
	var last *File
	for _, fix := range issue.Fixes {
		f := mustParse(t, src)
		if err := f.Apply(fix.Ops...); err != nil {
			t.Fatalf("%s: applying %q: %v", field, fix.Label, err)
		}
		for _, after := range check(f) {
			if after.Message == issue.Message {
				t.Errorf("%s: %q left the issue in place: %+v", field, fix.Label, after)
			}
		}
		last = f
	}
	return last
}

func TestSuggest(t *testing.T) {
	known := []string{"php", "mysql", "postgresql", "node", "nodejs", "ruby"}
	for _, c := range []struct {
		in, want string
		ok       bool
	}{
		{"pph", "php", true},
		{"MySQ", "mysql", true},
		{"postgresq", "postgresql", true},
		{"postgress", "postgresql", true},
		{"rubby", "ruby", true},
		{"php", "", false}, // already known
		{"PHP", "", false}, // same ignoring case
		{"nod", "node", true},
		{"java", "", false}, // nothing near
		{"xx", "", false},   // short names allow one error only
		{"phpmyadmin", "", false},
		{"", "", false},
	} {
		got, ok := Suggest(c.in, known)
		if got != c.want || ok != c.ok {
			t.Errorf("Suggest(%q) = %q, %v; want %q, %v", c.in, got, ok, c.want, c.ok)
		}
	}
	if got, ok := Suggest("nodx", []string{"nodea", "nodeb"}); ok {
		t.Errorf("two equally close names must not suggest %q", got)
	}
}

func TestValidateCatalogAndPlainValidateAgree(t *testing.T) {
	src := "name: x\ntechs: [{name: pph}, {name: php}]\nlockfiles: [{type: composer, path: composer.lock}]\n"
	plain := mustParse(t, src).Validate(testCatalog.Has)
	rich := validateCatalog(mustParse(t, src))
	if len(plain) != len(rich) {
		t.Fatalf("plain %+v, catalog %+v", plain, rich)
	}
	for i := range plain {
		if plain[i].Level != rich[i].Level || plain[i].Field != rich[i].Field || plain[i].Message != rich[i].Message || len(plain[i].Fixes) != 0 {
			t.Errorf("issue %d differs: %+v vs %+v", i, plain[i], rich[i])
		}
	}
}

func TestFixUnknownTechnology(t *testing.T) {
	f := checkFixes(t, "name: x\ntechs:\n  - {name: pph, version: \"8.2\"}\n", validateCatalog,
		"techs[0]", `"pph" is not in the catalog`, `use technology name "php" instead of "pph"`)
	if p := f.Project(); len(p.Techs) != 1 || p.Techs[0].Name != "php" || p.Techs[0].Version != "8.2" {
		t.Errorf("renamed project = %+v", p.Techs)
	}

	checkFixes(t, "name: x\ntechs: [{name: mariadb, version: \"10.11\"}]\n", validateCatalog,
		"techs[0]", `"mariadb"`, `use technology name "mysql" instead of "mariadb"`)

	f = checkFixes(t, "name: x\ntechs: [{name: php, version: \"8.2\"}, {name: pph, version: \"7.4\"}]\n", validateCatalog,
		"techs[1]", `"pph"`, `remove technology "pph", "php" is already listed`)
	if p := f.Project(); len(p.Techs) != 1 || p.Techs[0].Version != "8.2" {
		t.Errorf("duplicate kept: %+v", p.Techs)
	}

	f = checkFixes(t, "name: x\nenvironments:\n  prod:\n    techs: {pph: \"8.2.30\"}\n", validateCatalog,
		"environments.prod.techs.pph", `"pph"`, `use technology name "php" instead of "pph" in prod`)
	if got := f.Project().Environments[model.EnvProd].Techs; len(got) != 1 || got["php"] != "8.2.30" {
		t.Errorf("renamed env tech = %v", got)
	}

	checkFixes(t, "name: x\nenvironments:\n  prod:\n    techs: {php: \"8.2.30\", pph: \"7\"}\n", validateCatalog,
		"environments.prod.techs.pph", `"pph"`, `remove technology "pph" from prod, "php" is already set there`)

	for _, src := range []string{
		"name: x\ntechs: [{name: weird}]\n",
		"name: x\nenvironments:\n  prod:\n    techs: {pph: \"\"}\n", // no version to carry over
	} {
		for _, i := range validateCatalog(mustParse(t, src)) {
			if len(i.Fixes) != 0 {
				t.Errorf("unexpected fix for %+v", i)
			}
		}
	}
}

func TestFixLockfileType(t *testing.T) {
	f := checkFixes(t, "name: x\nlockfiles:\n  - {type: nope, path: sub/composer.lock, env: prod, dev: true}\n", validateCatalog,
		"lockfiles[0].type", "unknown lockfile type", `use lockfile type "composer" for sub/composer.lock instead of "nope"`)
	if l := f.Project().Lockfiles; len(l) != 1 || l[0] != (model.Lockfile{Type: "composer", Path: "sub/composer.lock", Env: model.EnvProd, Dev: true}) {
		t.Errorf("retyped lockfile = %+v", l)
	}

	for _, src := range []string{
		"name: x\nlockfiles: [{type: nope, path: whatever.txt}]\n",
		"name: x\nlockfiles: [{type: nope, path: composer.lock}, {type: composer, path: composer.lock, env: dev}]\n",
	} {
		i, ok := issueWith(validateCatalog(mustParse(t, src)), "lockfiles[0].type", "unknown")
		if !ok || len(i.Fixes) != 0 {
			t.Errorf("want an issue without fixes: %+v", i)
		}
	}
}

func TestFixEnvironments(t *testing.T) {
	f := checkFixes(t, "name: x\nenvs: [dev]\nlockfiles: [{type: composer, path: composer.lock, env: prod}]\n", validateCatalog,
		"lockfiles[0].env", "not in envs", "monitor environment prod", "remove lockfile composer.lock for prod")
	if len(f.Project().Lockfiles) != 0 {
		t.Errorf("lockfile kept: %+v", f.Project().Lockfiles)
	}

	f = checkFixes(t, "name: x\nenvs: [dev]\nenvironments:\n  prod: {image: i}\n", validateCatalog,
		"environments.prod", "not in envs", "monitor environment prod")
	if got := f.Project().Envs; len(got) != 2 || got[0] != model.EnvDev || got[1] != model.EnvProd {
		t.Errorf("envs = %v", got)
	}

	checkFixes(t, "name: x\nlockfiles: [{type: composer, path: composer.lock, env: qa}]\n", validateCatalog,
		"lockfiles[0].env", "invalid environment", "remove lockfile composer.lock")
	i, _ := issueWith(validateCatalog(mustParse(t, "name: x\nlockfiles: [{type: npm, path: a, env: qa}, {type: npm, path: a, env: dev}]\n")), "lockfiles[0].env", "invalid")
	if len(i.Fixes) != 0 {
		t.Errorf("a shared path must not be removed blindly: %+v", i.Fixes)
	}
}

func TestCheckFiles(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "app"), 0o755)
	for _, n := range []string{"app/composer.lock", "package-lock.json"} {
		os.WriteFile(filepath.Join(root, n), []byte("{}"), 0o644)
	}
	abs := filepath.Join(root, "package-lock.json")
	check := func(f *File) []Issue { return CheckFiles(f.Project(), root) }

	clean := "name: x\nlockfiles:\n  - {type: composer, path: app/composer.lock}\n  - {type: npm, path: " + abs + "}\n"
	if got := check(mustParse(t, clean)); len(got) != 0 {
		t.Fatalf("clean project: %+v", got)
	}

	f := checkFixes(t, "name: x\nlockfiles:\n  - {type: composer, path: app/composer.lock}\n  - {type: composer, path: app/gone.lock, env: prod}\n", check,
		"lockfiles[1].path", "does not exist", "remove lockfile app/gone.lock for prod")
	if l := f.Project().Lockfiles; len(l) != 1 || l[0].Path != "app/composer.lock" {
		t.Errorf("after fix: %+v", l)
	}
	if got := check(f); len(got) != 0 {
		t.Errorf("still issues: %+v", got)
	}

	checkFixes(t, "name: x\nlockfiles:\n  - {type: composer, path: "+filepath.Join(root, "missing.lock")+"}\n", check,
		"lockfiles[0].path", "does not exist", "remove lockfile "+filepath.Join(root, "missing.lock"))

	src := "name: x\nlockfiles:\n  - {type: composer, path: package-lock.json}\n"
	i, ok := issueWith(check(mustParse(t, src)), "lockfiles[0].type", "looks like")
	if !ok || i.Level != "warning" {
		t.Fatalf("wrong type not reported: %+v", check(mustParse(t, src)))
	}
	f = checkFixes(t, src, check, "lockfiles[0].type", "looks like", `use lockfile type "npm" for package-lock.json instead of "composer"`)
	if got := check(f); len(got) != 0 {
		t.Errorf("still issues: %+v", got)
	}

	// an unknown type is Validate's business; a file name nobody knows is not a mismatch
	for _, src := range []string{
		"name: x\nlockfiles: [{type: nope, path: package-lock.json}]\n",
		"name: x\nlockfiles: [{type: spdx, path: app/composer.lock.txt}]\n",
	} {
		for _, i := range check(mustParse(t, src)) {
			if strings.Contains(i.Message, "looks like") {
				t.Errorf("unexpected %+v", i)
			}
		}
	}
}
