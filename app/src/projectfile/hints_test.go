package projectfile

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/b070nd/cvewatch/app/src/catalog"
	"github.com/b070nd/cvewatch/app/src/model"
)

var hintCatalog = catalog.New([]model.Tech{
	{Name: "php", Category: "language", CPE: []string{"php:php"}},
	{Name: "mysql", Aliases: []string{"mariadb"}, Category: "database"},
	{Name: "rabbitmq", Category: "messaging"},
	{Name: "cisco-ios"}, {Name: "cisco-ios-xe"},
	{Name: "mine", Category: "other"},
})

func hintsOf(t *testing.T, src string, o HintOptions) []Hint {
	t.Helper()
	if o.Catalog == nil {
		o.Catalog = hintCatalog
	}
	return mustParse(t, src).Hints(o)
}

func hintAt(hs []Hint, field, msg string) (Hint, bool) {
	for _, h := range hs {
		if h.Field == field && strings.Contains(h.Message, msg) {
			return h, true
		}
	}
	return Hint{}, false
}

func TestHintsForTheUsersOwnTerms(t *testing.T) {
	src := "name: shop\nenvs: [local, prod]\nsince: 2026-01-01\ntechs:\n  - {name: rabbitMW, version: \"3\"}\n  - {name: algolia, version: \"1\"}\n  - {name: myssql, version: \"8\"}\n"
	hs := hintsOf(t, src, HintOptions{})

	rabbit, ok := hintAt(hs, "techs[0]", "not in the catalog")
	if !ok || len(rabbit.Suggest) == 0 || rabbit.Suggest[0] != "rabbitmq" || rabbit.Keyword != "rabbitMW" || rabbit.Level != "warn" {
		t.Fatalf("rabbitMW: %+v", rabbit)
	}
	algolia, ok := hintAt(hs, "techs[1]", "not in the catalog")
	if !ok || len(algolia.Suggest) != 0 || algolia.Keyword != "algolia" || !strings.Contains(algolia.Message, "own keyword") {
		t.Fatalf("algolia: %+v", algolia)
	}
	if _, ok := hintAt(hs, "techs[1]", "Did you mean"); ok {
		t.Fatal("no suggestion for a term nothing resembles")
	}
	if h, ok := hintAt(hs, "techs[2]", "mysql"); !ok || h.Suggest[0] != "mysql" {
		t.Fatalf("myssql: %+v", h)
	}
}

func TestHintsReuseTheIssuesFixes(t *testing.T) {
	src := "name: shop\nenvs: [local]\nsince: 2026-01-01\ntechs:\n  - {name: mariadb, version: \"10\"}\n"
	h, ok := hintAt(hintsOf(t, src, HintOptions{}), "techs[0]", "not in the catalog")
	if !ok || len(h.Fix) != 2 || h.Fix[0].Kind != "remove_tech" || h.Fix[1].Tech != "mysql" {
		t.Fatalf("the rename fix of ValidateCatalog must carry over: %+v", h)
	}
}

func TestHintsCoverageChecklist(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	src := "name: shop\ntechs:\n  - {name: php}\n  - {name: cisco-ios, version: \"15\"}\n  - {name: mine, version: \"1\"}\nlockfiles:\n  - {type: composer, path: " + filepath.ToSlash(filepath.Join(outside, "composer.lock")) + "}\n  - {type: yarn-classic, path: gone.lock}\n"
	hs := hintsOf(t, src, HintOptions{Root: dir, Dir: dir, Own: []string{"mine"}})
	for _, w := range []struct{ field, msg, level string }{
		{"techs[0].version", "no version", "warn"},
		{"techs[1]", "cisco-ios-xe", "info"},
		{"techs[2]", "your own keyword", "info"},
		{"lockfiles[0].path", "outside the repository folder", "info"},
		{"lockfiles[1].path", "does not exist", "warn"},
		{"lockfiles[1].type", "unknown lockfile type", "warn"},
		{"envs", "envs not set", "warn"},
		{"since", "no start date", "info"},
	} {
		h, ok := hintAt(hs, w.field, w.msg)
		if !ok || h.Level != w.level {
			t.Errorf("missing %s %q (%s) in %+v", w.field, w.msg, w.level, hs)
		}
	}
	seen := false
	for _, h := range hs {
		if h.Level == "info" {
			seen = true
		} else if seen {
			t.Fatalf("warnings come first: %+v", hs)
		}
	}
}

func TestHintsNoLockfileForALanguage(t *testing.T) {
	hs := hintsOf(t, "name: a\nenvs: [local, prod]\nsince: 2026-01-01\ntechs:\n  - {name: php, version: \"8.2\"}\n", HintOptions{})
	if h, ok := hintAt(hs, "lockfiles", "no lockfile"); !ok || h.Level != "info" {
		t.Fatalf("%+v", hs)
	}
	hs = hintsOf(t, "name: a\nenvs: [local, prod]\nsince: 2026-01-01\ntechs:\n  - {name: mysql, version: \"8\"}\n", HintOptions{})
	if len(hs) != 0 {
		t.Fatalf("a database alone needs no lockfile and everything else is set: %+v", hs)
	}
}

func TestHintsNothingMatchable(t *testing.T) {
	hs := hintsOf(t, "name: a\nenvs: [local]\nsince: 2026-01-01\n", HintOptions{})
	if h, ok := hintAt(hs, "techs", "nothing can match"); !ok || h.Level != "warn" {
		t.Fatalf("%+v", hs)
	}
	hs = hintsOf(t, "name: a\nenvs: [local]\nsince: 2026-01-01\ntechs:\n  - {name: nonesuch}\n", HintOptions{})
	if _, ok := hintAt(hs, "techs", "nothing can match"); !ok {
		t.Fatalf("only unknown technologies: %+v", hs)
	}
}

func TestHintsAboutEnvironments(t *testing.T) {
	hs := hintsOf(t, "name: a\nenvs: [local]\nsince: 2026-01-01\ntechs:\n  - {name: mysql, version: \"8\"}\n", HintOptions{})
	if h, ok := hintAt(hs, "envs", "no prod"); !ok || h.Level != "info" || len(h.Fix) != 1 || h.Fix[0].Kind != "add_env" {
		t.Fatalf("%+v", hs)
	}
	hs = hintsOf(t, "name: a\nenvs: [local, production]\nsince: 2026-01-01\ntechs:\n  - {name: mysql, version: \"8\"}\n", HintOptions{})
	if len(hs) != 0 {
		t.Fatalf("production counts as prod: %+v", hs)
	}
}
