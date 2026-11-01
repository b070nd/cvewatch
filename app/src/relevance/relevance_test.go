package relevance

import (
	"math/rand"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/b070nd/cvewatch/app/src/model"
)

// declaring gives a judge one target that runs every technology it knows, so
// tests about matching are not filtered by "who runs it".
func declaring(j *Judge) []Target {
	var techs []model.ProjectTech
	for _, n := range j.Names() {
		techs = append(techs, model.ProjectTech{Name: n})
	}
	return []Target{{Project: "p", Env: model.EnvProd, Techs: techs}}
}

func techsOf(j *Judge, it model.Item) []string { return j.Judge(it, declaring(j)).Techs }

func TestWholeWordOnly(t *testing.T) {
	j := New([]model.Tech{
		{Name: "php"},
		{Name: "nodejs", Aliases: []string{"nodejs", "node.js"}},
		{Name: "go", Aliases: []string{"golang"}},
	})
	cases := map[string][]string{
		"Critical RCE in PHP-FPM":        {"php"},
		"phpunit bug":                    nil,
		"Node.js HTTP smuggling":         {"nodejs"},
		"Google fixes Chrome bug":        nil,
		"golang net/http panic":          {"go"},
		"PHP and Node.js both affected.": {"php", "nodejs"},
	}
	for title, want := range cases {
		if got := techsOf(j, model.Item{Title: title}); !slices.Equal(got, want) {
			t.Errorf("%q: got %v want %v", title, got, want)
		}
	}
}

func TestExcludesAndTitleOnlyExplainThemselves(t *testing.T) {
	j := New([]model.Tech{{Name: "php", Excludes: []string{"wordpress", "plugin for"}}})
	v := j.Judge(model.Item{Title: "Gallery plugin for WordPress, PHP code injection"}, declaring(j))
	if v.Relevant() || len(v.Notes) != 1 || !strings.Contains(v.Notes[0], "excluded") {
		t.Fatalf("exclude must block and say why: %+v", v)
	}
	it := model.Item{Title: "Flaw in Acme CRM", Summary: "Acme CRM is written in PHP.", TitleOnly: true}
	if got := techsOf(j, it); got != nil {
		t.Fatalf("summary mention matched: %v", got)
	}
	it.TitleOnly = false
	if got := techsOf(j, it); len(got) != 1 {
		t.Fatalf("full text should match: %v", got)
	}
}

func nvdItem(cpe string, ranges ...model.Range) model.Item {
	return model.Item{
		Title:    "CVE-2026-1: flaw in a CMS written in PHP",
		Affected: []model.Affected{{Ecosystem: "cpe", Name: cpe, Ranges: ranges}},
	}
}

func TestCPEDataBeatsTextMentions(t *testing.T) {
	j := New([]model.Tech{{Name: "php", CPE: []string{"php:php"}}})
	projects := []model.Project{{Name: "shop", Techs: []model.ProjectTech{{Name: "php", Version: "8.2.10"}}}}

	// The text says PHP but the product data names Moodle: not about PHP.
	if v := j.Judge(nvdItem("moodle:moodle"), targetsOf(projects, nil)); v.Relevant() || len(v.Notes) == 0 {
		t.Fatalf("other product must not match: %+v", v)
	}
	// A package advisory (GHSA style) naming a PHP library says "PHP" in passing too.
	pkg := model.Item{Title: "Symfony flaw in a PHP framework", Affected: []model.Affected{{Ecosystem: "composer", Name: "symfony/http-kernel"}}}
	if v := j.Judge(pkg, targetsOf(projects, nil)); v.Relevant() {
		t.Fatalf("package data must outrank the word PHP: %+v", v)
	}
	// Real PHP advisory, installed version inside and outside the range.
	rng := model.Range{Max: "8.2.30", MaxExcl: true}
	v := j.Judge(nvdItem("php:php", rng), targetsOf(projects, nil))
	if len(v.Matches) != 1 || v.Matches[0].Applies != model.AppAffected {
		t.Fatalf("8.2.10 < 8.2.30 must be affected: %+v", v.Matches)
	}
	projects[0].Techs[0].Version = "8.3.1"
	v = j.Judge(nvdItem("php:php", rng), targetsOf(projects, nil))
	if len(v.Matches) != 1 || v.Matches[0].Applies != model.AppNotAffected {
		t.Fatalf("8.3.1 must be outside: %+v", v.Matches)
	}
	// A tech declared by series only cannot be decided against a patch-level bound.
	projects[0].Techs[0].Version = "8.2"
	if v = j.Judge(nvdItem("php:php", rng), targetsOf(projects, nil)); v.Matches[0].Applies != model.AppUnknown {
		t.Fatalf("series vs patch bound must be unknown: %+v", v.Matches)
	}
}

func TestStructuredOnlyWaitsForProductData(t *testing.T) {
	j := New([]model.Tech{{Name: "php", CPE: []string{"php:php"}}, {Name: "nginx"}})
	fresh := model.Item{Title: "CVE-2026-1: flaw in a CMS written in PHP and served by nginx", StructuredOnly: true}
	v := j.Judge(fresh, declaring(j))
	if len(v.Techs) != 1 || v.Techs[0] != "nginx" || len(v.Notes) != 1 {
		t.Fatalf("php (has cpe) must wait, nginx (no cpe) still matches by text: %+v", v)
	}
	fresh.StructuredOnly = false
	if got := techsOf(j, fresh); len(got) != 2 {
		t.Fatalf("without the option text decides: %v", got)
	}
}

func TestPackagesStructuredAndScopedText(t *testing.T) {
	j := New(nil)
	projects := []model.Project{{Name: "shop"}}
	pkgs := map[string][]model.Package{"shop": {
		{Name: "symfony/http-kernel", Version: "6.4.1", Ecosystem: "composer"},
		{Name: "lodash", Version: "4.17.20", Ecosystem: "npm"},
		{Name: "express", Version: "4.18.0", Ecosystem: "npm"},
	}}

	ghsa := model.Item{Title: "Prototype pollution in lodash", Affected: []model.Affected{
		{Ecosystem: "npm", Name: "lodash", Ranges: []model.Range{{Max: "4.17.21", MaxExcl: true}}},
	}}
	v := j.Judge(ghsa, targetsOf(projects, pkgs))
	if len(v.Matches) != 1 || v.Matches[0].Applies != model.AppAffected || v.Matches[0].Installed[0].Label() != "lodash@4.17.20" {
		t.Fatalf("structured package: %+v", v.Matches)
	}
	// A different ecosystem with the same name is not our package.
	ghsa.Affected[0].Ecosystem = "pip"
	if v := j.Judge(ghsa, targetsOf(projects, pkgs)); len(v.Matches) != 0 {
		t.Fatalf("ecosystem must match: %+v", v.Matches)
	}
	// Free text names only scoped packages, and never when the feed is structured.
	text := model.Item{Title: "symfony/http-kernel header injection; express mentioned"}
	v = j.Judge(text, targetsOf(projects, pkgs))
	if len(v.Matches) != 1 || v.Matches[0].Applies != model.AppUnknown || len(v.Matches[0].Installed) != 1 {
		t.Fatalf("scoped text match: %+v", v.Matches)
	}
}

func TestReassessUsesLateRanges(t *testing.T) {
	j := New([]model.Tech{{Name: "php", CPE: []string{"php:php"}}})
	in := []model.Installed{{Name: "php", Version: "8.2.10", Via: "tech"}, {Name: "lodash", Version: "4.17.21", Ecosystem: "npm", Via: "package"}}
	got, reasons := j.Reassess(in, []model.Affected{
		{Ecosystem: "cpe", Name: "php:php", Ranges: []model.Range{{Max: "8.2.30", MaxExcl: true}}},
		{Ecosystem: "npm", Name: "lodash", Ranges: []model.Range{{Max: "4.17.21", MaxExcl: true}}},
	})
	if got != model.AppAffected || len(reasons) != 2 {
		t.Fatalf("worst of the two must win: %v %v", got, reasons)
	}
	if got, _ := j.Reassess(in, nil); got != model.AppUnknown {
		t.Fatalf("no data must stay unknown, got %v", got)
	}
}

// targetsOf builds one production target per project for tests that do not care about environments.
func targetsOf(projects []model.Project, pkgs map[string][]model.Package) []Target {
	var out []Target
	for _, p := range projects {
		out = append(out, Target{Project: p.Name, Env: model.EnvProd, Techs: p.Techs, Packages: pkgs[p.Name]})
	}
	return out
}

func TestPerEnvironmentVersionsGiveDifferentVerdicts(t *testing.T) {
	j := New([]model.Tech{{Name: "php", CPE: []string{"php:php"}}})
	rng := model.Range{Max: "8.2.30", MaxExcl: true}
	targets := []Target{
		{Project: "shop", Env: model.EnvDev, Techs: []model.ProjectTech{{Name: "php", Version: "8.3.1"}}},
		{Project: "shop", Env: model.EnvProd, Techs: []model.ProjectTech{{Name: "php", Version: "8.2.10"}}},
	}
	v := j.Judge(nvdItem("php:php", rng), targets)
	if len(v.Matches) != 2 || v.Matches[0].Env != model.EnvDev || v.Matches[0].Applies != model.AppNotAffected ||
		v.Matches[1].Env != model.EnvProd || v.Matches[1].Applies != model.AppAffected {
		t.Fatalf("dev runs 8.3.1 (outside), prod runs 8.2.10 (inside): %+v", v.Matches)
	}
}

func TestPackageNamesMatchAcrossSpellings(t *testing.T) {
	j := New(nil)
	targets := []Target{{Project: "api", Env: model.EnvProd, Packages: []model.Package{
		{Name: "django-rest-framework", Version: "3.14.0", Ecosystem: "pypi"},
		{Name: "org.apache.logging.log4j:log4j-core", Version: "2.14.1", Ecosystem: "maven"},
	}}}
	it := model.Item{Title: "flaws", Affected: []model.Affected{
		{Ecosystem: "pip", Name: "Django_REST.framework", Ranges: []model.Range{{Max: "3.15.0", MaxExcl: true}}},
		{Ecosystem: "maven", Name: "org.apache.logging.log4j:log4j-core", Ranges: []model.Range{{Max: "2.17.1", MaxExcl: true}}},
	}}
	v := j.Judge(it, targets)
	if len(v.Matches) != 1 || len(v.Matches[0].Installed) != 2 || v.Matches[0].Applies != model.AppAffected {
		t.Fatalf("pip == pypi and PEP 503 names must match, maven group:artifact too: %+v", v.Matches)
	}
}

func TestTargetFindFollowsInventoryChanges(t *testing.T) {
	tg := Target{Techs: []model.ProjectTech{{Name: "php", Version: "8.2.30"}},
		Packages: []model.Package{{Name: "lodash", Version: "4.17.21", Ecosystem: "npm"}, {Name: "lodash", Version: "3.0.0", Ecosystem: "npm"}}}
	if got, ok := tg.Find(model.Installed{Name: "PHP", Via: "tech", Version: "8.2.10"}); !ok || got.Version != "8.2.30" {
		t.Fatalf("tech upgrade: %+v %v", got, ok)
	}
	if got, ok := tg.Find(model.Installed{Name: "lodash", Ecosystem: "npm", Via: "package", Version: "3.0.0"}); !ok || got.Version != "3.0.0" {
		t.Fatalf("same version wins among several: %+v", got)
	}
	if _, ok := tg.Find(model.Installed{Name: "gone", Ecosystem: "npm", Via: "package"}); ok {
		t.Fatal("removed packages are not found")
	}
}

func TestOnlyDeclaredTechnologiesAreJudged(t *testing.T) {
	j := New([]model.Tech{{Name: "php"}, {Name: "redis"}})
	it := model.Item{Title: "PHP and Redis flaws"}
	run := []Target{{Project: "shop", Env: model.EnvProd, Techs: []model.ProjectTech{{Name: "redis", Version: "7.2"}}}}
	if v := j.Judge(it, run); len(v.Techs) != 1 || v.Techs[0] != "redis" {
		t.Fatalf("php is in the catalog but nobody runs it: %+v", v.Techs)
	}
	if v := j.Judge(it, nil); v.Relevant() {
		t.Fatal("with nothing declared nothing can be relevant")
	}
}

func TestTechSchemeOrdersItsVersions(t *testing.T) {
	j := New([]model.Tech{{Name: "pyapp", Scheme: "pypi", CPE: []string{"acme:pyapp"}}})
	it := nvdItem("acme:pyapp", model.Range{Max: "1.0", MaxExcl: true})
	tg := []Target{{Project: "p", Env: model.EnvProd, Techs: []model.ProjectTech{{Name: "pyapp", Version: "1.0.post1"}}}}
	// PEP 440: 1.0.post1 is after 1.0, so it is outside "< 1.0"; the default scheme would call it a pre-release.
	if v := j.Judge(it, tg); len(v.Matches) != 1 || v.Matches[0].Applies != model.AppNotAffected || v.Matches[0].Installed[0].Ecosystem != "pypi" {
		t.Fatalf("scheme must be used for tech versions: %+v", v.Matches)
	}
}

func TestProjectSinceDecidesByPublicationDate(t *testing.T) {
	j := New([]model.Tech{{Name: "php"}})
	since := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	techs := []model.ProjectTech{{Name: "php", Version: "8.2"}}
	targets := []Target{
		{Project: "shop", Env: model.EnvDev, Techs: techs, Since: since},
		{Project: "shop", Env: model.EnvProd, Techs: techs, Since: since},
		{Project: "other", Env: model.EnvProd, Techs: techs},
	}
	cases := map[string]struct {
		published time.Time
		matched   []string
		notes     int
	}{
		"the day before":  {since.AddDate(0, 0, -1), []string{"other"}, 1},
		"the start day":   {since, []string{"shop", "shop", "other"}, 0},
		"after the start": {since.AddDate(0, 1, 0), []string{"shop", "shop", "other"}, 0},
		"no date":         {time.Time{}, []string{"shop", "shop", "other"}, 0},
	}
	for name, c := range cases {
		v := j.Judge(model.Item{Title: "PHP flaw", Published: c.published}, targets)
		var got []string
		for _, m := range v.Matches {
			got = append(got, m.Project)
		}
		if !slices.Equal(got, c.matched) || len(v.Notes) != c.notes {
			t.Errorf("%s: matched %v, notes %v", name, got, v.Notes)
		}
	}
	v := j.Judge(model.Item{Title: "PHP flaw", Published: since.AddDate(0, 0, -1)}, targets)
	if len(v.Notes) != 1 || v.Notes[0] != "shop: published 2025-12-31, before the project's start date 2026-01-01" {
		t.Errorf("one note per project: %v", v.Notes)
	}
	only := j.Judge(model.Item{Title: "PHP flaw", Published: since.AddDate(0, 0, -1)}, targets[:2])
	if only.Relevant() || len(only.Notes) != 1 {
		t.Errorf("skipped by every project must not be relevant: techs %v, matches %d", only.Techs, len(only.Matches))
	}
}

func TestHorizonKeepsItemsOutsideTheWindowOutOfEveryProject(t *testing.T) {
	j := New([]model.Tech{{Name: "php"}})
	techs := []model.ProjectTech{{Name: "php", Version: "8.2"}}
	from := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	since := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	targets := []Target{
		{Project: "shop", Env: model.EnvProd, Techs: techs, Horizon: Window{From: from, To: to}},
		{Project: "late", Env: model.EnvProd, Techs: techs, Since: since, Horizon: Window{From: from, To: to}},
	}
	for name, c := range map[string]struct {
		published time.Time
		matched   []string
	}{
		"before the window":       {from.Add(-time.Second), nil},
		"the first instant":       {from, []string{"shop"}},
		"between":                 {since.Add(-time.Hour), []string{"shop"}},
		"after the project start": {since, []string{"shop", "late"}},
		"the last instant":        {to, []string{"shop", "late"}},
		"after the window":        {to.Add(time.Second), nil},
		"no date":                 {time.Time{}, []string{"shop", "late"}},
	} {
		v := j.Judge(model.Item{Title: "PHP flaw", Published: c.published}, targets)
		var got []string
		for _, m := range v.Matches {
			got = append(got, m.Project)
		}
		if !slices.Equal(got, c.matched) {
			t.Errorf("%s: matched %v, want %v (notes %v)", name, got, c.matched, v.Notes)
		}
	}
	v := j.Judge(model.Item{Title: "PHP flaw", Published: to.AddDate(0, 0, 1)}, targets)
	if v.Relevant() || len(v.Notes) != 2 || !strings.Contains(v.Notes[0], "outside the alert horizon") {
		t.Errorf("skipped by every window: relevant %v, notes %v", v.Relevant(), v.Notes)
	}
	open := j.Judge(model.Item{Title: "PHP flaw", Published: from.AddDate(-5, 0, 0)}, []Target{{Project: "p", Env: model.EnvProd, Techs: techs}})
	if len(open.Matches) != 1 {
		t.Error("no horizon judges everything")
	}
}

func TestWordMatchAgreesWithTheExpression(t *testing.T) {
	termSets := [][]string{{"go"}, {"php"}, {"node.js", "nodejs"}, {"c++"}, {"a b", "ab"}, {" Spaced "}, {"é"}, {"k"}, {"s"}, {""}, {"vendor/package"}}
	pieces := []string{"go", "php", "Node.js", "nodejs", "c++", "a", "b", " ", "ab", "-", ".", "/", "vendor/package", "GO", "PHP", "1", "é", "\u212a", "\u017f", "k", "K", "s", "S", "\n"}
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 20000; i++ {
		var b strings.Builder
		for n := rng.Intn(8); n >= 0; n-- {
			b.WriteString(pieces[rng.Intn(len(pieces))])
		}
		text := b.String()
		for _, terms := range termSets {
			w := newWords(terms)
			if got, want := w.match(newSubject(text)), wordRe(terms).MatchString(text); got != want {
				t.Fatalf("terms %q in %q: fast %v, expression %v", terms, text, got, want)
			}
		}
	}
}
