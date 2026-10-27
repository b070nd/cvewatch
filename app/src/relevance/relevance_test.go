package relevance

import (
	"slices"
	"strings"
	"testing"

	"github.com/b070nd/cvewatch/app/src/model"
)

func techsOf(j *Judge, it model.Item) []string { return j.Judge(it, nil, nil).Techs }

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
	v := j.Judge(model.Item{Title: "Gallery plugin for WordPress, PHP code injection"}, nil, nil)
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
	if v := j.Judge(nvdItem("moodle:moodle"), projects, nil); v.Relevant() || len(v.Notes) == 0 {
		t.Fatalf("other product must not match: %+v", v)
	}
	// A package advisory (GHSA style) naming a PHP library says "PHP" in passing too.
	pkg := model.Item{Title: "Symfony flaw in a PHP framework", Affected: []model.Affected{{Ecosystem: "composer", Name: "symfony/http-kernel"}}}
	if v := j.Judge(pkg, projects, nil); v.Relevant() {
		t.Fatalf("package data must outrank the word PHP: %+v", v)
	}
	// Real PHP advisory, installed version inside and outside the range.
	rng := model.Range{Max: "8.2.30", MaxExcl: true}
	v := j.Judge(nvdItem("php:php", rng), projects, nil)
	if len(v.Matches) != 1 || v.Matches[0].Applies != model.AppAffected {
		t.Fatalf("8.2.10 < 8.2.30 must be affected: %+v", v.Matches)
	}
	projects[0].Techs[0].Version = "8.3.1"
	v = j.Judge(nvdItem("php:php", rng), projects, nil)
	if len(v.Matches) != 1 || v.Matches[0].Applies != model.AppNotAffected {
		t.Fatalf("8.3.1 must be outside: %+v", v.Matches)
	}
	// A tech declared by series only cannot be decided against a patch-level bound.
	projects[0].Techs[0].Version = "8.2"
	if v = j.Judge(nvdItem("php:php", rng), projects, nil); v.Matches[0].Applies != model.AppUnknown {
		t.Fatalf("series vs patch bound must be unknown: %+v", v.Matches)
	}
}

func TestStructuredOnlyWaitsForProductData(t *testing.T) {
	j := New([]model.Tech{{Name: "php", CPE: []string{"php:php"}}, {Name: "nginx"}})
	fresh := model.Item{Title: "CVE-2026-1: flaw in a CMS written in PHP and served by nginx", StructuredOnly: true}
	v := j.Judge(fresh, nil, nil)
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
	v := j.Judge(ghsa, projects, pkgs)
	if len(v.Matches) != 1 || v.Matches[0].Applies != model.AppAffected || v.Matches[0].Installed[0].Label() != "lodash@4.17.20" {
		t.Fatalf("structured package: %+v", v.Matches)
	}
	// A different ecosystem with the same name is not our package.
	ghsa.Affected[0].Ecosystem = "pip"
	if v := j.Judge(ghsa, projects, pkgs); len(v.Matches) != 0 {
		t.Fatalf("ecosystem must match: %+v", v.Matches)
	}
	// Free text names only scoped packages, and never when the feed is structured.
	text := model.Item{Title: "symfony/http-kernel header injection; express mentioned"}
	v = j.Judge(text, projects, pkgs)
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
