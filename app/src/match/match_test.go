package match

import (
	"slices"
	"testing"

	"cvewatch/src/model"
)

func TestTechsWholeWordOnly(t *testing.T) {
	m := New([]model.Tech{
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
		if got := m.Techs(model.Item{Title: title}); !slices.Equal(got, want) {
			t.Errorf("%q: got %v want %v", title, got, want)
		}
	}
}

func TestExcludes(t *testing.T) {
	m := New([]model.Tech{{Name: "php", Excludes: []string{"wordpress", "plugin for"}}})
	if got := m.Techs(model.Item{Title: "Gallery plugin for WordPress, PHP code injection"}); got != nil {
		t.Fatalf("excluded item matched: %v", got)
	}
	if got := m.Techs(model.Item{Title: "PHP-FPM overflow"}); !slices.Equal(got, []string{"php"}) {
		t.Fatalf("got %v", got)
	}
}

func TestTitleOnly(t *testing.T) {
	m := New([]model.Tech{{Name: "php"}})
	it := model.Item{Title: "Flaw in Acme CRM", Summary: "Acme CRM is written in PHP.", TitleOnly: true}
	if got := m.Techs(it); got != nil {
		t.Fatalf("summary mention matched: %v", got)
	}
	it.TitleOnly = false
	if got := m.Techs(it); len(got) != 1 {
		t.Fatalf("full text should match: %v", got)
	}
}

func TestSimilar(t *testing.T) {
	same := [][2]string{
		{"CVE-2026-1: launch-editor allows users to open files with line numbers outside the project",
			"CVE-2026-2: launch-editor allows users to open files with line numbers outside the project root"},
		{"Critical PHP flaw lets attackers run code remotely", "PHP flaw lets remote attackers run code, critical"},
	}
	for _, c := range same {
		if !Similar(c[0], c[1]) {
			t.Errorf("should merge: %q / %q", c[0], c[1])
		}
	}
	diff := [][2]string{
		{"ApostropheCMS content management stored XSS in media library", "ApostropheCMS content management SQL injection in search endpoint"},
		{"PHP RCE", "PHP RCE"}, // too short to trust
		{"PHP2Shell exploitation attempts continue amid suspected hackers", "PHP warns of another unpatched RCE risk after emergency patch"},
	}
	for _, c := range diff {
		if Similar(c[0], c[1]) {
			t.Errorf("should stay apart: %q / %q", c[0], c[1])
		}
	}
}

func TestProject(t *testing.T) {
	p := model.Project{Name: "shop", Techs: []model.ProjectTech{{Name: "php", Version: "8.2"}, {Name: "nodejs"}}}
	pkgs := []model.Package{
		{Name: "symfony/http-kernel", Version: "6.4.1"},
		{Name: "lodash", Version: "4.17.20"},
		{Name: "express", Version: "4.18.0"},
	}
	it := model.Item{
		Title:    "symfony/http-kernel header injection and lodash prototype pollution; express mentioned",
		Packages: []string{"lodash"},
	}
	got := Project(p, pkgs, []string{"php"}, it)
	want := []string{"php@8.2", "symfony/http-kernel@6.4.1", "lodash@4.17.20"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	if Project(p, pkgs, nil, model.Item{Title: "unrelated"}) != nil {
		t.Fatal("expected no match")
	}
}
