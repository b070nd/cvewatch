package query

import (
	"strings"
	"testing"
	"time"

	"github.com/b070nd/cvewatch/app/src/model"
)

func searchIssues() []Issue {
	php := Issue{
		ID: "CVE-2026-1234", Aliases: []string{"GHSA-aaaa-bbbb-cccc"}, Severity: model.SevHigh,
		Published: time.Date(2026, 9, 15, 10, 0, 0, 0, time.UTC), Techs: []string{"php"}, Applies: model.AppAffected,
		Fix:       FixInfo{Available: true},
		Untrusted: Untrusted{Title: "PHP memory corruption: Use After Free in zend", Description: "Heap flaw in the engine"},
		Targets: []Target{
			{Project: "shop", Env: model.EnvProd, Status: model.StatusOpen, Owner: "Jane Doe", Ticket: "OPS-12", Matched: []string{"php@8.2"}, Overdue: true},
			{Project: "shop", Env: model.EnvDev, Status: model.StatusFixed},
		},
	}
	openssl := Issue{
		ID: "CVE-2026-5678", Severity: model.SevCritical, Published: time.Date(2026, 10, 2, 8, 0, 0, 0, time.UTC),
		Techs: []string{"openssl"}, Applies: model.AppUnknown, KEV: &KEVInfo{}, Fix: FixInfo{Available: true, Official: true},
		Untrusted: Untrusted{Title: "OpenSSL overflow", Description: "Affects the WordPress plugin"},
		Targets:   []Target{{Project: "blog", Env: model.EnvStaging, Status: model.StatusOpen, Owner: "Bob", Matched: []string{"libssl@3.0.1"}}},
	}
	nginx := Issue{
		ID: "CVE-2025-0001", Severity: model.SevLow, Published: time.Date(2026, 1, 1, 0, 30, 0, 0, time.FixedZone("plus2", 2*3600)),
		Techs: []string{"nginx"}, Applies: model.AppNotAffected,
		Untrusted: Untrusted{Title: "Nginx note"},
		Targets:   []Target{{Project: "shop", Env: model.EnvProd, Status: model.StatusIgnored}},
	}
	return []Issue{php, openssl, nginx}
}

const (
	php     = "CVE-2026-1234"
	openssl = "CVE-2026-5678"
	nginx   = "CVE-2025-0001"
)

func TestSearchMatches(t *testing.T) {
	all := php + "," + openssl + "," + nginx
	cases := []struct{ text, want string }{
		{"", all},
		{"   ", all},
		{`""`, all},

		// plain terms
		{"cve-2026-1234", php},
		{"2026-12", php},
		{"CVE-2026-12", php},
		{"CVE-2026", php + "," + openssl},
		{"ghsa-aaaa", php},
		{"PHP MEMORY", php},
		{"libssl", openssl},
		{"jane", php},
		{"ops-12", php},
		{"staging", openssl},
		{"blog", openssl},
		{"nginx", nginx},
		{`php memory "use after free" -wordpress`, php},
		{`"use after"`, php},
		{`"after use"`, ""},
		{`"use after free`, php},
		{"wordpress", openssl},

		// exclusion
		{"-wordpress", php + "," + nginx},
		{"memory -wordpress", php},
		{"-severity:critical", php + "," + nginx},
		{`-"use after free"`, openssl + "," + nginx},
		{`-owner:"Jane Doe"`, openssl + "," + nginx},
		{"-php", openssl + "," + nginx},
		{"- php", php},

		// OR
		{"php OR openssl", php + "," + openssl},
		{"severity:high php OR openssl", php},
		{"openssl OR libssl status:open", openssl},
		{"php OR nginx -wordpress", php + "," + nginx},
		{"severity:low OR severity:critical", openssl + "," + nginx},
		{"OR nginx", ""},
		{"nginx OR", ""},
		{`nginx "OR" openssl`, ""},
		{"php or openssl", ""},

		// fields
		{"id:CVE-2026-1234", php},
		{"cve:ghsa-AAAA-bbbb-cccc", php},
		{"id:2026-1234", ""},
		{"id:CVE-2026-1*", php},
		{"id:cve-2026-*", php + "," + openssl},
		{"id:CVE-2026-1234,CVE-2025-0001", php + "," + nginx},
		{"severity:critical", openssl},
		{"sev:HIGH", php},
		{"SEVERITY:high", php},
		{"severity:high+", php + "," + openssl},
		{"severity:medium+", php + "," + openssl},
		{"severity:low", nginx},
		{"severity:unknown", ""},
		{"severity:unknown+", all},
		{"severity:critical,low", openssl + "," + nginx},
		{"project:shop", php + "," + nginx},
		{"Project:SHOP env:prod", php + "," + nginx},
		{"project:sho", ""},
		{"env:dev", php},
		{"env:dev,staging", php + "," + openssl},
		{"env:prod project:blog", ""},
		{"env:Staging", openssl},
		{"env:qa-2", ""}, // a valid name nothing runs in matches nothing
		{`owner:"Jane Doe"`, php},
		{`owner:"Jane Doe`, php},
		{"owner:jane", ""},
		{"owner:bob", openssl},
		{"ticket:ops-12", php},
		{"tech:php", php},
		{"tech:openssl,nginx", openssl + "," + nginx},
		{"status:open", php + "," + openssl},
		{"status:fixed", php},
		{"status:ignored", nginx},
		{"status:not_affected", ""},
		{"applies:affected", php},
		{"applies:unknown", openssl},
		{"applies:not_affected", nginx},
		{"kev:yes", openssl},
		{"kev:true", openssl},
		{"kev:no", php + "," + nginx},
		{"kev:false", php + "," + nginx},
		{"fix:yes", php + "," + openssl},
		{"fix:no", nginx},
		{"fix:official", openssl},
		{"overdue:yes", php},
		{"overdue:no", openssl + "," + nginx},
		{"after:2026-09-15", php + "," + openssl},
		{"after:2026-09-16", openssl},
		{"before:2026-09-15", nginx},
		{"before:2026-09-16", php + "," + nginx},
		{"after:2026-09-01 before:2026-10-01", php},
		{"before:2026-01-01", nginx},
		{"after:2026-01-01", php + "," + openssl},
	}
	for _, c := range cases {
		s, err := ParseSearch(c.text)
		if err != nil {
			t.Errorf("%q: %v", c.text, err)
			continue
		}
		var got []string
		for _, is := range searchIssues() {
			if s.Match(is) {
				got = append(got, is.ID)
			}
		}
		if strings.Join(got, ",") != c.want {
			t.Errorf("%q: got %q want %q", c.text, got, c.want)
		}
	}
}

func TestSearchEmpty(t *testing.T) {
	for text, want := range map[string]bool{"": true, "  \t": true, `""`: true, "php": false, "-php": false, "severity:high": false} {
		s, err := ParseSearch(text)
		if err != nil || s.Empty() != want {
			t.Errorf("%q: empty=%v err=%v want empty=%v", text, s.Empty(), err, want)
		}
	}
}

func TestSearchExact(t *testing.T) {
	is := searchIssues()[0]
	cases := map[string]bool{
		"cve-2026-1234":            true,
		"CVE-2026-1234 shop":       true,
		"ghsa-AAAA-bbbb-cccc":      true,
		"shop ghsa-aaaa-bbbb-cccc": true,
		"2026-1234":                false,
		"cve-2026-12":              false,
		"-cve-2026-1234":           false,
		"id:cve-2026-1234":         false,
		"php":                      false,
		"":                         false,
	}
	for text, want := range cases {
		s, err := ParseSearch(text)
		if err != nil {
			t.Fatalf("%q: %v", text, err)
		}
		if got := s.Exact(is); got != want {
			t.Errorf("%q: got %v want %v", text, got, want)
		}
	}
}

func TestSearchErrors(t *testing.T) {
	cases := []struct{ text, want string }{
		{"foo:bar", `unknown field "foo"; use one of: id, severity, project`},
		{"http://example.test", `unknown field "http"`},
		{"-foo:bar", `unknown field "foo"`},
		{"owner:", "missing value after owner:"},
		{`owner:""`, "missing value after owner:"},
		{"foo:", `unknown field "foo"`},
		{"severity:high,", "missing value after severity:"},
		{"severity:urgent", `unknown severity "urgent"`},
		{"severity:urgent+", `unknown severity "urgent+"`},
		{"severity:+", `unknown severity "+"`},
		{"env:QA!", `unknown environment "QA!"`},
		{"status:done", `unknown status "done"; use one of: open, fixed, ignored, not_affected`},
		{"applies:maybe", `unknown applicability "maybe"`},
		{"kev:maybe", `kev needs yes or no, not "maybe"`},
		{"overdue:soon", `overdue needs yes or no, not "soon"`},
		{"fix:maybe", `fix needs yes, no or official, not "maybe"`},
		{"after:yesterday", `bad date "yesterday" for after; use YYYY-MM-DD`},
		{"before:2026-13-01", `bad date "2026-13-01" for before`},
		{"after:2026-9-1", `bad date "2026-9-1" for after`},
		{"php severity:urgent", `unknown severity`},
	}
	for _, c := range cases {
		_, err := ParseSearch(c.text)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q: got error %v want %q", c.text, err, c.want)
		}
	}
}

func TestSearchNeverPanics(t *testing.T) {
	is := searchIssues()[0]
	for _, text := range []string{
		`"`, `""`, `"""`, "-", "--", "-\"", `-"`, "OR", "OR OR", "OR OR OR", "a OR OR b", "a OR", "OR a", ":", "::", ":a", "a:b:c",
		"-:x", `"a"b"c d"`, "\x00", "é:é", "id:*", "-OR", "- OR -", "a,b", "severity:,", " ", "日本語 -日本",
	} {
		s, err := ParseSearch(text)
		if err != nil {
			continue
		}
		s.Match(is)
		s.Exact(is)
	}
}
