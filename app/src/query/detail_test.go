package query

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/b070nd/cvewatch/app/src/model"
)

func TestSafeLinkAcceptsOnlyPlainWebAddresses(t *testing.T) {
	for raw, want := range map[string]bool{
		"https://a.test/x?y=1#z":  true,
		"http://a.test":           true,
		"HTTPS://a.test":          true,
		"":                        false,
		"javascript:alert(1)":     false,
		"file:///etc/passwd":      false,
		"-oProxyCommand=x":        false,
		"https://":                false,
		"https://a.test/a b":      false,
		"https://a.test/<b>":      false,
		"https://a.test/\x1b[31m": false,
		"https://a.test/\n":       false,
		"ftp://a.test/x":          false,
		"//a.test/x":              false,
		"https://a.test/" + strings.Repeat("a", 2000): false,
	} {
		if got := SafeLink(raw); got != want {
			t.Errorf("SafeLink(%q) = %v, want %v", raw, got, want)
		}
	}
}

func detailFixture() (*model.Vulnerability, []model.Finding) {
	v := &model.Vulnerability{ID: "CVE-1", Title: "Bug", Severity: model.SevHigh, Published: day,
		Refs: []model.Ref{
			{Source: "hn", Kind: model.RefArticle, URL: "https://late.test", Title: "late", Published: day.Add(48 * time.Hour)},
			{Source: "nvd", Kind: model.RefAdvisory, URL: "https://nvd.test/1", Title: "NVD"},
			{Source: "rss", Kind: model.RefArticle, URL: "https://early.test", Title: "early", Published: day.Add(time.Hour)},
			{Source: "nvd", Kind: model.RefAdvisory, URL: "https://nvd.test/1"}, // the same address twice
			{Source: "x", Kind: model.RefArticle, URL: "javascript:alert(1)", Title: "hostile"},
		},
		Fixes:    []model.Fix{{Kind: model.FixVersion, Detail: "1.2", Source: "ghsa", URL: "https://early.test"}, {Kind: model.FixPatch, Source: "ghsa", URL: "https://patch.test/1"}},
		Affected: []model.Affected{{Ecosystem: "npm", Name: "left-pad", Ranges: []model.Range{{Max: "1.2", MaxExcl: true}}}},
	}
	fs := []model.Finding{
		{VulnID: "CVE-1", Project: "shop", Env: model.EnvDev, Status: model.StatusOpen, Ticket: "https://jira.test/1",
			Installed: []model.Installed{{Name: "left-pad", Version: "1.1", Via: "package"}},
			Evidence:  []model.Evidence{{Time: day, Actor: "a", Note: "one", URL: "https://ci.test/1"}, {Time: day.Add(time.Hour), Actor: "b", Note: "two"}}},
		{VulnID: "CVE-1", Project: "shop", Env: model.EnvProd, Status: model.StatusOpen, Ticket: "SHOP-12"},
	}
	return v, fs
}

func TestDetailListsLinksOnceInReadingOrder(t *testing.T) {
	v, fs := detailFixture()
	d := DetailOf(v, fs, now)
	var got []string
	for _, l := range d.Links {
		got = append(got, l.Kind+" "+l.URL)
	}
	want := []string{"advisory https://nvd.test/1", "fix https://early.test", "fix https://patch.test/1", "article https://late.test",
		"evidence https://ci.test/1", "ticket https://jira.test/1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("links:\n%v\nwant\n%v", got, want)
	}
}

func TestDetailCarriesTheFactsOfEachTarget(t *testing.T) {
	v, fs := detailFixture()
	d := DetailOf(v, fs, now)
	if len(d.Issue.Targets) != 2 || len(d.Targets) != 2 {
		t.Fatalf("targets: %+v", d.Targets)
	}
	dev := d.TargetOf("shop", model.EnvDev)
	if len(dev.Installed) != 1 || dev.Installed[0].Label() != "left-pad@1.1" || len(dev.Evidence) != 2 || dev.Evidence[0].Note != "one" {
		t.Fatalf("shop/dev: %+v", dev)
	}
	if prod := d.TargetOf("shop", model.EnvProd); len(prod.Installed) != 0 || prod.Project != "shop" {
		t.Fatalf("shop/prod: %+v", prod)
	}
	if none := d.TargetOf("nope", model.EnvProd); none.Project != "nope" || len(none.Evidence) != 0 {
		t.Fatalf("an unknown target is empty: %+v", none)
	}
	if len(d.Affected) != 1 || d.Affected[0].Name != "left-pad" {
		t.Fatalf("affected: %+v", d.Affected)
	}
	if !d.Issue.ProdOpen || len(d.Why) == 0 || len(d.Issue.Priority) != 0 {
		t.Fatalf("why %v, issue priority %v: the issue itself must stay as the JSON exports know it", d.Why, d.Issue.Priority)
	}
	// the copies must not alias the ledger's slices
	d.Targets[0].Evidence[0].Note = "changed"
	if fs[0].Evidence[0].Note != "one" {
		t.Fatal("the detail shares the evidence slice with the finding")
	}
}

func TestDetailIssueMatchesOne(t *testing.T) {
	l := seed()
	one, err := One(l, "CRIT", Filter{}, now)
	if err != nil {
		t.Fatal(err)
	}
	d := DetailOf(l.Vuln("CRIT"), l.FindingsOf("CRIT"), now)
	if !reflect.DeepEqual(one, d.Issue) {
		t.Fatalf("the exported issue must not depend on how it was built:\n%+v\n%+v", one, d.Issue)
	}
}

func TestRangeText(t *testing.T) {
	for _, c := range []struct {
		in   []model.Range
		want string
	}{
		{nil, "no range given"},
		{[]model.Range{{}}, "all versions"},
		{[]model.Range{{Min: "1.0", Max: "1.5", MaxExcl: true}}, ">=1.0, <1.5"},
		{[]model.Range{{Min: "1.0", MinExcl: true}, {Max: "0.5"}}, ">1.0; <=0.5"},
	} {
		if got := RangeText(c.in); got != c.want {
			t.Errorf("RangeText(%+v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestDetailCarriesTheRatingBeyondTheScore(t *testing.T) {
	v := &model.Vulnerability{ID: "CVE-1", Title: "Bug", Severity: model.SevCritical, Published: day,
		CVSS: 9.8, CVSSVersion: model.CVSS31, CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", CVSSSource: model.ScoreNVD}
	is := DetailOf(v, nil, day.Add(time.Hour)).Issue
	if is.CVSSVersion != "3.1" || is.CVSSVector != v.CVSSVector || is.CVSSSource != "nvd" {
		t.Fatalf("issue = %+v", is)
	}
	if is.CVSSText() != "9.8 (v3.1)" || is.CVSSOrigin() != v.CVSSVector+" from nvd" {
		t.Fatalf("text = %q origin = %q", is.CVSSText(), is.CVSSOrigin())
	}
	// scores recorded before versions were kept, and the unrated
	old := Issue{CVSS: 7.5}
	if old.CVSSText() != "7.5" || old.CVSSOrigin() != "" || (Issue{}).CVSSText() != "" {
		t.Fatalf("old = %q %q", old.CVSSText(), old.CVSSOrigin())
	}
}
