package query

import (
	"strings"
	"testing"

	"github.com/b070nd/cvewatch/app/src/ledger"
	"github.com/b070nd/cvewatch/app/src/model"
)

// tenants holds one vulnerability open in two vendors' projects and in a project without a vendor.
func tenants(t *testing.T) (*ledger.Ledger, map[string]string) {
	t.Helper()
	l := ledger.New(ledger.State{})
	l.Create(model.Item{Title: "PHP flaw", URL: "https://a.test/x", IDs: []string{"CVE-1"}, Severity: model.SevHigh,
		Published: day, SourceID: "feed", SourceType: "rss"}, day, []string{"php"})
	for _, f := range []model.Finding{
		{VulnID: "CVE-1", Project: "shop", Env: model.EnvProd, Owner: "ann"},
		{VulnID: "CVE-1", Project: "shop", Env: model.EnvDev, Owner: "bob"},
		{VulnID: "CVE-1", Project: "crm", Env: model.EnvDev, Status: model.StatusOpen},
		{VulnID: "CVE-1", Project: "blog", Env: model.EnvProd},
	} {
		if f.Status == "" {
			f.Status = model.StatusOpen
		}
		l.AddFinding(f)
	}
	return l, map[string]string{"shop": "acme", "crm": "acme", "blog": ""}
}

func targetsOf(is Issue) string {
	var out []string
	for _, t := range is.Targets {
		out = append(out, t.Vendor+"/"+t.Project+"/"+string(t.Env))
	}
	return strings.Join(out, ",")
}

func TestTargetsCarryTheirVendor(t *testing.T) {
	l, vendors := tenants(t)
	got := Open(l, Filter{Vendors: vendors}, now)
	if len(got) != 1 || targetsOf(got[0]) != "/blog/prod,acme/crm/dev,acme/shop/dev,acme/shop/prod" {
		t.Fatalf("%+v", got)
	}
	if plain := Open(l, Filter{}, now); targetsOf(plain[0]) != "/blog/prod,/crm/dev,/shop/dev,/shop/prod" {
		t.Fatalf("without a vendor map no target has one: %s", targetsOf(plain[0]))
	}
}

func TestVendorFilterRemovesTheOtherRowsFromTheIssue(t *testing.T) {
	l, vendors := tenants(t)
	for vendor, want := range map[string]string{
		"acme":         "acme/crm/dev,acme/shop/dev,acme/shop/prod",
		model.NoVendor: "/blog/prod",
		"other":        "",
	} {
		got := Open(l, Filter{Vendor: vendor, Vendors: vendors}, now)
		if want == "" {
			if len(got) != 0 {
				t.Errorf("%s: %+v", vendor, got)
			}
			continue
		}
		if len(got) != 1 || targetsOf(got[0]) != want {
			t.Errorf("%s: %+v", vendor, got)
		}
	}
	only := Open(l, Filter{Project: "crm", Vendors: vendors}, now)
	if len(only) != 1 || targetsOf(only[0]) != "acme/crm/dev" {
		t.Fatalf("a project filter leaves only that project's rows: %+v", only)
	}
	if one, err := One(l, "CVE-1", Filter{Vendor: "acme", Vendors: vendors}, now); err != nil || targetsOf(one) != "acme/crm/dev,acme/shop/dev,acme/shop/prod" {
		t.Fatalf("One: %v %+v", err, one)
	}
}

func TestOpenInProdNamesTheProjectsWhenTheIssueSpansSeveral(t *testing.T) {
	l, vendors := tenants(t)
	all := Open(l, Filter{Vendors: vendors}, now)[0]
	if !strings.Contains(strings.Join(all.Priority, "|"), "open in prod: blog, shop") {
		t.Fatalf("priority = %v", all.Priority)
	}
	crm := Open(l, Filter{Project: "shop", Vendors: vendors}, now)[0]
	if !strings.Contains(strings.Join(crm.Priority, "|"), "open in prod") || strings.Contains(strings.Join(crm.Priority, "|"), "open in prod:") {
		t.Fatalf("one project needs no names: %v", crm.Priority)
	}
	dev := Open(l, Filter{Project: "crm", Vendors: vendors}, now)[0]
	if dev.ProdOpen || strings.Contains(strings.Join(dev.Priority, "|"), "prod") {
		t.Fatalf("crm is open in dev only, but: %v prod=%v", dev.Priority, dev.ProdOpen)
	}
}

func rowsOf(t *testing.T, l *ledger.Ledger, vendors map[string]string, text string) string {
	t.Helper()
	s, err := ParseSearchAt(text, now)
	if err != nil {
		t.Fatal(err)
	}
	f := Filter{Vendors: vendors, All: true, AnyStatus: true, Row: s.Row}
	var out []string
	for _, is := range Open(l, f, now) {
		out = append(out, targetsOf(is))
	}
	return strings.Join(out, ";")
}

func TestSearchTermsHoldOnTheSameRow(t *testing.T) {
	l, vendors := tenants(t)
	for text, want := range map[string]string{
		"project:shop env:dev":              "acme/shop/dev",
		"project:crm env:prod":              "", // crm has no prod row, though the issue has
		"project:shop env:prod owner:ann":   "acme/shop/prod",
		"project:shop env:prod owner:bob":   "",
		"vendor:acme env:prod":              "acme/shop/prod",
		"vendor:acme project:blog":          "",
		"vendor:-":                          "/blog/prod",
		"vendor:acme -project:shop":         "acme/crm/dev",
		"owner:bob status:open":             "acme/shop/dev",
		"severity:high vendor:acme env:dev": "acme/crm/dev,acme/shop/dev",
		"crm prod":                          "", // plain words are matched against one row too
		"php":                               "/blog/prod,acme/crm/dev,acme/shop/dev,acme/shop/prod",
		"vendor:acme OR vendor:-":           "/blog/prod,acme/crm/dev,acme/shop/dev,acme/shop/prod",
	} {
		if got := rowsOf(t, l, vendors, text); got != want {
			t.Errorf("%q: got %q want %q", text, got, want)
		}
	}
}

func TestSearchVendorValueIsChecked(t *testing.T) {
	for _, bad := range []string{"vendor:a.b", "vendor:!x"} {
		if _, err := ParseSearch(bad); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
	if _, err := ParseSearch("vendor:Acme,-"); err != nil {
		t.Fatal(err)
	}
}

func TestSearchMatchNeedsOneRowForAllTerms(t *testing.T) {
	l, vendors := tenants(t)
	is := Open(l, Filter{Vendors: vendors}, now)[0]
	for text, want := range map[string]bool{
		"project:shop env:prod": true,
		"project:crm env:prod":  false,
		"vendor:acme env:prod":  true,
	} {
		s, _ := ParseSearch(text)
		if got := s.Match(is); got != want {
			t.Errorf("%q: %v", text, got)
		}
	}
}
