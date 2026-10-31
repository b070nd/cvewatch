package projectfile

import (
	"strings"
	"testing"
)

func TestSetVendorWritesKeepsAndClears(t *testing.T) {
	src := "# the shop\nname: shop # the name\nenvs: [dev, prod]\ntechs: []\nlockfiles: []\n"
	got := mustApply(t, src, Op{Kind: "set_vendor", Vendor: "acme"})
	if !strings.Contains(got, "name: shop # the name\nvendor: acme\nenvs: [dev, prod]\n") || !strings.Contains(got, "# the shop") {
		t.Fatalf("a new vendor goes right after the name:\n%s", got)
	}
	again := mustApply(t, got, Op{Kind: "set_vendor", Vendor: "acme-2"})
	if strings.Count(again, "vendor:") != 1 || !strings.Contains(again, "vendor: acme-2\n") {
		t.Fatalf("a vendor is changed in place:\n%s", again)
	}
	if p := mustParse(t, again).Project(); p.Vendor != "acme-2" || p.Name != "shop" {
		t.Fatalf("project = %+v", p)
	}
	cleared := mustApply(t, again, Op{Kind: "set_vendor"})
	if strings.Contains(cleared, "vendor") || cleared != src {
		t.Fatalf("an empty vendor clears the key:\n%s", cleared)
	}
	if mustApply(t, src, Op{Kind: "set_vendor"}) != src {
		t.Error("clearing a vendor that is not there changes nothing")
	}
}

func TestSetVendorRejectsBadNames(t *testing.T) {
	for _, bad := range []string{"Acme", "acme corp", "-acme", "acme/x", strings.Repeat("a", 64), "ä"} {
		if err := mustParse(t, "name: shop\n").Apply(Op{Kind: "set_vendor", Vendor: bad}); err == nil {
			t.Errorf("%q should be refused", bad)
		}
	}
	for _, good := range []string{"acme", "a", "acme_corp-2", "9lives", strings.Repeat("a", 63)} {
		if err := mustParse(t, "name: shop\n").Apply(Op{Kind: "set_vendor", Vendor: good}); err != nil {
			t.Errorf("%q: %v", good, err)
		}
	}
}

func TestEnvsGoAfterTheVendor(t *testing.T) {
	got := mustApply(t, "name: shop\nvendor: acme\ntechs: []\n", Op{Kind: "add_env", Env: "qa"})
	if !strings.Contains(got, "name: shop\nvendor: acme\nenvs:") {
		t.Fatalf("envs:\n%s", got)
	}
}

func TestValidateRefusesABadHandWrittenVendor(t *testing.T) {
	issues := mustParse(t, "name: shop\nvendor: Acme Corp\n").Validate(nil)
	found := false
	for _, i := range issues {
		found = found || i.Level == "error" && i.Field == "vendor"
	}
	if !found {
		t.Fatalf("issues = %+v", issues)
	}
	for _, i := range mustParse(t, "name: shop\nvendor: acme\n").Validate(nil) {
		if i.Field == "vendor" {
			t.Errorf("a good vendor is not an issue: %+v", i)
		}
	}
}
