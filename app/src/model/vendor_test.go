package model

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestValidVendor(t *testing.T) {
	for _, ok := range []string{"", "acme", "a", "acme_corp-2", "9lives", strings.Repeat("a", 63)} {
		if !ValidVendor(ok) {
			t.Errorf("%q should be valid", ok)
		}
	}
	for _, bad := range []string{"Acme", "acme corp", "-acme", "_acme", "acme/x", "-", strings.Repeat("a", 64)} {
		if ValidVendor(bad) {
			t.Errorf("%q should be invalid", bad)
		}
	}
}

func TestVendorLabelShowsNoneAsADash(t *testing.T) {
	if VendorLabel("") != NoVendor || VendorLabel("acme") != "acme" {
		t.Fatal("labels")
	}
}

func TestProjectReadsItsVendor(t *testing.T) {
	var p Project
	if err := yaml.Unmarshal([]byte("name: shop\nvendor: acme\nenvs: [prod]\n"), &p); err != nil || p.Vendor != "acme" || p.Name != "shop" {
		t.Fatalf("%+v %v", p, err)
	}
}
