package catalog

import (
	"testing"

	"github.com/b070nd/cvewatch/app/src/model"
)

func sample() []model.Tech {
	return []model.Tech{
		{Name: "nginx", Title: "nginx", Category: "web-server", Vendor: "F5", Source: "open", CPE: []string{"nginx:nginx"},
			Detect: model.Detect{Images: []string{"nginx"}, Files: []string{"nginx.conf"}}},
		{Name: "elasticsearch", Category: "search", Detect: model.Detect{Images: []string{"elasticsearch/elasticsearch"}}},
		{Name: "go", Aliases: []string{"golang"}, Category: "language"},
		{Name: "magento", Category: "ecommerce", Detect: model.Detect{Packages: []model.PackageHint{{Ecosystem: "composer", Name: "magento/product-community-edition"}}}},
	}
}

func TestMergeLayersByName(t *testing.T) {
	user := []model.Tech{
		{Name: "NGINX", Title: "mine"},            // replaces, keeps position
		{Name: "go", Disabled: true},              // drops the shipped one
		{Name: "grafana", Category: "monitoring"}, // new
		{Name: "unknown", Disabled: true},         // nothing to drop
	}
	got := Merge(sample(), user)
	names := []string{}
	for _, t := range got {
		names = append(names, t.Name)
	}
	if len(got) != 4 || names[0] != "NGINX" || got[0].Title != "mine" || names[3] != "grafana" {
		t.Fatalf("merge: %v", names)
	}
}

func TestLookups(t *testing.T) {
	c := New(sample())
	for ref, want := range map[string]string{
		"nginx:1.25.3-alpine":                                  "nginx",
		"docker.io/library/nginx@sha256:abc":                   "nginx",
		"docker.elastic.co/elasticsearch/elasticsearch:8.11.1": "elasticsearch",
		"registry.local:5000/nginx:1":                          "nginx",
	} {
		if got, ok := c.ForImage(ref); !ok || got.Name != want {
			t.Errorf("ForImage(%q) = %v %v, want %s", ref, got.Name, ok, want)
		}
	}
	if _, ok := c.ForImage("busybox"); ok {
		t.Error("unknown image")
	}
	if got, ok := c.ForPackage("Packagist", "Magento/Product-Community-Edition"); !ok || got.Name != "magento" {
		t.Errorf("package lookup: %v", got.Name)
	}
	if got, ok := c.ForTerm("golang"); !ok || got.Name != "go" {
		t.Errorf("alias lookup: %v", got.Name)
	}
	if got := c.ForFile("NGINX.CONF"); len(got) != 1 {
		t.Errorf("file lookup: %v", got)
	}
	if got := c.Search("elastic"); len(got) != 1 || len(c.Search("")) != 4 || len(c.Search("f5")) != 1 {
		t.Errorf("search: %v", got)
	}
	if cats := c.UsedCategories(); len(cats) == 0 || cats[0] != "language" {
		t.Errorf("categories: %v", cats)
	}
}

func TestValidateCatchesMistakes(t *testing.T) {
	bad := []model.Tech{
		{Name: "a", CPE: []string{"Php:php"}},
		{Name: "a"},
		{Name: "b", Category: "weird", Source: "free", Scheme: "rpm"},
		{Name: "c", Detect: model.Detect{Versions: []model.VersionHint{{File: "x", Pattern: "("}, {File: "y", Pattern: "no group"}}}},
	}
	if errs := New(bad).Validate(); len(errs) != 7 {
		t.Fatalf("want 7 problems, got %d: %v", len(errs), errs)
	}
	if errs := New(sample()).Validate(); len(errs) != 0 {
		t.Fatalf("sample is valid: %v", errs)
	}
}
