package catalog

import (
	"slices"
	"testing"

	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/relevance"
)

func TestVendorProductNamesMatchTheShippedTech(t *testing.T) {
	judge := relevance.New(shippedCatalog(t).All())
	for _, tc := range []struct{ tech, vendor, product string }{
		{"mysql", "Oracle Corporation", "MySQL Server"},
		{"mysql", "Oracle Corporation", "MySQL Cluster"},
		{"mariadb", "MariaDB Corporation", "MariaDB Server"},
		{"mongodb", "MongoDB Inc.", "MongoDB Server"},
	} {
		it := model.Item{
			Title:     "CVE-2026-1: " + tc.product + " flaw",
			Summary:   "flaw in " + tc.product,
			Products:  []model.Product{{Vendor: tc.vendor, Name: tc.product}},
			TitleOnly: true,
		}
		target := relevance.Target{Project: "shop", Env: "prod", Techs: []model.ProjectTech{{Name: tc.tech}}}
		v := judge.Judge(it, []relevance.Target{target})
		if !slices.Contains(v.Techs, tc.tech) || len(v.Matches) != 1 {
			t.Errorf("%s %s should match a project running %s: techs %v, matches %d, notes %v", tc.vendor, tc.product, tc.tech, v.Techs, len(v.Matches), v.Notes)
		}
	}
}
