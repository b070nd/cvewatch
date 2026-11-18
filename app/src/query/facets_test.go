package query

import (
	"testing"
	"time"

	"github.com/b070nd/cvewatch/app/src/model"
)

// A facet's values must be what its field's test matches, or ticking a value
// in a filter list would filter out the issue it was counted for.
func TestEveryFacetValueMatchesItsOwnIssue(t *testing.T) {
	issues := []Issue{
		{ID: "CVE-1", Severity: model.SevHigh, Techs: []string{"php"}, KEV: &KEVInfo{}, Fix: FixInfo{Available: true},
			Targets: []Target{{Project: "shop", Env: model.EnvProd, Owner: "ann", Applies: model.AppAffected, Status: model.StatusOpen, Overdue: true}}},
		{ID: "CVE-2", Severity: model.SevUnknown,
			Targets: []Target{{Project: "web", Env: model.EnvDev, Applies: model.AppNotAffected, Status: model.StatusOpen}}},
	}
	for _, f := range Facets {
		for _, is := range issues {
			for _, v := range f.Values(is) {
				q, err := ParseSearchAt(SetField("", f.Field, []string{v}), time.Now())
				if err != nil {
					t.Fatalf("%s:%s does not parse: %v", f.Field, v, err)
				}
				if !q.Match(is) {
					t.Errorf("%s:%s does not match %s, which the facet counts for it", f.Field, v, is.ID)
				}
			}
		}
	}
}
