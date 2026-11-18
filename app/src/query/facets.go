package query

import (
	"slices"

	"github.com/b070nd/cvewatch/app/src/model"
)

// Facet is a field of the search language that a filter list offers, with
// the values an issue has for it: ticking values writes field:a,b into the
// search text, and these values are the ones the field's test matches.
type Facet struct {
	Field, Label string
	Order        []string // a fixed order of the values; nil sorts by count
	values       func(is Issue) []string
}

// Values is what the issue has for the facet's field.
func (f Facet) Values(is Issue) []string { return f.values(is) }

// FacetOf is the facet of a field.
func FacetOf(field string) (Facet, bool) {
	for _, f := range Facets {
		if f.Field == field {
			return f, true
		}
	}
	return Facet{}, false
}

func yesNo(b bool) []string {
	if b {
		return []string{"yes"}
	}
	return []string{"no"}
}

// ofTargets is the distinct values of the issue's targets.
func ofTargets(get func(t Target) string) func(is Issue) []string {
	return func(is Issue) []string {
		var out []string
		for _, t := range is.Targets {
			if v := get(t); v != "" && !slices.Contains(out, v) {
				out = append(out, v)
			}
		}
		return out
	}
}

// Facets are the fields a filter list offers, in the order it lists them.
var Facets = []Facet{
	{Field: "severity", Label: "Severity", Order: []string{"critical", "high", "medium", "low", "unknown"},
		values: func(is Issue) []string { return []string{string(is.Severity)} }},
	{Field: "env", Label: "Environment", values: ofTargets(func(t Target) string { return string(t.Env) })},
	{Field: "project", Label: "Project", values: ofTargets(func(t Target) string { return t.Project })},
	{Field: "tech", Label: "Technology", values: func(is Issue) []string { return is.Techs }},
	{Field: "owner", Label: "Owner", values: ofTargets(func(t Target) string { return t.Owner })},
	{Field: "applies", Label: "Applies", Order: []string{string(model.AppAffected), string(model.AppUnknown), string(model.AppNotAffected)},
		values: ofTargets(func(t Target) string { return string(t.Applies) })},
	{Field: "kev", Label: "Known exploited (KEV)", Order: []string{"yes", "no"},
		values: func(is Issue) []string { return yesNo(is.KEV != nil) }},
	{Field: "fix", Label: "Fix available", Order: []string{"yes", "no"},
		values: func(is Issue) []string { return yesNo(is.Fix.Available) }},
	{Field: "overdue", Label: "Overdue", Order: []string{"yes", "no"},
		values: func(is Issue) []string {
			return yesNo(slices.ContainsFunc(is.Targets, func(t Target) bool { return t.Overdue }))
		}},
}
