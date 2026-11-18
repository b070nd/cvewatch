package tui

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/query"
)

// facet is a field of the search language that the filter list offers, with
// the values an issue has for it.
type facet struct {
	field, label string
	values       func(is query.Issue) []string
	order        []string // a fixed order of the values; nil sorts by count
}

func yesNo(b bool) []string {
	if b {
		return []string{"yes"}
	}
	return []string{"no"}
}

// ofTargets is the distinct values of the issue's targets.
func ofTargets(get func(t query.Target) string) func(is query.Issue) []string {
	return func(is query.Issue) []string {
		var out []string
		for _, t := range is.Targets {
			if v := get(t); v != "" && !slices.Contains(out, v) {
				out = append(out, v)
			}
		}
		return out
	}
}

var facets = []facet{
	{field: "severity", label: "Severity", order: []string{"critical", "high", "medium", "low", "unknown"},
		values: func(is query.Issue) []string { return []string{string(is.Severity)} }},
	{field: "env", label: "Environment", values: ofTargets(func(t query.Target) string { return string(t.Env) })},
	{field: "project", label: "Project", values: ofTargets(func(t query.Target) string { return t.Project })},
	{field: "tech", label: "Technology", values: func(is query.Issue) []string { return is.Techs }},
	{field: "owner", label: "Owner", values: ofTargets(func(t query.Target) string { return t.Owner })},
	{field: "applies", label: "Applies", order: []string{string(model.AppAffected), string(model.AppUnknown), string(model.AppNotAffected)},
		values: ofTargets(func(t query.Target) string { return string(t.Applies) })},
	{field: "kev", label: "Known exploited (KEV)", order: []string{"yes", "no"},
		values: func(is query.Issue) []string { return yesNo(is.KEV != nil) }},
	{field: "fix", label: "Fix available", order: []string{"yes", "no"},
		values: func(is query.Issue) []string { return yesNo(is.Fix.Available) }},
	{field: "overdue", label: "Overdue", order: []string{"yes", "no"},
		values: func(is query.Issue) []string {
			return yesNo(slices.ContainsFunc(is.Targets, func(t query.Target) bool { return t.Overdue }))
		}},
}

// facetCounts counts the issues per value of the facet among those the rest
// of the filter lets through, so every value of it stays to be picked.
func (m *app) facetCounts(f facet) []pickItem {
	l := m.list()
	rows := query.Narrow(m.dataIssues(), l.min, query.SetField(l.text, f.field, nil))
	n := map[string]int{}
	for _, is := range rows {
		for _, v := range f.values(is) {
			n[v]++
		}
	}
	for _, v := range query.FieldValues(l.text, f.field) { // a value in the filter stays to be unticked
		if _, ok := n[v]; !ok {
			n[v] = 0
		}
	}
	vals := make([]string, 0, len(n))
	for v := range n {
		vals = append(vals, v)
	}
	rank := func(v string) int {
		if i := slices.Index(f.order, v); i >= 0 {
			return i
		}
		return len(f.order)
	}
	slices.SortFunc(vals, func(a, b string) int {
		if f.order != nil {
			if d := cmp.Compare(rank(a), rank(b)); d != 0 {
				return d
			}
		}
		if d := cmp.Compare(n[b], n[a]); d != 0 {
			return d
		}
		return cmp.Compare(a, b)
	})
	out := make([]pickItem, len(vals))
	for i, v := range vals {
		out[i] = pickItem{value: v, label: v, detail: plural(n[v], "issue", "issues")}
	}
	return out
}

// startFacets lists the fields to filter by, with what the filter holds for each.
func (m *app) startFacets() tea.Cmd {
	l := m.list()
	pk := &picker{title: "Filter the issues by", hint: "enter lists the values of a field with their counts; the filter text (/) shows and keeps what you tick", crumb: "filter"}
	for _, f := range facets {
		detail := "any"
		if vs := query.FieldValues(l.text, f.field); len(vs) > 0 {
			detail = strings.Join(vs, ", ")
		}
		pk.items = append(pk.items, pickItem{value: f.field, label: f.label, detail: detail})
	}
	if l.text != "" {
		pk.items = append(pk.items, pickItem{value: "", label: "Clear the filter", detail: oneLine(l.text)})
	}
	pk.done = func(m *app, vals []string) tea.Cmd {
		if vals[0] == "" {
			m.chs = nil
			return m.clearFilter()
		}
		i := slices.IndexFunc(facets, func(f facet) bool { return f.field == vals[0] })
		m.chooseFacet(facets[i])
		return nil
	}
	m.choose(pk)
	return nil
}

// chooseFacet ticks the values of one field; ticking none takes the field out of the filter.
func (m *app) chooseFacet(f facet) {
	l := m.list()
	pk := &picker{title: f.label, multi: true, none: true, crumb: "filter " + f.field,
		hint:  "space ticks, enter keeps; an issue passes with any ticked value; none ticked filters nothing on " + f.field,
		items: m.facetCounts(f), sel: map[string]bool{}}
	for _, v := range query.FieldValues(l.text, f.field) {
		for _, it := range pk.items {
			if strings.EqualFold(it.value, v) {
				pk.sel[it.value] = true
			}
		}
	}
	if len(pk.items) == 0 {
		m.chs = nil
		m.say(fmt.Sprintf("no issue in the list has a %s", strings.ToLower(f.label)))
		return
	}
	pk.done = func(m *app, vals []string) tea.Cmd {
		m.chs = nil
		l := m.list()
		l.text = query.SetField(l.text, f.field, vals)
		m.refitLists()
		if l.text == "" {
			m.say("filter cleared")
		} else {
			m.say("filter: " + oneLine(l.text))
		}
		return nil
	}
	m.choose(pk)
}

func bindFacets() binding {
	return binding{keys: ks("="), help: "filter by a field: severity, environment, project, technology, owner, applies, KEV, fix or overdue, each value with its count", short: "filter by", prio: 4, do: plain((*app).startFacets)}
}
