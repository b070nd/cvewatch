package tui

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/b070nd/cvewatch/app/src/query"
)

// facetCounts counts the issues per value of the facet among those the rest
// of the filter lets through, so every value of it stays to be picked.
func (m *app) facetCounts(f query.Facet) []pickItem {
	l := m.list()
	rows := query.NarrowFrom(m.dataIssues(), m.wideIssues(), l.min, query.SetField(l.text, f.Field, nil))
	n := map[string]int{}
	for _, is := range rows {
		for _, v := range f.Values(is) {
			n[v]++
		}
	}
	for _, v := range query.FieldValues(l.text, f.Field) { // a value in the filter stays to be unticked
		if _, ok := n[v]; !ok {
			n[v] = 0
		}
	}
	vals := make([]string, 0, len(n))
	for v := range n {
		vals = append(vals, v)
	}
	rank := func(v string) int {
		if i := slices.Index(f.Order, v); i >= 0 {
			return i
		}
		return len(f.Order)
	}
	slices.SortFunc(vals, func(a, b string) int {
		if f.Order != nil {
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
	for _, f := range query.Facets {
		detail := "any"
		if vs := query.FieldValues(l.text, f.Field); len(vs) > 0 {
			detail = strings.Join(vs, ", ")
		}
		pk.items = append(pk.items, pickItem{value: f.Field, label: f.Label, detail: detail})
	}
	if l.text != "" {
		pk.items = append(pk.items, pickItem{value: "", label: "Clear the filter", detail: oneLine(l.text)})
	}
	pk.done = func(m *app, vals []string) tea.Cmd {
		if vals[0] == "" {
			m.chs = nil
			return m.clearFilter()
		}
		f, _ := query.FacetOf(vals[0])
		m.chooseFacet(f)
		return nil
	}
	m.choose(pk)
	return nil
}

// chooseFacet ticks the values of one field; ticking none takes the field out of the filter.
func (m *app) chooseFacet(f query.Facet) {
	l := m.list()
	pk := &picker{title: f.Label, multi: true, none: true, crumb: "filter " + f.Field,
		hint:  "space ticks, enter keeps; an issue passes with any ticked value; none ticked filters nothing on " + f.Field,
		items: m.facetCounts(f), sel: map[string]bool{}}
	for _, v := range query.FieldValues(l.text, f.Field) {
		for _, it := range pk.items {
			if strings.EqualFold(it.value, v) {
				pk.sel[it.value] = true
			}
		}
	}
	if len(pk.items) == 0 {
		m.chs = nil
		m.say(fmt.Sprintf("no issue in the list has a %s", strings.ToLower(f.Label)))
		return
	}
	pk.done = func(m *app, vals []string) tea.Cmd {
		m.chs = nil
		l := m.list()
		l.text = query.SetField(l.text, f.Field, vals)
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
