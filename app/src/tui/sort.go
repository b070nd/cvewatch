package tui

import (
	"cmp"
	"slices"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/b070nd/cvewatch/app/src/query"
)

// sortCol is a way to order the issue list. The zero one is the priority
// order the issues come in.
type sortCol struct {
	name     string // in the picker and the count line
	head     string // the column heading it marks; empty when no column shows it
	desc     bool   // the order it starts in: true for the largest value first
	up, down string // the order in words, ascending and descending
	cmp      func(a, b query.Issue) int
}

var sortCols = []sortCol{
	{name: "priority", up: "as ranked", down: "as ranked"},
	{name: "severity", head: "SEVERITY", desc: true, up: "lowest first", down: "highest first",
		cmp: func(a, b query.Issue) int { return cmp.Compare(a.Severity.Rank(), b.Severity.Rank()) }},
	{name: "CVSS", head: "CVSS", desc: true, up: "lowest first", down: "highest first",
		cmp: func(a, b query.Issue) int { return cmp.Compare(a.CVSS, b.CVSS) }},
	{name: "EPSS", desc: true, up: "least likely first", down: "most likely first",
		cmp: func(a, b query.Issue) int { return cmp.Compare(epss(a), epss(b)) }},
	{name: "ID", head: "ID", up: "A to Z", down: "Z to A",
		cmp: func(a, b query.Issue) int { return cmp.Compare(strings.ToLower(a.ID), strings.ToLower(b.ID)) }},
	{name: "age", head: "AGE", up: "newest first", down: "oldest first",
		cmp: func(a, b query.Issue) int { return b.Published.Compare(a.Published) }},
	{name: "open in", head: "OPEN IN", up: "A to Z", down: "Z to A",
		cmp: func(a, b query.Issue) int { return cmp.Compare(rowProject(a), rowProject(b)) }},
	{name: "owner", head: "OWNER", up: "A to Z", down: "Z to A",
		cmp: func(a, b query.Issue) int { return cmp.Compare(strings.ToLower(owners(a)), strings.ToLower(owners(b))) }},
	{name: "title", head: "TITLE", up: "A to Z", down: "Z to A",
		cmp: func(a, b query.Issue) int {
			return cmp.Compare(strings.ToLower(a.Untrusted.Title), strings.ToLower(b.Untrusted.Title))
		}},
}

func epss(is query.Issue) float64 {
	if is.EPSS == nil {
		return -1
	}
	return is.EPSS.Score
}

// sortIssues orders the rows by the column; ties keep the priority order. In
// a grouped list the projects keep their order and the rows sort inside each.
func sortIssues(rows []query.Issue, col int, desc, grouped bool) {
	c := sortCols[col]
	if c.cmp == nil && !grouped {
		return
	}
	order := map[string]int{}
	for _, is := range rows {
		if _, ok := order[rowProject(is)]; !ok {
			order[rowProject(is)] = len(order)
		}
	}
	slices.SortStableFunc(rows, func(a, b query.Issue) int {
		if grouped {
			if d := cmp.Compare(order[rowProject(a)], order[rowProject(b)]); d != 0 {
				return d
			}
		}
		if c.cmp == nil {
			return 0
		}
		if desc {
			return c.cmp(b, a)
		}
		return c.cmp(a, b)
	})
}

// sortLabel is the order in words for the count line; empty for the priority order.
func (l *issueList) sortLabel() string {
	if l.sortBy == 0 {
		return ""
	}
	c := sortCols[l.sortBy]
	if l.desc {
		return c.name + ", " + c.down
	}
	return c.name + ", " + c.up
}

// sortHead is the column heading with the arrow of the order when it is the sorted one.
func (l *issueList) sortHead(head string) string {
	if l.sortBy == 0 || sortCols[l.sortBy].head != head {
		return head
	}
	if l.desc {
		return head + "▼"
	}
	return head + "▲"
}

// startSort lists the orders; choosing the one in use reverses it.
func (m *app) startSort() tea.Cmd {
	l := m.list()
	pk := &picker{title: "Sort the issues by", hint: "enter sorts; the order in use again reverses it; < reverses it from the list", crumb: "sort"}
	for i, c := range sortCols {
		detail := c.down
		if !c.desc {
			detail = c.up
		}
		if i == l.sortBy {
			detail = "in use: " + strings.TrimPrefix(l.sortLabel(), c.name+", ")
			if i == 0 {
				detail = "in use"
			}
		}
		pk.items = append(pk.items, pickItem{value: c.name, label: c.name, detail: detail})
	}
	pk.done = func(m *app, vals []string) tea.Cmd {
		m.chs = nil
		i := slices.IndexFunc(sortCols, func(c sortCol) bool { return c.name == vals[0] })
		l := m.list()
		if i == l.sortBy {
			l.desc = !l.desc
		} else {
			l.sortBy, l.desc = i, sortCols[i].desc
		}
		m.refitLists()
		m.sayOrder()
		return nil
	}
	m.choose(pk)
	pk.vp.to(l.sortBy)
	return nil
}

// reverseSort turns the order around.
func (m *app) reverseSort() tea.Cmd {
	l := m.list()
	if l.sortBy == 0 {
		m.say("the priority order has no reverse: > picks a column to sort by")
		return nil
	}
	l.desc = !l.desc
	m.refitLists()
	m.sayOrder()
	return nil
}

func (m *app) sayOrder() {
	if s := m.list().sortLabel(); s != "" {
		m.say("sorted by " + s)
		return
	}
	m.say("sorted by priority")
}

func bindSort() binding {
	return binding{keys: ks(">"), help: "sort by a column: priority, severity, CVSS, EPSS, ID, age, open in, owner or title; the one in use again reverses it", short: "sort", prio: 4, do: plain((*app).startSort)}
}

func bindReverse() binding {
	return binding{keys: ks("<"), help: "reverse the order of the sorted column", short: "reverse", prio: 4, do: plain((*app).reverseSort)}
}
