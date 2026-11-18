package query

import (
	"slices"
	"strings"

	"github.com/b070nd/cvewatch/app/src/model"
)

// wideFields are the fields an open list cannot answer: a search that names
// one is answered from the issues in any status.
var wideFields = []string{"status", "applies"}

// NarrowFrom is Narrow over the open issues, or over wide (each issue with
// its targets in any status, not-affected ones included) when the search
// names a status or an applicability, so a front end that holds both answers
// such a query as a search does. Exact id matches come first, as in a search.
func NarrowFrom(open, wide []Issue, min model.Severity, text string) []Issue {
	q, err := ParseSearch(text)
	if err != nil {
		return Narrow(open, min, text)
	}
	from := open
	if q.Names(wideFields...) {
		from = wide
	}
	out := Narrow(from, min, text)
	slices.SortStableFunc(out, func(a, b Issue) int {
		ea, eb := q.Exact(a), q.Exact(b)
		switch {
		case ea && !eb:
			return -1
		case eb && !ea:
			return 1
		}
		return 0
	})
	return out
}

// Narrow keeps the issues at or above min that match the search text (see
// ParseSearch). Text that does not parse, such as a field still being typed
// ("severity:"), is matched as plain words until it does.
func Narrow(all []Issue, min model.Severity, text string) []Issue {
	search, perr := ParseSearch(text)
	words := strings.Fields(strings.ToLower(text))
	var out []Issue
	for _, is := range all {
		if !is.Severity.AtLeast(min) {
			continue
		}
		if perr == nil {
			if search.Match(is) {
				out = append(out, is)
			}
			continue
		}
		if len(words) > 0 {
			hay := []string{is.ID, is.Untrusted.Title, strings.Join(is.Techs, " "), strings.Join(is.Aliases, " ")}
			for _, t := range is.Targets {
				hay = append(hay, t.Project, string(t.Env), t.Owner)
			}
			text := strings.ToLower(strings.Join(hay, " "))
			if !slices.ContainsFunc(words, func(w string) bool { return !strings.Contains(text, w) }) {
				out = append(out, is)
			}
			continue
		}
		out = append(out, is)
	}
	return out
}

// Counts is the arithmetic of a list of issues.
type Counts struct {
	Issues   int
	Findings int               // open findings
	BySev    map[int]int       // issues by severity rank
	ByEnv    map[model.Env]int // open findings by environment
	KEV      int
	ProdOpen int
	Overdue  int
}

// Count adds up a list of issues.
func Count(issues []Issue) Counts {
	c := Counts{BySev: map[int]int{}, ByEnv: map[model.Env]int{}, Issues: len(issues)}
	for _, is := range issues {
		c.BySev[is.Severity.Rank()]++
		if is.KEV != nil {
			c.KEV++
		}
		if is.ProdOpen {
			c.ProdOpen++
		}
		for _, t := range is.Targets {
			if t.Status != model.StatusOpen {
				continue
			}
			c.Findings++
			c.ByEnv[t.Env]++
			if t.Overdue {
				c.Overdue++
			}
		}
	}
	return c
}

// OpenIn is the environments the issue is open in, per project, in the order
// the projects appear.
func (is Issue) OpenIn() (order []string, open map[string][]model.Env) {
	open = map[string][]model.Env{}
	for _, t := range is.Targets {
		if t.Status != model.StatusOpen {
			continue
		}
		if _, ok := open[t.Project]; !ok {
			order = append(order, t.Project)
		}
		if !slices.Contains(open[t.Project], t.Env) {
			open[t.Project] = append(open[t.Project], t.Env)
		}
	}
	return order, open
}
