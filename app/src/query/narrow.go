package query

import (
	"slices"
	"strings"

	"github.com/b070nd/cvewatch/app/src/model"
)

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
