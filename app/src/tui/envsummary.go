package tui

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/query"
)

const envsShown = 3 // environments named in one cell before "+k"

// monitored maps each project to the environments it monitors; projects whose file does not load are left out.
func (sn *snapshot) monitored() map[string][]model.Env {
	if sn == nil {
		return nil
	}
	out := map[string][]model.Env{}
	for _, p := range sn.Projects {
		if p.Broken != "" || p.Disabled {
			continue
		}
		for _, e := range p.Envs {
			out[p.Name] = append(out[p.Name], model.Env(e))
		}
	}
	return out
}

// compactEnvs names the environments with prod first and at most envsShown of them: "prod,dev,int+2".
func compactEnvs(envs []model.Env) string {
	es := slices.Clone(envs)
	model.SortEnvs(es)
	slices.SortStableFunc(es, func(a, b model.Env) int {
		switch {
		case model.IsProd(a) == model.IsProd(b):
			return 0
		case model.IsProd(a):
			return -1
		}
		return 1
	})
	var names []string
	for _, e := range es[:min(len(es), envsShown)] {
		names = append(names, oneLine(string(e)))
	}
	s := strings.Join(names, ",")
	if more := len(es) - envsShown; more > 0 {
		s += fmt.Sprintf("+%d", more)
	}
	return s
}

func sameEnvs(a, b []model.Env) bool {
	return len(a) == len(b) && !slices.ContainsFunc(a, func(e model.Env) bool { return !slices.Contains(b, e) })
}

// openEnvs is the environments an issue is open in, per project, in the order the projects appear.
func openEnvs(is query.Issue) (order []string, open map[string][]model.Env) {
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

// whereOpen says where an issue is open in at most w cells: a project's name alone
// when it is open in every environment the project monitors, else the name and
// only the environments it is open in. Projects that do not fit end in "+k more".
func whereOpen(is query.Issue, mon map[string][]model.Env, w int) string {
	order, open := openEnvs(is)
	entries := make([]string, 0, len(order))
	for _, p := range order {
		if envs, ok := mon[p]; ok && sameEnvs(envs, open[p]) {
			entries = append(entries, oneLine(p))
			continue
		}
		entries = append(entries, oneLine(p)+":"+compactEnvs(open[p]))
	}
	for n := len(entries); n > 0; n-- {
		s := strings.Join(entries[:n], " ")
		if n < len(entries) {
			s += fmt.Sprintf(" +%d more", len(entries)-n)
		}
		if w <= 0 || width(s) <= w || n == 1 {
			return s
		}
	}
	return "-"
}

// openIn is the same for the issues of one project, whose name the page already shows.
func openIn(is query.Issue, project string, envs []string) string {
	_, open := openEnvs(is)
	mon := make([]model.Env, len(envs))
	for i, e := range envs {
		mon[i] = model.Env(e)
	}
	switch got := open[project]; {
	case len(got) == 0:
		return "-"
	case sameEnvs(mon, got):
		return "all"
	default:
		return compactEnvs(got)
	}
}

var prodInCell = regexp.MustCompile(`:(prod|production)([,+ ]|$)`)

// emphasiseProd makes the prod environment stand out in a row that is not the cursor row.
func emphasiseProd(cell string) string {
	return prodInCell.ReplaceAllStringFunc(cell, func(m string) string {
		sub := prodInCell.FindStringSubmatch(m)
		return ":" + stBold.Render(sub[1]) + sub[2]
	})
}

// envSummary says how the open findings spread over the environments of the
// projects in scope: one line when they are all alike, else only the
// environments that hold findings, those with the same count together.
func envSummary(byEnv map[model.Env]int, inScope []model.Env, barW int) string {
	set := maps.Clone(byEnv)
	if set == nil {
		set = map[model.Env]int{}
	}
	for _, e := range inScope {
		if _, ok := set[e]; !ok {
			set[e] = 0
		}
	}
	envs := slices.SortedFunc(maps.Keys(set), model.EnvCompare)
	switch {
	case len(envs) == 0:
		return "none"
	case len(envs) == 1:
		return fmt.Sprintf("%s %d", envs[0], set[envs[0]])
	}
	alike := true
	for _, e := range envs {
		alike = alike && set[e] == set[envs[0]]
	}
	if alike {
		each := fmt.Sprintf("%d open each", set[envs[0]])
		if set[envs[0]] == 0 {
			each = "none open"
		}
		return fmt.Sprintf("all %d environments alike (%s)", len(envs), each)
	}
	most := 0
	for _, n := range set {
		most = max(most, n)
	}
	var groups []string
	done := map[int]bool{}
	for _, e := range envs {
		n := set[e]
		if n == 0 || done[n] {
			continue
		}
		done[n] = true
		var names []string
		for _, o := range envs {
			if set[o] == n {
				names = append(names, string(o))
			}
		}
		groups = append(groups, strings.TrimSpace(fmt.Sprintf("%s %d %s", strings.Join(names, ","), n, bar(n, most, barW))))
	}
	return strings.Join(groups, "  ")
}
