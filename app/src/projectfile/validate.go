package projectfile

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/b070nd/cvewatch/app/src/matrix"
	"github.com/b070nd/cvewatch/app/src/model"
)

// Issue is one problem found in a project. Level is "error" or "warning".
type Issue struct {
	Level   string
	Field   string
	Message string
}

var versionRE = regexp.MustCompile(`^v?\d`)

// Validate checks the project. known says whether a tech name exists in the
// catalog; nil skips that check.
func (f *File) Validate(known func(tech string) bool) []Issue {
	p := f.Project()
	var issues []Issue
	add := func(level, field, format string, args ...any) {
		issues = append(issues, Issue{level, field, fmt.Sprintf(format, args...)})
	}
	checkTech := func(field, name, version string) {
		if known != nil && !known(name) {
			add("warning", field, "technology %q is not in the catalog, so no advisory will match it", name)
		}
		if version != "" && !versionRE.MatchString(version) {
			add("warning", field, "version %q does not look like a version number", version)
		}
	}

	if strings.TrimSpace(p.Name) == "" {
		add("error", "name", "the project needs a name")
	}
	enabled := map[model.Env]bool{}
	for i, e := range p.EffectiveEnvs() {
		if !e.Valid() {
			add("error", fmt.Sprintf("envs[%d]", i), "invalid environment %q (valid: %v)", e, model.AllEnvs)
			continue
		}
		enabled[e] = true
	}

	seen := map[string]bool{}
	for i, t := range p.Techs {
		field := fmt.Sprintf("techs[%d]", i)
		low := strings.ToLower(strings.TrimSpace(t.Name))
		switch {
		case low == "":
			add("error", field+".name", "the technology needs a name")
		case seen[low]:
			add("error", field+".name", "technology %q is listed more than once", t.Name)
		default:
			seen[low] = true
			checkTech(field, t.Name, t.Version)
		}
	}

	types := matrix.Types()
	for i, l := range p.Lockfiles {
		field := fmt.Sprintf("lockfiles[%d]", i)
		if !slices.Contains(types, l.Type) {
			add("error", field+".type", "unknown lockfile type %q (valid types: %s)", l.Type, strings.Join(types, ", "))
		}
		if l.Env != "" && !l.Env.Valid() {
			add("error", field+".env", "invalid environment %q (valid: %v)", l.Env, model.AllEnvs)
		}
		if strings.TrimSpace(l.Path) == "" {
			add("error", field+".path", "the lockfile needs a path")
		}
	}

	envs := make([]model.Env, 0, len(p.Environments))
	for e := range p.Environments {
		envs = append(envs, e)
	}
	slices.Sort(envs)
	for _, e := range envs {
		field := "environments." + string(e)
		switch {
		case !e.Valid():
			add("error", field, "invalid environment %q (valid: %v)", e, model.AllEnvs)
		case !enabled[e]:
			add("warning", field, "environment %s is not in envs, so it is not monitored", e)
		}
		names := make([]string, 0, len(p.Environments[e].Techs))
		for n := range p.Environments[e].Techs {
			names = append(names, n)
		}
		slices.Sort(names)
		for _, n := range names {
			checkTech(field+".techs."+n, n, p.Environments[e].Techs[n])
		}
	}
	return issues
}
