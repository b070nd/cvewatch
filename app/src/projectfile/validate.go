package projectfile

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/b070nd/cvewatch/app/src/catalog"
	"github.com/b070nd/cvewatch/app/src/matrix"
	"github.com/b070nd/cvewatch/app/src/model"
)

// Issue is one problem found in a project. Level is "error" or "warning".
type Issue struct {
	Level   string
	Field   string
	Message string
	Project string `json:",omitempty"`
	Fixes   []Fix  `json:"fixes,omitempty"`
}

// Fix is a way to remove an Issue, written as the edits Apply runs.
type Fix struct {
	Label string `json:"label"`
	Ops   []Op   `json:"ops"`
}

var versionRE = regexp.MustCompile(`^v?\d`)

// Validate checks the project. known says whether a tech name exists in the
// catalog; nil skips that check.
func (f *File) Validate(known func(tech string) bool) []Issue {
	return f.validate(known, nil)
}

// ValidateCatalog is Validate against a catalog, and adds a fix for a
// technology name that is a near miss or an alias of a catalog name.
func (f *File) ValidateCatalog(c *catalog.Catalog) []Issue {
	var names []string
	for _, t := range c.All() {
		names = append(names, t.Name)
	}
	return f.validate(c.Has, func(name string) (string, bool) {
		if t, ok := c.ForTerm(name); ok && !strings.EqualFold(t.Name, name) {
			return t.Name, true
		}
		return Suggest(name, names)
	})
}

func (f *File) validate(known func(tech string) bool, suggest func(name string) (string, bool)) []Issue {
	p := f.Project()
	var issues []Issue
	add := func(level, field, format string, args ...any) {
		issues = append(issues, Issue{Level: level, Field: field, Message: fmt.Sprintf(format, args...)})
	}
	addFix := func(level, field string, fixes []Fix, format string, args ...any) {
		issues = append(issues, Issue{Level: level, Field: field, Message: fmt.Sprintf(format, args...), Fixes: fixes})
	}
	checkTech := func(field, name, version string, rename func(to string) []Fix) {
		if known != nil && !known(name) {
			var fixes []Fix
			if suggest != nil {
				if to, ok := suggest(name); ok {
					fixes = rename(to)
				}
			}
			addFix("warning", field, fixes, "technology %q is not in the catalog, so no advisory will match it", name)
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
			checkTech(field, t.Name, t.Version, func(to string) []Fix { return renameTech(p, t, to) })
		}
	}

	types := matrix.Types()
	for i, l := range p.Lockfiles {
		field := fmt.Sprintf("lockfiles[%d]", i)
		if !slices.Contains(types, l.Type) {
			var fixes []Fix
			if fix, ok := retypeLockfile(p, l); ok {
				fixes = []Fix{fix}
			}
			addFix("error", field+".type", fixes, "unknown lockfile type %q (valid types: %s)", l.Type, strings.Join(types, ", "))
		}
		switch {
		case l.Env != "" && !l.Env.Valid():
			var fixes []Fix
			if !sharedPath(p, l) {
				fixes = []Fix{RemoveLockfileFix(l)}
			}
			addFix("error", field+".env", fixes, "invalid environment %q (valid: %v)", l.Env, model.AllEnvs)
		case l.Env != "" && !enabled[l.Env]:
			addFix("warning", field+".env", []Fix{enableEnvFix(p, l.Env), RemoveLockfileFix(l)},
				"environment %s is not in envs, so lockfile %s is not used", l.Env, l.Path)
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
			addFix("warning", field, []Fix{enableEnvFix(p, e)}, "environment %s is not in envs, so it is not monitored", e)
		}
		names := make([]string, 0, len(p.Environments[e].Techs))
		for n := range p.Environments[e].Techs {
			names = append(names, n)
		}
		slices.Sort(names)
		for _, n := range names {
			checkTech(field+".techs."+n, n, p.Environments[e].Techs[n], func(to string) []Fix { return renameEnvTech(p, e, n, to) })
		}
	}
	return issues
}
