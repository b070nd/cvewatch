package projectfile

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

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
	Line    int    `json:",omitempty"` // line of the field in the file, 0 when unknown
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
		if to, ok := Suggest(name, names); ok {
			return to, true
		}
		t, ok := c.Closest(name) // several words or a misspelt word: "kernal"
		return t.Name, ok
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
	if !model.ValidVendor(p.Vendor) {
		add("error", "vendor", "invalid vendor %q (use lowercase letters, digits, - and _, at most 63 characters)", p.Vendor)
	}
	if p.Since.After(time.Now()) {
		add("warning", "since", "since %s is in the future, so every dated vulnerability is skipped for now", p.Since.Format(SinceLayout))
	}
	if e := p.Update.Every; e != 0 && e < model.MinEvery {
		shortest := Op{Kind: "set_update", Every: model.Span(model.MinEvery)}
		addFix("error", "update.every", []Fix{{Label: "refresh every " + shortest.Every, Ops: []Op{shortest}}, {Label: "use the interval of config.yaml", Ops: []Op{{Kind: "set_update", Every: "default"}}}},
			"update.every %s is shorter than the minimum of %s", model.Span(e), model.Span(model.MinEvery))
	}
	enabled := map[model.Env]bool{}
	for i, e := range p.EffectiveEnvs() {
		if !e.Valid() {
			add("error", fmt.Sprintf("envs[%d]", i), "invalid environment %q (use lowercase letters, digits, - and _)", e)
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
			addFix("error", field+".env", fixes, "invalid environment %q (use lowercase letters, digits, - and _)", l.Env)
		case l.Env != "" && !enabled[l.Env]:
			addFix("warning", field+".env", []Fix{enableEnvFix(p, l.Env), RemoveLockfileFix(l)},
				"environment %s is not in envs, so lockfile %s is not used", l.Env, l.Path)
		}
		if strings.TrimSpace(l.Path) == "" {
			add("error", field+".path", "the lockfile needs a path")
		}
	}

	for i, t := range p.Techs {
		for _, e := range t.Envs {
			switch {
			case !e.Valid():
				add("error", fmt.Sprintf("techs[%d].envs", i), "invalid environment %q (use lowercase letters, digits, - and _)", e)
			case !enabled[e]:
				addFix("warning", fmt.Sprintf("techs[%d].envs", i), []Fix{enableEnvFix(p, e)}, "environment %s is not in envs, so %s is never present there", e, t.Name)
			}
		}
	}

	envs := make([]model.Env, 0, len(p.Environments))
	for e := range p.Environments {
		envs = append(envs, e)
	}
	slices.Sort(envs)
	for _, e := range envs {
		field, ec := envField(p, e), p.Environments[e]
		switch {
		case !e.Valid():
			add("error", field, "invalid environment %q (use lowercase letters, digits, - and _)", e)
		case !enabled[e] && ec.Old:
			addFix("warning", field, []Fix{enableEnvFix(p, e)}, "environment %s is not in envs, so it is not monitored", e)
		case !enabled[e]:
			fixes := []Fix{enableEnvFix(p, e)}
			if drop := dropDifferencesFix(e, ec); len(drop.Ops) > 0 {
				fixes = append(fixes, drop)
			}
			addFix("error", field, fixes, "%s describes environment %s, which is not in envs", field, e)
		}
		names := make([]string, 0, len(ec.Techs))
		for n := range ec.Techs {
			names = append(names, n)
		}
		slices.Sort(names)
		for _, n := range names {
			checkTech(field+".techs."+n, n, ec.Techs[n], func(to string) []Fix { return renameEnvTech(p, e, n, to) })
			if slices.ContainsFunc(ec.Exclude, func(x string) bool { return strings.EqualFold(x, n) }) {
				addFix("warning", field+".exclude", []Fix{{Label: "keep " + n + " in " + string(e), Ops: []Op{{Kind: "include_env_tech", Env: e, Tech: n}}}},
					"%s is excluded in %s and also has a version there; the exclusion wins", n, e)
			}
		}
		for _, x := range ec.Exclude {
			if !seen[strings.ToLower(strings.TrimSpace(x))] {
				add("warning", field+".exclude", "%q is excluded in %s but the project does not declare it, so there is nothing to exclude", x, e)
			}
		}
	}
	f.Locate(issues)
	return issues
}

// Locate fills in the line of every issue whose field can be found in the
// file, e.g. "techs[0].name" or "environments.prod". Others keep their Line.
func (f *File) Locate(issues []Issue) {
	for i := range issues {
		if issues[i].Line == 0 && issues[i].Field != "" {
			issues[i].Line = f.LineOf(issues[i].Field)
		}
	}
}

// LineOf is the line of a field as validation names it, or 0 when the file
// has no such key or item.
func (f *File) LineOf(field string) int {
	if f.doc == nil || len(f.doc.Content) == 0 {
		return 0
	}
	return lineOf(f.doc.Content[0], field, 0)
}

func lineOf(n *yaml.Node, path string, line int) int {
	if path == "" {
		return line
	}
	switch n.Kind {
	case yaml.AliasNode:
		if n.Alias != nil {
			return lineOf(n.Alias, path, line)
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			rest, ok := strings.CutPrefix(path, k.Value)
			if !ok || k.Value == "" {
				continue
			}
			switch {
			case rest == "":
				return k.Line
			case rest[0] == '.':
				if l := lineOf(n.Content[i+1], rest[1:], k.Line); l != 0 { // a key may hold a dot: try the next one then
					return l
				}
			case rest[0] == '[':
				if l := lineOf(n.Content[i+1], rest, k.Line); l != 0 {
					return l
				}
			}
		}
	case yaml.SequenceNode:
		end := strings.IndexByte(path, ']')
		if path[0] != '[' || end < 0 {
			return 0
		}
		i, err := strconv.Atoi(path[1:end])
		if err != nil || i < 0 || i >= len(n.Content) {
			return 0
		}
		item := n.Content[i]
		return lineOf(item, strings.TrimPrefix(path[end+1:], "."), item.Line)
	}
	return 0
}

// dropDifferencesFix empties the when@ block of an environment the project does not have.
func dropDifferencesFix(e model.Env, ec model.EnvConfig) Fix {
	var ops []Op
	for _, n := range sortedKeys(ec.Techs) {
		ops = append(ops, Op{Kind: "remove_env_tech", Env: e, Tech: n})
	}
	for _, x := range ec.Exclude {
		ops = append(ops, Op{Kind: "include_env_tech", Env: e, Tech: x})
	}
	if ec.Image != "" {
		ops = append(ops, Op{Kind: "set_image", Env: e})
	}
	return Fix{Label: "drop the differences of " + string(e), Ops: ops}
}
