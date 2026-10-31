package setup

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/b070nd/cvewatch/app/src/model"
)

// Difference is one way an environment differs from the generic technologies.
type Difference struct {
	Kind    string // version, extra, exclude or image
	Tech    string
	Version string // the version there; the tag of an image
	Generic string // the generic version, for a version
}

// String is the difference as the lists show it: php 8.3, +varnish 7.4, -xdebug, image shop:1.
func (d Difference) String() string {
	switch d.Kind {
	case "extra":
		return strings.TrimSpace("+" + d.Tech + " " + d.Version)
	case "exclude":
		return "-" + d.Tech
	case "image":
		return "image " + d.Version
	}
	return strings.TrimSpace(d.Tech + " " + d.Version)
}

// Differences are what c changes from the generic technologies: versions,
// technologies that run only there, technologies left out, then the image.
func Differences(generic []model.ProjectTech, c model.EnvConfig) []Difference {
	var out []Difference
	for _, name := range slices.Sorted(maps.Keys(c.Techs)) {
		if i := techIndex(generic, name); i >= 0 {
			out = append(out, Difference{Kind: "version", Tech: name, Version: c.Techs[name], Generic: generic[i].Version})
		} else {
			out = append(out, Difference{Kind: "extra", Tech: name, Version: c.Techs[name]})
		}
	}
	for _, x := range slices.Sorted(slices.Values(c.Exclude)) {
		out = append(out, Difference{Kind: "exclude", Tech: x})
	}
	if c.Image != "" {
		out = append(out, Difference{Kind: "image", Version: c.Image})
	}
	return out
}

// DifferenceLines is one line per environment that differs: prod: php 8.3, +varnish 7.4, -xdebug.
func DifferenceLines(p model.Project) []string {
	var out []string
	for _, e := range envKeys(p.Environments) {
		var parts []string
		for _, d := range Differences(p.Techs, p.Environments[e]) {
			parts = append(parts, d.String())
		}
		if len(parts) > 0 {
			out = append(out, string(e)+": "+strings.Join(parts, ", "))
		}
	}
	return out
}

func (f *Flow) hasDifferences() bool {
	for _, c := range f.draft.Environments {
		if len(c.Techs)+len(c.Exclude) > 0 || c.Image != "" {
			return true
		}
	}
	return false
}

// differOrReview is the step after the environments: differences make sense
// only with more than one environment.
func (f *Flow) differOrReview() string {
	if len(f.draft.EffectiveEnvs()) > 1 {
		return "differ"
	}
	return "review"
}

func (f *Flow) setEnvConfig(env string, c model.EnvConfig) {
	e := model.Env(env)
	if len(c.Techs) == 0 && len(c.Exclude) == 0 && c.Image == "" {
		delete(f.draft.Environments, e)
		return
	}
	if f.draft.Environments == nil {
		f.draft.Environments = map[model.Env]model.EnvConfig{}
	}
	f.draft.Environments[e] = c
}

// afterDiffEnv goes on with the next environment that was chosen, else leaves the section.
func (f *Flow) afterDiffEnv(env string) string {
	if i := slices.Index(f.differing, model.Env(env)); i >= 0 && i+1 < len(f.differing) {
		return "diff-techs:" + string(f.differing[i+1])
	}
	return f.afterSection("review")
}

// afterDiffTechs asks which technologies are left out, when there are some to leave out.
func (f *Flow) afterDiffTechs(env string) string {
	if len(f.draft.Techs) == 0 {
		return "diff-image:" + env
	}
	return "diff-exclude:" + env
}

func askDiffer(f *Flow, _ string) Step {
	def := "no"
	if f.hasDifferences() {
		def = "yes"
	}
	return Step{Title: "Does an environment differ from the rest? (default: " + def + ")", Kind: KindConfirm, Default: def,
		Help: "The technologies above apply to every environment. Say yes if an environment runs another version, " +
			"an extra technology, leaves one out or has its own image: only those differences are written, in a when@<env> block. " +
			"No removes the differences the project has."}
}

func applyDiffer(f *Flow, _, v string) error {
	if v == "no" {
		f.draft.Environments = nil
	}
	return nil
}

func nextDiffer(f *Flow, _, v string) string {
	if v == "yes" {
		return "differ-envs"
	}
	return f.afterSection("review")
}

func askDifferEnvs(f *Flow, _ string) Step {
	var opts []Option
	for _, e := range f.draft.EffectiveEnvs() {
		c := f.draft.Environments[e]
		var parts []string
		for _, d := range Differences(f.draft.Techs, c) {
			parts = append(parts, d.String())
		}
		opts = append(opts, Option{Value: string(e), Label: string(e), Detail: strings.Join(parts, ", "), Selected: len(parts) > 0})
	}
	return Step{Title: "Which environments differ?", Kind: KindMulti, Options: opts,
		Help: "Tick the environments that run something other than the technologies above; the rest follow them. An environment left unticked loses its differences."}
}

func applyDifferEnvs(f *Flow, _, v string) error {
	sel := valueSet(v)
	f.differing = f.differing[:0]
	for _, e := range f.draft.EffectiveEnvs() {
		if sel[string(e)] {
			f.differing = append(f.differing, e)
		} else {
			delete(f.draft.Environments, e)
		}
	}
	return nil
}

func nextDifferEnvs(f *Flow, _, _ string) string {
	if len(f.differing) == 0 {
		return f.afterSection("review")
	}
	return "diff-techs:" + string(f.differing[0])
}

func askDiffTechs(f *Flow, env string) Step {
	var cur []string
	for _, d := range Differences(f.draft.Techs, f.draft.Environments[model.Env(env)]) {
		if d.Kind == "version" || d.Kind == "extra" {
			cur = append(cur, d.Tech+"="+d.Version)
		}
	}
	return Step{Title: "Versions that differ in " + env, Kind: KindText, Default: strings.Join(cur, ", "),
		Help: "Only what " + env + " runs differently, written tech=version and separated by commas, for example php=8.3, varnish=7.4. " +
			"A technology that is not in the list above is added to " + env + " alone. Empty means none."}
}

func applyDiffTechs(f *Flow, env, v string) error {
	techs := map[string]string{}
	for _, tok := range strings.Split(v, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		name, ver, ok := strings.Cut(tok, "=")
		if !ok {
			name, ver, _ = strings.Cut(tok, " ")
		}
		name, ver = strings.TrimSpace(name), strings.TrimSpace(ver)
		if !versionRE.MatchString(ver) {
			return fmt.Errorf("%q needs a version, written tech=version, for example php=8.3", plain(tok))
		}
		if i := techIndex(f.draft.Techs, name); i >= 0 {
			name = f.draft.Techs[i].Name
			if f.draft.Techs[i].Version == ver {
				continue // the same as the generic one is no difference
			}
		} else if lk := f.Lookup(name); lk.Found {
			name = lk.Tech.Name
		} else if len(lk.Suggest) == 0 {
			return fmt.Errorf("%q is not in the catalog", plain(name))
		} else {
			var names []string
			for _, t := range lk.Suggest {
				names = append(names, t.Name)
			}
			return fmt.Errorf("%q is not in the catalog. Did you mean: %s?", plain(name), strings.Join(names, ", "))
		}
		techs[name] = ver
	}
	c := f.draft.Environments[model.Env(env)]
	c.Techs = techs
	c.Exclude = slices.DeleteFunc(slices.Clone(c.Exclude), func(x string) bool { return techs[x] != "" })
	f.setEnvConfig(env, c)
	return nil
}

func askDiffExclude(f *Flow, env string) Step {
	c := f.draft.Environments[model.Env(env)]
	var opts []Option
	for _, t := range f.draft.Techs {
		on := slices.ContainsFunc(c.Exclude, func(x string) bool { return strings.EqualFold(x, t.Name) })
		opts = append(opts, Option{Value: t.Name, Label: t.Name, Detail: t.Version, Selected: on})
	}
	return Step{Title: "Technologies that do not run in " + env, Kind: KindMulti, Options: opts,
		Help: "Tick the technologies from the list above that " + env + " does not have; they are not checked there. Nothing ticked means all of them run."}
}

func applyDiffExclude(f *Flow, env, v string) error {
	sel := valueSet(v)
	c := f.draft.Environments[model.Env(env)]
	c.Exclude = nil
	techs := maps.Clone(c.Techs)
	for _, t := range f.draft.Techs {
		if sel[t.Name] {
			c.Exclude = append(c.Exclude, t.Name)
			for n := range techs {
				if strings.EqualFold(n, t.Name) {
					delete(techs, n) // a version there is moot for a tech that does not run
				}
			}
		}
	}
	c.Techs = techs
	f.setEnvConfig(env, c)
	return nil
}

func askDiffImage(f *Flow, env string) Step {
	return Step{Title: "Image of " + env, Kind: KindText, Default: f.draft.Environments[model.Env(env)].Image,
		Help: "An image tag or digest, recorded only. Empty means none."}
}

func applyDiffImage(f *Flow, env, v string) error {
	c := f.draft.Environments[model.Env(env)]
	c.Image = v
	f.setEnvConfig(env, c)
	return nil
}
