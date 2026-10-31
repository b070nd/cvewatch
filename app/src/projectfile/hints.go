package projectfile

import (
	"fmt"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/b070nd/cvewatch/app/src/catalog"
	"github.com/b070nd/cvewatch/app/src/model"
)

// Hint is advice about a project that is not an error: something the monitor
// may not cover, or that will make it noisy. Level is "warn" or "info".
type Hint struct {
	Level   string   `json:"level"`
	Field   string   `json:"field"`
	Message string   `json:"message"`
	Fix     []Op     `json:"fix,omitempty"`     // the edits that apply the advice; none when it needs an answer from the person
	Suggest []string `json:"suggest,omitempty"` // catalog names close to an unknown technology
	Keyword string   `json:"keyword,omitempty"` // an unknown technology that can be added as the person's own keyword
}

// HintOptions say what Hints knows about the surroundings.
type HintOptions struct {
	Catalog *catalog.Catalog // the technologies that can match; required
	Root    string           // lockfile paths are relative to this
	Dir     string           // the repository folder, when there is one: lockfiles outside it are noted
	Own     []string         // names of technologies the person added to techs.yaml
}

// languageCategories are the technologies whose packages a lockfile lists.
var languageCategories = []string{"language", "runtime", "framework"}

// Hints validates the file against the catalog and checks the files it points
// to, then says what else is worth knowing. The problems Validate and
// CheckFiles find are reused, not repeated: an unknown technology or a missing
// lockfile appears here once, with what could fix it.
func (f *File) Hints(o HintOptions) []Hint {
	p := f.Project()
	issues := f.ValidateCatalog(o.Catalog)
	issues = append(issues, CheckFiles(p, o.Root)...)
	return HintsFor(p, issues, o)
}

// HintsFor is Hints for a project whose issues are already known.
func HintsFor(p model.Project, issues []Issue, o HintOptions) []Hint {
	cat := o.Catalog
	if cat == nil {
		cat = catalog.New(nil)
	}
	var out []Hint
	add := func(h Hint) { out = append(out, h) }

	issueAt := func(field string) (Issue, bool) {
		i := slices.IndexFunc(issues, func(is Issue) bool { return is.Field == field })
		if i < 0 {
			return Issue{}, false
		}
		return issues[i], true
	}

	unknown := func(field, name string) {
		h := unknownHint(cat, field, name)
		if is, ok := issueAt(field); ok && len(is.Fixes) > 0 {
			h.Fix = is.Fixes[0].Ops
		}
		add(h)
	}
	for i, t := range p.Techs {
		if name := strings.TrimSpace(t.Name); name != "" && !cat.Has(name) {
			unknown(fmt.Sprintf("techs[%d]", i), t.Name)
		}
	}
	for _, e := range sortedEnvs(p) {
		for _, n := range sortedKeys(p.Environments[e].Techs) {
			if !cat.Has(n) {
				unknown(envField(p, e)+".techs."+n, n)
			}
		}
	}

	known := 0
	for _, t := range p.Techs {
		if cat.Has(t.Name) {
			known++
		}
	}
	if known == 0 && len(p.Lockfiles) == 0 {
		add(Hint{Level: "warn", Field: "techs", Message: "nothing can match yet: add a technology from the catalog (or your own keyword) or a lockfile"})
	}

	for _, is := range issues {
		if !strings.HasPrefix(is.Field, "lockfiles[") {
			continue
		}
		h := Hint{Level: "warn", Field: is.Field, Message: is.Message}
		if len(is.Fixes) > 0 {
			h.Fix = is.Fixes[0].Ops
		}
		add(h)
	}
	if o.Dir != "" {
		for i, l := range p.Lockfiles {
			if l.Path != "" && !within(o.Dir, ResolvePath(o.Root, l.Path)) {
				add(Hint{Level: "info", Field: fmt.Sprintf("lockfiles[%d].path", i),
					Message: fmt.Sprintf("lockfile %s is outside the repository folder, so it may not exist where the monitor runs", l.Path)})
			}
		}
	}

	for _, h := range EnvHints(p) {
		add(Hint{Level: h.Level, Field: h.Field, Message: h.Message, Fix: h.Fix})
	}

	own := map[string]bool{}
	for _, n := range o.Own {
		own[strings.ToLower(n)] = true
	}
	language := false
	for i, t := range p.Techs {
		ct, ok := cat.Get(t.Name)
		if !ok {
			continue
		}
		field := fmt.Sprintf("techs[%d]", i)
		if t.Version == "" && !versionInEnvs(p, t.Name) {
			add(Hint{Level: "warn", Field: field + ".version",
				Message: fmt.Sprintf("%s has no version, so every advisory naming it is reported as \"version could not be checked\"; add the version you run (a series such as 8.2 is fine)", t.Name)})
		}
		if more := broader(cat, ct.Name); len(more) > 0 {
			add(Hint{Level: "info", Field: field,
				Message: fmt.Sprintf("%s is broad: the catalog also has %s; pick the specific product if that is what you run", t.Name, strings.Join(more, ", ")),
				Suggest: more})
		}
		if own[strings.ToLower(ct.Name)] && len(ct.CPE) == 0 {
			add(Hint{Level: "info", Field: field,
				Message: fmt.Sprintf("%s is your own keyword: advisories match when their title or text names it; add a CPE name (vendor:product) to match NVD product data and versions", ct.Name)})
		}
		language = language || slices.Contains(languageCategories, ct.Category)
	}
	if language && len(p.Lockfiles) == 0 {
		add(Hint{Level: "info", Field: "lockfiles",
			Message: "no lockfile: the packages your language or framework installs are not checked; add the lockfile (composer.lock, package-lock.json, go.sum and so on)"})
	}
	if p.Since.IsZero() {
		add(Hint{Level: "info", Field: "since",
			Message: "no start date: every advisory the sources serve counts, old ones included; set since (YYYY-MM-DD) to ignore older ones (their open findings close by themselves; an earlier date fetches older advisories and reopens those)"})
	}

	if !p.AutoUpdate() {
		on := true
		add(Hint{Level: "info", Field: "update.auto",
			Message: "scheduled runs skip this project; run cvewatch update or press F to refresh it",
			Fix:     []Op{{Kind: "set_update", Auto: &on}}})
	}
	if p.Update.Every > model.LongEvery {
		add(Hint{Level: "info", Field: "update.every",
			Message: fmt.Sprintf("update.every %s is longer than 30 days, so the project is hardly ever refreshed", model.Span(p.Update.Every))})
	}

	sort.SliceStable(out, func(i, j int) bool { return out[i].Level == "warn" && out[j].Level != "warn" })
	return out
}

// unknownHint is the advice for a technology the catalog does not have.
func unknownHint(cat *catalog.Catalog, field, name string) Hint {
	h := Hint{Level: "warn", Field: field, Keyword: strings.TrimSpace(name)}
	for _, t := range cat.Suggest(name, 4) {
		h.Suggest = append(h.Suggest, t.Name)
	}
	if len(h.Suggest) == 0 {
		h.Message = fmt.Sprintf("%q is not in the catalog, so no advisory will match it; add it as your own keyword so advisories that name it do", name)
	} else {
		h.Message = fmt.Sprintf("%q is not in the catalog, so no advisory will match it. Did you mean: %s? Or add it as your own keyword", name, strings.Join(h.Suggest, ", "))
	}
	return h
}

// broader lists catalog names that extend name with a dash: cisco-ios has cisco-ios-xe.
func broader(cat *catalog.Catalog, name string) []string {
	var out []string
	for _, t := range cat.All() {
		if strings.HasPrefix(strings.ToLower(t.Name), strings.ToLower(name)+"-") {
			out = append(out, t.Name)
		}
	}
	return out
}

func versionInEnvs(p model.Project, tech string) bool {
	for _, c := range p.Environments {
		for n, v := range c.Techs {
			if strings.EqualFold(n, tech) && v != "" {
				return true
			}
		}
	}
	return false
}

func within(dir, path string) bool {
	rel, err := filepath.Rel(filepath.Clean(dir), filepath.Clean(path))
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func sortedEnvs(p model.Project) []model.Env {
	envs := make([]model.Env, 0, len(p.Environments))
	for e := range p.Environments {
		envs = append(envs, e)
	}
	model.SortEnvs(envs)
	return envs
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
