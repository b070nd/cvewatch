package setup

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"

	"github.com/b070nd/cvewatch/app/src/catalog"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/projectfile"
)

// Lookup is what a typed term means to the catalog.
type Lookup struct {
	Found   bool
	Tech    model.Tech   // the technology, when Found
	Suggest []model.Tech // close catalog entries, when not; none means the term is not in the catalog at all
}

// Lookup resolves a typed term: an exact name or alias, else the only catalog
// entry that contains it. Otherwise it lists the closest entries, if any.
func (f *Flow) Lookup(term string) Lookup {
	if t, ok := f.cat.ForTerm(term); ok {
		return Lookup{Found: true, Tech: t}
	}
	if hits := f.cat.Search(term); len(hits) == 1 {
		return Lookup{Found: true, Tech: hits[0]}
	}
	return Lookup{Suggest: f.cat.Suggest(term, 5)}
}

// newCustom builds the entry AddCustom would stage, without staging it. The
// name is the slug of t.Name; with no keywords the typed name (and the slug,
// when it differs) are the keywords.
func (f *Flow) newCustom(t model.Tech) (model.Tech, error) {
	typed := strings.TrimSpace(t.Name)
	t.Name = catalog.Slug(typed)
	if err := catalog.CheckName(t.Name); err != nil {
		return t, err
	}
	if t.Category != "" && !slices.Contains(catalog.Categories, t.Category) {
		return t, fmt.Errorf("unknown category %q", t.Category)
	}
	var err error
	if t.Aliases, err = words(t.Aliases); err != nil {
		return t, err
	}
	if len(t.Aliases) == 0 {
		t.Aliases = []string{t.Name}
		if low := strings.ToLower(typed); low != t.Name && !strings.ContainsFunc(low, unicode.IsControl) && !strings.Contains(low, ",") {
			t.Aliases = []string{low, t.Name}
		}
	}
	var cpe []string
	for _, c := range t.CPE {
		if c = strings.ToLower(strings.TrimSpace(c)); c != "" && !slices.Contains(cpe, c) {
			cpe = append(cpe, c)
		}
	}
	t.CPE = cpe
	t.Title, t.Vendor = plain(t.Title), plain(t.Vendor)
	t.Excludes, t.Feeds, t.Disabled = nil, nil, false
	if _, shipped := f.base.ForTerm(t.Name); shipped {
		return t, fmt.Errorf("%s is already in the catalog; use it by name", t.Name)
	}
	return t, nil
}

func words(in []string) ([]string, error) {
	var out []string
	for _, w := range in {
		w = strings.TrimSpace(w)
		switch {
		case w == "":
		case strings.ContainsFunc(w, unicode.IsControl) || strings.Contains(w, ","):
			return nil, fmt.Errorf("a keyword cannot contain a comma or control characters: %q", plain(w))
		case !slices.ContainsFunc(out, func(o string) bool { return strings.EqualFold(o, w) }):
			out = append(out, w)
		}
	}
	return out, nil
}

// AddCustom stages a technology of the person's own and puts it in the
// project. Nothing is written until the change is saved: ops.ProjectChange
// carries Custom() as NewTechs, so the preview, the validation and the save
// see it together with the project. Name may be any typed term. Aliases are the
// keywords advisories are matched on (default: the name); Category, Title,
// Vendor and CPE are optional. Adding a staged name again replaces it.
func (f *Flow) AddCustom(t model.Tech) error {
	c, err := f.newCustom(t)
	if err != nil {
		return err
	}
	f.stage(c)
	f.problem = "" // what the person was told about the old answer no longer holds
	return nil
}

// ReplaceTech puts another catalog technology in the place of one of the
// draft, for a typo: the version, and the versions per environment, stay.
func (f *Flow) ReplaceTech(old, with string) error {
	i := techIndex(f.draft.Techs, old)
	if i < 0 {
		return fmt.Errorf("%s is not in the project", old)
	}
	t, ok := f.cat.Get(with)
	if !ok {
		return fmt.Errorf("%q is not in the catalog", with)
	}
	from := f.draft.Techs[i].Name
	if j := techIndex(f.draft.Techs, t.Name); j >= 0 && j != i {
		f.draft.Techs = slices.Delete(f.draft.Techs, i, i+1) // already listed: the typo just goes
	} else {
		f.draft.Techs[i].Name = t.Name
	}
	for e, cfg := range f.draft.Environments {
		for n, v := range cfg.Techs {
			if strings.EqualFold(n, from) {
				delete(cfg.Techs, n)
				if _, taken := cfg.Techs[t.Name]; !taken {
					cfg.Techs[t.Name] = v
				}
			}
		}
		for i, x := range cfg.Exclude {
			if strings.EqualFold(x, from) {
				cfg.Exclude[i] = t.Name
			}
		}
		f.draft.Environments[e] = cfg
	}
	f.forgetCustom()
	f.problem = ""
	return nil
}

func (f *Flow) stage(c model.Tech) {
	if i := techIndex2(f.custom, c.Name); i >= 0 {
		f.custom[i] = c
	} else {
		f.custom = append(f.custom, c)
	}
	f.rebuildCatalog()
	if techIndex(f.draft.Techs, c.Name) < 0 {
		f.draft.Techs = append(f.draft.Techs, model.ProjectTech{Name: c.Name})
		f.added = append(f.added, c.Name)
	}
}

// RemoveCustom drops a staged technology, from the project as well.
func (f *Flow) RemoveCustom(name string) error {
	i := techIndex2(f.custom, name)
	if i < 0 {
		return fmt.Errorf("%s is not one of the technologies added in this setup", name)
	}
	f.custom = slices.Delete(f.custom, i, i+1)
	f.rebuildCatalog()
	if j := techIndex(f.draft.Techs, name); j >= 0 {
		f.draft.Techs = slices.Delete(f.draft.Techs, j, j+1)
		f.dropEnvTech(name)
	}
	f.added = slices.DeleteFunc(f.added, func(a string) bool { return strings.EqualFold(a, name) })
	return nil
}

// Custom lists the staged technologies the project still names, which the
// save has to add to techs.yaml.
func (f *Flow) Custom() []model.Tech {
	var out []model.Tech
	for _, c := range f.custom {
		if techIndex(f.draft.Techs, c.Name) >= 0 {
			out = append(out, c)
		}
	}
	return out
}

// SetOwn gives Hints the names of the technologies already in the person's
// techs.yaml.
func (f *Flow) SetOwn(names []string) { f.own = slices.Clone(names) }

// forgetCustom drops staged technologies the project no longer names.
func (f *Flow) forgetCustom() {
	n := len(f.custom)
	f.custom = slices.DeleteFunc(f.custom, func(c model.Tech) bool { return techIndex(f.draft.Techs, c.Name) < 0 })
	if len(f.custom) != n {
		f.rebuildCatalog()
	}
}

func (f *Flow) rebuildCatalog() {
	f.cat = f.base
	if len(f.custom) > 0 {
		f.cat = catalog.New(append(f.base.All(), f.custom...))
	}
}

func techIndex2(techs []model.Tech, name string) int {
	return slices.IndexFunc(techs, func(t model.Tech) bool { return strings.EqualFold(t.Name, name) })
}

// Hints says what in the draft may not be covered or may cause trouble: see
// projectfile.Hints. Technologies staged with AddCustom count as known.
func (f *Flow) Hints() ([]projectfile.Hint, error) {
	var file *projectfile.File
	var err error
	switch {
	case f.src != nil:
		file, err = projectfile.Parse(f.src)
	case f.existing != nil:
		return nil, errors.New("setup: the text of the existing file is needed for hints")
	default:
		file, err = projectfile.New(f.draft.Name)
	}
	if err != nil {
		return nil, err
	}
	if err := file.Apply(f.Ops()...); err != nil {
		return nil, err
	}
	own := slices.Clone(f.own)
	for _, c := range f.custom {
		own = append(own, c.Name)
	}
	return file.Hints(projectfile.HintOptions{Catalog: f.cat, Root: f.dir, Dir: f.dir, Own: own}), nil
}
