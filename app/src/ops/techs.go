package ops

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"

	"github.com/b070nd/cvewatch/app/src/catalog"
	"github.com/b070nd/cvewatch/app/src/confdoc"
	"github.com/b070nd/cvewatch/app/src/model"
)

// TechChange adds, changes or removes one of the user's own technologies in
// techs.yaml. Without Save it is only previewed.
type TechChange struct {
	Tech model.Tech
	Save bool
}

// cleanTech normalises what a person typed: the name in lowercase, keywords
// trimmed, without blanks and repeats.
func cleanTech(t model.Tech) (model.Tech, error) {
	t.Name = strings.ToLower(strings.TrimSpace(t.Name))
	if err := catalog.CheckName(t.Name); err != nil {
		return t, err
	}
	var err error
	if t.Aliases, err = cleanWords("keyword", t.Aliases); err != nil {
		return t, err
	}
	if t.Excludes, err = cleanWords("exclude", t.Excludes); err != nil {
		return t, err
	}
	var cpe []string
	for _, c := range t.CPE {
		if c = strings.ToLower(strings.TrimSpace(c)); c != "" && !slices.Contains(cpe, c) {
			cpe = append(cpe, c)
		}
	}
	t.CPE = cpe
	t.Title, t.Vendor = strings.TrimSpace(t.Title), strings.TrimSpace(t.Vendor)
	if len(t.Feeds) > 0 {
		return t, errors.New("feeds are not set here; use settings for a technology's feeds")
	}
	return t, nil
}

func cleanWords(what string, in []string) ([]string, error) {
	var out []string
	for _, w := range in {
		w = strings.TrimSpace(w)
		switch {
		case w == "":
		case strings.ContainsFunc(w, unicode.IsControl) || strings.Contains(w, ","):
			return nil, fmt.Errorf("a %s cannot contain a comma or control characters: %q", what, w)
		case !slices.ContainsFunc(out, func(o string) bool { return strings.EqualFold(o, w) }):
			out = append(out, w)
		}
	}
	return out, nil
}

// techState is what techs.yaml and the shipped catalog hold now.
func (ss *SettingsSession) techState() (user, shipped []model.Tech, err error) {
	if err := ss.mayRead(); err != nil {
		return nil, nil, err
	}
	set, err := confdoc.Read(ss.Root)
	if err != nil {
		return nil, nil, err
	}
	if user, err = set.UserTechs(); err != nil {
		return nil, nil, fmt.Errorf("techs.yaml cannot be read: %w", err)
	}
	if shipped, err = set.ShippedTechs(); err != nil {
		return nil, nil, err
	}
	return user, shipped, nil
}

func findTech(list []model.Tech, name string) (model.Tech, bool) {
	i := slices.IndexFunc(list, func(t model.Tech) bool { return strings.EqualFold(t.Name, name) })
	if i < 0 {
		return model.Tech{}, false
	}
	return list[i], true
}

// UserTechs lists the technologies in the user's own techs.yaml.
func (ss *SettingsSession) UserTechs() ([]model.Tech, error) {
	user, _, err := ss.techState()
	return user, err
}

// AddTech adds a technology of your own to techs.yaml, for example a product
// the catalog does not know. With keywords (Aliases) only, advisories match
// when their title or text names one of them as a whole word; with no
// keywords the name is the keyword. CPE names make it match NVD's product
// data too. A name the catalog already has is refused: change it with EditTech
// when it is yours, or override a built-in one in settings.
func (ss *SettingsSession) AddTech(c TechChange) (SettingsPreview, error) {
	return ss.AddTechs([]model.Tech{c.Tech}, c.Save)
}

// AddTechs adds several technologies of your own in one change: all are added or none.
func (ss *SettingsSession) AddTechs(techs []model.Tech, save bool) (SettingsPreview, error) {
	user, shipped, err := ss.techState()
	if err != nil {
		return SettingsPreview{}, err
	}
	var edits []confdoc.Edit
	for _, in := range techs {
		t, err := cleanTech(in)
		if err != nil {
			return SettingsPreview{}, err
		}
		switch _, mine := findTech(user, t.Name); {
		case mine:
			return SettingsPreview{}, fmt.Errorf("%s is already one of your technologies; change it with edit", t.Name)
		case slices.ContainsFunc(shipped, func(s model.Tech) bool { return strings.EqualFold(s.Name, t.Name) }):
			return SettingsPreview{}, fmt.Errorf("%s is already in the catalog; use it by name", t.Name)
		}
		user = append(user, t) // a repeated name in one change is a duplicate too
		edits = append(edits, confdoc.AddTechEdit(t))
	}
	return ss.Edit(SettingsChange{Edits: edits, Save: save})
}

// EditTech changes one of your own technologies. Fields left empty in the
// change are removed from the entry; its feeds, comments and layout stay.
func (ss *SettingsSession) EditTech(c TechChange) (SettingsPreview, error) {
	t, err := cleanTech(c.Tech)
	if err != nil {
		return SettingsPreview{}, err
	}
	user, _, err := ss.techState()
	if err != nil {
		return SettingsPreview{}, err
	}
	old, ok := findTech(user, t.Name)
	if !ok {
		return SettingsPreview{}, fmt.Errorf("%s is not one of your technologies; built-in ones are changed in settings", t.Name)
	}
	t.Name = old.Name
	return ss.Edit(SettingsChange{Edits: confdoc.ChangeTechEdits(old, t), Save: c.Save})
}

// RemoveTech deletes one of your own technologies from techs.yaml. A project
// that still names it keeps working but nothing will match it any more.
func (ss *SettingsSession) RemoveTech(c TechChange) (SettingsPreview, error) {
	name := strings.ToLower(strings.TrimSpace(c.Tech.Name))
	user, shipped, err := ss.techState()
	if err != nil {
		return SettingsPreview{}, err
	}
	mine, ok := findTech(user, name)
	switch {
	case !ok && slices.ContainsFunc(shipped, func(s model.Tech) bool { return strings.EqualFold(s.Name, name) }):
		return SettingsPreview{}, fmt.Errorf("%s is built in; to hide it add an entry with disabled: true in settings", name)
	case !ok:
		return SettingsPreview{}, fmt.Errorf("%s is not one of your technologies", name)
	}
	return ss.Edit(SettingsChange{Edits: []confdoc.Edit{confdoc.RemoveTechEdit(mine.Name)}, Save: c.Save})
}

// UserTechs lists the technologies the user added to techs.yaml.
func (s *Session) UserTechs() ([]model.Tech, error) { return s.Settings().UserTechs() }

// AddTech adds a technology of your own; see SettingsSession.AddTech. A saved
// change is in Cfg.Catalog at once.
func (s *Session) AddTech(c TechChange) (SettingsPreview, error) {
	return s.techEdit(c, (*SettingsSession).AddTech)
}

// AddTechs adds several at once; see SettingsSession.AddTechs.
func (s *Session) AddTechs(techs []model.Tech, save bool) (SettingsPreview, error) {
	p, err := s.Settings().AddTechs(techs, save)
	if err == nil && p.Saved {
		s.refreshTechs()
	}
	return p, err
}

// EditTech changes a technology of your own; a saved change is in Cfg.Catalog at once.
func (s *Session) EditTech(c TechChange) (SettingsPreview, error) {
	return s.techEdit(c, (*SettingsSession).EditTech)
}

// RemoveTech deletes a technology of your own; a saved change is out of Cfg.Catalog at once.
func (s *Session) RemoveTech(c TechChange) (SettingsPreview, error) {
	return s.techEdit(c, (*SettingsSession).RemoveTech)
}

func (s *Session) techEdit(c TechChange, do func(*SettingsSession, TechChange) (SettingsPreview, error)) (SettingsPreview, error) {
	p, err := do(s.Settings(), c)
	if err == nil && p.Saved {
		s.refreshTechs()
	}
	return p, err
}

// refreshTechs re-reads the catalog after techs.yaml changed, so this session
// sees the change without a restart.
func (s *Session) refreshTechs() {
	set, err := confdoc.Read(s.Cfg.Root)
	if err != nil {
		return
	}
	user, uerr := set.UserTechs()
	shipped, serr := set.ShippedTechs()
	if uerr != nil || serr != nil {
		return
	}
	s.Cfg.Techs = catalog.Merge(shipped, user)
	s.Cfg.Catalog = catalog.New(s.Cfg.Techs)
}
