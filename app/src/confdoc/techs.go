package confdoc

import (
	"reflect"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/b070nd/cvewatch/app/src/model"
)

// UserTechs are the entries of the user's techs.yaml.
func (s *Set) UserTechs() ([]model.Tech, error) { return s.techsOf(IDTechs) }

// ShippedTechs are the built-in catalog entries.
func (s *Set) ShippedTechs() ([]model.Tech, error) { return s.techsOf(IDShippedTechs) }

func (s *Set) techsOf(id string) ([]model.Tech, error) {
	d := s.Doc(id)
	if d == nil {
		return nil, nil
	}
	if d.ParseErr != nil {
		return nil, d.ParseErr
	}
	b, err := d.Bytes()
	if err != nil {
		return nil, err
	}
	var f struct {
		Techs []model.Tech `yaml:"techs"`
	}
	if err := yaml.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	return f.Techs, nil
}

// techField is one key of a technology entry: how to read it from a Tech and
// what to write for it.
type techField struct {
	key string
	get func(model.Tech) any
}

func list(v []string) any {
	if len(v) == 0 {
		return nil
	}
	return v
}

// techFields are the keys a front end edits. Feeds and disabled are left to
// the settings editor.
var techFields = []techField{
	{"title", func(t model.Tech) any { return t.Title }},
	{"category", func(t model.Tech) any { return t.Category }},
	{"vendor", func(t model.Tech) any { return t.Vendor }},
	{"source", func(t model.Tech) any { return t.Source }},
	{"scheme", func(t model.Tech) any { return t.Scheme }},
	{"aliases", func(t model.Tech) any { return list(t.Aliases) }},
	{"excludes", func(t model.Tech) any { return list(t.Excludes) }},
	{"cpe", func(t model.Tech) any { return list(t.CPE) }},
	{"detect.files", func(t model.Tech) any { return list(t.Detect.Files) }},
	{"detect.images", func(t model.Tech) any { return list(t.Detect.Images) }},
	{"detect.packages", func(t model.Tech) any {
		var out []any
		for _, p := range t.Detect.Packages {
			out = append(out, map[string]any{"ecosystem": p.Ecosystem, "name": p.Name})
		}
		return out
	}},
	{"detect.versions", func(t model.Tech) any {
		var out []any
		for _, v := range t.Detect.Versions {
			out = append(out, map[string]any{"file": v.File, "pattern": v.Pattern})
		}
		return out
	}},
}

func empty(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	return rv.Kind() == reflect.String && rv.Len() == 0 || rv.Kind() == reflect.Slice && rv.Len() == 0
}

// AddTechEdit appends t to the user's techs.yaml. Only the keys that are set
// are written.
func AddTechEdit(t model.Tech) Edit {
	rec := map[string]any{"name": t.Name}
	for _, f := range techFields {
		if v := f.get(t); !empty(v) {
			setNested(rec, f.key, v)
		}
	}
	return Edit{Doc: IDTechs, Op: OpAppend, Path: "techs", Value: rec}
}

func setNested(rec map[string]any, key string, v any) {
	head, rest, nested := strings.Cut(key, ".")
	if !nested {
		rec[head] = v
		return
	}
	sub, _ := rec[head].(map[string]any)
	if sub == nil {
		sub = map[string]any{}
		rec[head] = sub
	}
	setNested(sub, rest, v)
}

// ChangeTechEdits turns the user's entry old into t key by key, so what t
// does not carry (feeds, comments, spacing) stays as it is.
func ChangeTechEdits(old, t model.Tech) []Edit {
	var out []Edit
	for _, f := range techFields {
		was, now := f.get(old), f.get(t)
		if reflect.DeepEqual(was, now) || empty(was) && empty(now) {
			continue
		}
		path := FormatPath([]string{"techs", "name=" + old.Name}) + "." + f.key
		if empty(now) {
			out = append(out, Edit{Doc: IDTechs, Op: OpUnset, Path: path})
		} else {
			out = append(out, Edit{Doc: IDTechs, Op: OpSet, Path: path, Value: now})
		}
	}
	return out
}

// RemoveTechEdit drops the user's entry called name.
func RemoveTechEdit(name string) Edit {
	return Edit{Doc: IDTechs, Op: OpUnset, Path: FormatPath([]string{"techs", "name=" + name})}
}
