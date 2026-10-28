// Package defaults carries the configuration cvewatch ships with: supported
// technologies, feeds, a commented settings file and a project example. They
// are embedded in the binary, so one executable is enough to start; files in
// the user's folder are layered over them.
package defaults

import (
	"embed"
	"io/fs"
	"sort"
)

//go:embed files/*
var files embed.FS

func read(name string) []byte {
	b, err := files.ReadFile("files/" + name)
	if err != nil {
		panic("defaults: missing embedded file " + name) // a build error, not a runtime condition
	}
	return b
}

// Techs is the shipped techs.yaml.
func Techs() []byte { return read("techs.yaml") }

// Sources is the shipped feed list (a sources: key, like any file in sources/).
func Sources() []byte { return read("sources.yaml") }

// UserTechs is the commented techs.yaml `init` writes: shipped technologies
// are always available, so it holds only the user's own additions.
func UserTechs() []byte { return read("user-techs.yaml") }

// UserSources is the commented feed file `init` writes, for the user's own feeds.
func UserSources() []byte { return read("user-sources.yaml") }

// Settings is a commented config.yaml for `init`; every key in it is optional.
func Settings() []byte { return read("config.yaml") }

// ProjectExample is a commented project file for `init`.
func ProjectExample() []byte { return read("project.example.yaml") }

// Layout lists the files `init` writes, by path relative to the root folder.
func Layout() map[string][]byte {
	return map[string][]byte{
		"config/config.yaml":                   Settings(),
		"config/techs.yaml":                    UserTechs(),
		"sources/custom.yaml":                  UserSources(),
		"config/projects/example.yaml.example": ProjectExample(),
	}
}

// Names returns the layout paths in a stable order.
func Names() []string {
	var out []string
	for n := range Layout() {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

var _ fs.FS = files
