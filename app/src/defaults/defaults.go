// Package defaults carries the configuration cvewatch ships with: supported
// technologies, feeds, a commented settings file and a project example. They
// are embedded in the binary, so one executable is enough to start; a file
// with the same purpose in the user's folder takes over completely.
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

// Settings is a commented config.yaml for `init`; every key in it is optional.
func Settings() []byte { return read("config.yaml") }

// ProjectExample is a commented project file for `init`.
func ProjectExample() []byte { return read("project.example.yaml") }

// Layout lists the files `init` writes, by path relative to the root folder.
func Layout() map[string][]byte {
	return map[string][]byte{
		"config/config.yaml":                   Settings(),
		"config/techs.yaml":                    Techs(),
		"sources/default.yaml":                 Sources(),
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
