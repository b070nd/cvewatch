// Package defaults carries the configuration cvewatch ships with: supported
// technologies, feeds, a commented settings file and a project example. They
// are embedded in the binary, so one executable is enough to start; files in
// the user's folder are layered over them.
package defaults

import (
	"embed"
	"io/fs"
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

// UserTechs is the commented techs.yaml.dist `init` writes: shipped
// technologies are always available, so it holds only additions.
func UserTechs() []byte { return read("user-techs.yaml") }

// UserSources is the commented feed file `init` writes, for added feeds.
func UserSources() []byte { return read("user-sources.yaml") }

// UserSettings is the config.yaml `init` writes: a person's own settings,
// over config.yaml.dist (see confdoc.DistSettings, which `init` writes too).
func UserSettings() []byte {
	return []byte("# Your own settings. A key here overrides config.yaml.dist next to this file,\n" +
		"# which lists every setting with its help and default. The TUI, the MCP\n" +
		"# tools and the CLI write their changes here.\n\n" +
		"data_dir: data       # state.json, audit.log (relative to this folder)\n" +
		"alerts_dir: alerts   # generated reports and calendar pages\n")
}

// ProjectExample is a commented project template for `init`.
func ProjectExample() []byte { return read("project.example.yaml") }

// Layout lists the files `init` writes from this package, by path relative to
// the root folder. config/config.yaml.dist comes from the settings schema.
func Layout() map[string][]byte {
	return map[string][]byte{
		"config/config.yaml":                UserSettings(),
		"config/techs.yaml.dist":            UserTechs(),
		"sources/custom.yaml.dist":          UserSources(),
		"config/projects/example.yaml.dist": ProjectExample(),
	}
}

var _ fs.FS = files
