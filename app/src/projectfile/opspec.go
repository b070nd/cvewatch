package projectfile

import (
	"fmt"
	"strings"

	"github.com/b070nd/cvewatch/app/src/model"
)

// Param is one input of an op kind. Name is the Op field in its JSON spelling;
// the fields of the lockfile are lockfile.type, lockfile.path, lockfile.env
// and lockfile.dev.
type Param struct {
	Name     string
	Type     string // string, env, envs, date or bool
	Required bool
	Help     string // what it means for this kind
}

// OpSpec describes one op kind as data. The MCP schema, the CLI usage text and
// the parity tests are all built from OpTable, so a new kind is one row here
// plus its case in apply.
type OpSpec struct {
	Kind    string
	Summary string
	Params  []Param
	Example Op
	Flag    string   // the cvewatch project flag that builds it, as in the usage text
	Args    []string // arguments that make the CLI build Example
}

// OpTable lists every op kind that apply accepts.
var OpTable = []OpSpec{
	{
		Kind: "set_envs", Summary: "choose which environments the project runs in",
		Params:  []Param{{"envs", "envs", false, "dev, int, staging or prod; empty means all four"}},
		Example: Op{Kind: "set_envs", Envs: []model.Env{model.EnvDev, model.EnvProd}},
		Flag:    "-envs E,E|all", Args: []string{"-envs", "dev,prod"},
	},
	{
		Kind: "set_tech", Summary: "declare a technology and its version, or change the version",
		Params: []Param{
			{"tech", "string", true, "catalog name"},
			{"version", "string", false, "version or series such as 8.2; empty means unknown"},
		},
		Example: Op{Kind: "set_tech", Tech: "php", Version: "8.2"},
		Flag:    "-set TECH[=VERSION]", Args: []string{"-set", "php=8.2"},
	},
	{
		Kind: "remove_tech", Summary: "stop declaring a technology",
		Params:  []Param{{"tech", "string", true, "catalog name"}},
		Example: Op{Kind: "remove_tech", Tech: "php"},
		Flag:    "-remove TECH", Args: []string{"-remove", "php"},
	},
	{
		Kind: "set_env_tech", Summary: "set the version deployed in one environment, when it differs from the declared one",
		Params: []Param{
			{"env", "env", true, "dev, int, staging or prod"},
			{"tech", "string", true, "catalog name"},
			{"version", "string", true, "the deployed version"},
		},
		Example: Op{Kind: "set_env_tech", Env: model.EnvProd, Tech: "php", Version: "8.3"},
		Flag:    "-env-set ENV:TECH=VERSION", Args: []string{"-env-set", "prod:php=8.3"},
	},
	{
		Kind: "remove_env_tech", Summary: "drop the version deployed in one environment",
		Params: []Param{
			{"env", "env", true, "dev, int, staging or prod"},
			{"tech", "string", true, "catalog name"},
		},
		Example: Op{Kind: "remove_env_tech", Env: model.EnvProd, Tech: "php"},
		Flag:    "-env-unset ENV:TECH", Args: []string{"-env-unset", "prod:php"},
	},
	{
		Kind: "set_image", Summary: "set the container image of one environment",
		Params: []Param{
			{"env", "env", true, "dev, int, staging or prod"},
			{"image", "string", false, "image tag or digest; empty clears"},
		},
		Example: Op{Kind: "set_image", Env: model.EnvProd, Image: "shop:1.4.2"},
		Flag:    "-image ENV=TAG", Args: []string{"-image", "prod=shop:1.4.2"},
	},
	{
		Kind: "add_lockfile", Summary: "read packages from a lockfile",
		Params: []Param{
			{"lockfile.type", "string", true, "composer, npm, go, pip and so on"},
			{"lockfile.path", "string", true, "path of the lockfile on the monitor's machine"},
			{"lockfile.env", "env", false, "only this environment; empty means all"},
			{"lockfile.dev", "bool", false, "count development-only packages in every environment"},
		},
		Example: Op{Kind: "add_lockfile", Lockfile: model.Lockfile{Type: "composer", Path: "composer.lock", Env: model.EnvProd, Dev: true}},
		Flag:    "-lock TYPE:PATH[:ENV][:dev]", Args: []string{"-lock", "composer:composer.lock:prod:dev"},
	},
	{
		Kind: "remove_lockfile", Summary: "stop reading a lockfile",
		Params: []Param{
			{"lockfile.type", "string", false, "not used to find the entry; accepted so the lockfile object of add_lockfile works as it is"},
			{"lockfile.path", "string", true, "path of the lockfile as declared"},
			{"lockfile.env", "env", false, "only the entry for this environment; empty removes every entry with the path"},
		},
		Example: Op{Kind: "remove_lockfile", Lockfile: model.Lockfile{Type: "composer", Path: "composer.lock", Env: model.EnvProd}},
		Flag:    "-unlock TYPE:PATH[:ENV]", Args: []string{"-unlock", "composer:composer.lock:prod"},
	},
	{
		Kind: "set_lockfile_dev", Summary: "count a lockfile's development-only packages in every environment, or stop",
		Params: []Param{
			{"lockfile.type", "string", false, "not used to find the entry; accepted so the lockfile object of add_lockfile works as it is"},
			{"lockfile.path", "string", true, "path of the lockfile as declared"},
			{"lockfile.env", "env", false, "only the entry for this environment; empty changes every entry with the path"},
			{"lockfile.dev", "bool", false, "the new value; false (the default) stops counting them outside dev and int"},
		},
		Example: Op{Kind: "set_lockfile_dev", Lockfile: model.Lockfile{Type: "composer", Path: "composer.lock", Env: model.EnvProd, Dev: true}},
		Flag:    "-lock-dev|-lock-nodev TYPE:PATH[:ENV]", Args: []string{"-lock-dev", "composer:composer.lock:prod"},
	},
	{
		Kind: "set_since", Summary: "set the date from which advisories count for the project",
		Params:  []Param{{"since", "date", false, "YYYY-MM-DD; empty clears"}},
		Example: Op{Kind: "set_since", Since: "2026-01-31"},
		Flag:    "-since DATE", Args: []string{"-since", "2026-01-31"},
	},
}

// SpecOf finds the row of a kind.
func SpecOf(kind string) (OpSpec, bool) {
	for _, s := range OpTable {
		if s.Kind == kind {
			return s, true
		}
	}
	return OpSpec{}, false
}

// Kinds lists the op kinds in table order.
func Kinds() []string {
	out := make([]string, len(OpTable))
	for i, s := range OpTable {
		out[i] = s.Kind
	}
	return out
}

// Signature is the kind with its inputs, optional ones marked: set_tech(tech, version?).
func (s OpSpec) Signature() string {
	var ps []string
	for _, p := range s.Params {
		n := p.Name
		if !p.Required {
			n += "?"
		}
		ps = append(ps, n)
	}
	return s.Kind + "(" + strings.Join(ps, ", ") + ")"
}

// KindHelp describes every kind, one per line, for schema descriptions.
func KindHelp() string {
	var lines []string
	for _, s := range OpTable {
		lines = append(lines, s.Signature()+": "+s.Summary)
	}
	return strings.Join(lines, "\n")
}

// ParamHelp says what an input means in each kind that takes it. name is a
// table name (lockfile.path); callers that flatten it may pass the flattened
// spelling with an underscore.
func ParamHelp(name string) string {
	name = strings.Replace(name, "_", ".", 1)
	var parts []string
	for _, s := range OpTable {
		for _, p := range s.Params {
			if p.Name == name {
				req := ""
				if p.Required {
					req = " (required)"
				}
				parts = append(parts, s.Kind+req+": "+p.Help)
			}
		}
	}
	return strings.Join(parts, "; ")
}

// FlagHelp lists the project edit flags with what each does, one per line.
func FlagHelp(indent string) string {
	width := 0
	for _, s := range OpTable {
		width = max(width, len(s.Flag))
	}
	var b strings.Builder
	for _, s := range OpTable {
		fmt.Fprintf(&b, "%s%-*s  %s (%s)\n", indent, width, s.Flag, s.Summary, s.Kind)
	}
	return b.String()
}
