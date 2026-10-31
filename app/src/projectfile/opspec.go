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
		Params:  []Param{{"envs", "envs", false, "environment names, free to choose (local, dev, prod, qa-2); empty removes the key, which means the old default dev, int, staging, prod"}},
		Example: Op{Kind: "set_envs", Envs: []model.Env{model.EnvDev, model.EnvProd}},
		Flag:    "-envs E,E|all", Args: []string{"-envs", "dev,prod"},
	},
	{
		Kind: "add_env", Summary: "add an environment to the project",
		Params:  []Param{{"env", "env", true, "the name: lowercase letters, digits, - and _; a file without envs first gets the old default list, then this one"}},
		Example: Op{Kind: "add_env", Env: "qa"},
		Flag:    "-env-add ENV", Args: []string{"-env-add", "qa"},
	},
	{
		Kind: "remove_env", Summary: "remove an environment from the project's list and its when@ block (lockfiles that name it stay in the file and are reported)",
		Params:  []Param{{"env", "env", true, "an environment of the project; the last one cannot be removed"}},
		Example: Op{Kind: "remove_env", Env: "int"},
		Flag:    "-env-remove ENV", Args: []string{"-env-remove", "int"},
	},
	{
		Kind: "rename_env", Summary: "rename an environment in the list, its when@ block, its lockfiles and the envs of scoped techs",
		Params: []Param{
			{"env", "env", true, "the current name"},
			{"to", "env", true, "the new name; it must not exist yet"},
		},
		Example: Op{Kind: "rename_env", Env: "staging", To: "stage"},
		Flag:    "-env-rename OLD=NEW", Args: []string{"-env-rename", "staging=stage"},
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
		Kind: "set_env_tech", Summary: "set the version a tech has in one environment (its when@ENV block), when it differs from the generic one; also adds a tech that exists only there",
		Params: []Param{
			{"env", "env", true, "an environment of the project, such as local, dev or prod"},
			{"tech", "string", true, "catalog name"},
			{"version", "string", true, "the version in that environment"},
		},
		Example: Op{Kind: "set_env_tech", Env: model.EnvProd, Tech: "php", Version: "8.3"},
		Flag:    "-env-set ENV:TECH=VERSION", Args: []string{"-env-set", "prod:php=8.3"},
	},
	{
		Kind: "remove_env_tech", Summary: "drop the version a tech has in one environment, so the generic one applies again",
		Params: []Param{
			{"env", "env", true, "an environment of the project, such as local, dev or prod"},
			{"tech", "string", true, "catalog name"},
		},
		Example: Op{Kind: "remove_env_tech", Env: model.EnvProd, Tech: "php"},
		Flag:    "-env-unset ENV:TECH", Args: []string{"-env-unset", "prod:php"},
	},
	{
		Kind: "exclude_env_tech", Summary: "a generic tech does not run in one environment (exclude: in its when@ENV block)",
		Params: []Param{
			{"env", "env", true, "an environment of the project, such as local, dev or prod"},
			{"tech", "string", true, "a generic tech of the project"},
		},
		Example: Op{Kind: "exclude_env_tech", Env: model.EnvDev, Tech: "varnish"},
		Flag:    "-env-exclude ENV:TECH", Args: []string{"-env-exclude", "dev:varnish"},
	},
	{
		Kind: "include_env_tech", Summary: "undo exclude_env_tech: the generic tech runs in the environment again",
		Params: []Param{
			{"env", "env", true, "an environment of the project, such as local, dev or prod"},
			{"tech", "string", true, "the excluded tech"},
		},
		Example: Op{Kind: "include_env_tech", Env: model.EnvDev, Tech: "varnish"},
		Flag:    "-env-include ENV:TECH", Args: []string{"-env-include", "dev:varnish"},
	},
	{
		Kind: "set_tech_envs", Summary: "limit a generic tech to some environments (envs: on the tech); no envs lifts the limit",
		Params: []Param{
			{"tech", "string", true, "a generic tech of the project"},
			{"envs", "envs", false, "the environments it is present in; empty means all of them"},
		},
		Example: Op{Kind: "set_tech_envs", Tech: "php", Envs: []model.Env{model.EnvLocal, model.EnvDev}},
		Flag:    "-tech-envs TECH=E,E", Args: []string{"-tech-envs", "php=local,dev"},
	},
	{
		Kind: "set_image", Summary: "set the container image of one environment",
		Params: []Param{
			{"env", "env", true, "an environment of the project, such as local, dev or prod"},
			{"image", "string", false, "image tag or digest; empty clears"},
		},
		Example: Op{Kind: "set_image", Env: model.EnvProd, Image: "shop:1.4.2"},
		Flag:    "-image ENV=TAG", Args: []string{"-image", "prod=shop:1.4.2"},
	},
	{
		Kind: "migrate_envs", Summary: "rewrite the old environments: map as when@ENV blocks (same meaning); nothing else changes, and no old map means no change",
		Example: Op{Kind: "migrate_envs"},
		Flag:    "-migrate-envs", Args: []string{"-migrate-envs"},
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
			{"lockfile.path", "string", true, "path of the lockfile as declared in the project file (list_projects: declared_path), or the resolved one it shows as path"},
			{"lockfile.env", "env", false, "only the entry for this environment; empty removes every entry with the path"},
		},
		Example: Op{Kind: "remove_lockfile", Lockfile: model.Lockfile{Type: "composer", Path: "composer.lock", Env: model.EnvProd}},
		Flag:    "-unlock TYPE:PATH[:ENV]", Args: []string{"-unlock", "composer:composer.lock:prod"},
	},
	{
		Kind: "set_lockfile_dev", Summary: "count a lockfile's development-only packages in every environment, or stop",
		Params: []Param{
			{"lockfile.type", "string", false, "not used to find the entry; accepted so the lockfile object of add_lockfile works as it is"},
			{"lockfile.path", "string", true, "path of the lockfile as declared in the project file (list_projects: declared_path), or the resolved one it shows as path"},
			{"lockfile.env", "env", false, "only the entry for this environment; empty changes every entry with the path"},
			{"lockfile.dev", "bool", false, "the new value; false (the default) stops counting them outside development-like environments (local, dev, int)"},
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
	{
		Kind: "set_vendor", Summary: "set the vendor (customer or organisation) that owns the project; findings and access rules group by it",
		Params:  []Param{{"vendor", "string", false, "lowercase letters, digits, - and _, at most 63 characters; empty clears, so the project has no vendor"}},
		Example: Op{Kind: "set_vendor", Vendor: "acme"},
		Flag:    "-vendor NAME", Args: []string{"-vendor", "acme"},
	},
	{
		Kind: "set_update", Summary: "set how often the project is refreshed, or take it out of scheduled runs",
		Params: []Param{
			{"every", "string", false, "a period such as 30m, 1h or 2d, at least 5m; default removes it, so the interval of config.yaml applies; empty leaves it"},
			{"auto", "bool", false, "false: scheduled runs skip the project (cvewatch update and the u key still include it); true schedules it again; left out leaves it"},
		},
		Example: Op{Kind: "set_update", Every: "1h", Auto: &autoOff},
		Flag:    "-update-every SPAN, -update-auto BOOL", Args: []string{"-update-every", "1h", "-update-auto", "false"},
	},
}

var autoOff = false

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
