package projectfile

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/b070nd/cvewatch/app/src/model"
)

// currentEnvs is the environment list as the file means it: without an envs
// key that is the old default, so the first edit keeps what the file meant.
func currentEnvs(root *yaml.Node) []model.Env {
	seq := mapGet(root, "envs")
	if seq == nil || seq.Kind != yaml.SequenceNode || len(seq.Content) == 0 {
		return slices.Clone(model.LegacyEnvs)
	}
	out := make([]model.Env, 0, len(seq.Content))
	for _, n := range seq.Content {
		out = append(out, model.Env(n.Value))
	}
	return out
}

func checkEnvName(label string, e model.Env) error {
	if !e.Valid() {
		return fmt.Errorf("invalid %s %q (lowercase letters, digits, - and _, starting with a letter)", label, e)
	}
	return nil
}

func addEnv(root *yaml.Node, env model.Env) error {
	if err := checkEnvName("env", env); err != nil {
		return err
	}
	list := currentEnvs(root)
	if slices.Contains(list, env) {
		return nil
	}
	return setEnvs(root, append(list, env))
}

// removeEnv drops the name from envs and its when@ block of differences, which
// would otherwise name an environment the project does not have. An old
// environments: entry and lockfiles that name it stay, and the check warns about them.
func removeEnv(root *yaml.Node, env model.Env) error {
	if err := checkEnvName("env", env); err != nil {
		return err
	}
	list := currentEnvs(root)
	i := slices.Index(list, env)
	switch {
	case i < 0:
		return fmt.Errorf("environment %q is not in envs", env)
	case len(list) == 1:
		return errors.New("a project needs at least one environment")
	}
	mapDel(root, whenKey(env))
	return setEnvs(root, slices.Delete(list, i, i+1))
}

// renameEnv renames the name in envs, its when@ block, the lockfile envs and
// the envs of scoped techs. An old environments: entry is migrated first.
func renameEnv(root *yaml.Node, from, to model.Env) error {
	if err := checkEnvName("env", from); err != nil {
		return err
	}
	if err := checkEnvName("new env", to); err != nil {
		return err
	}
	if from == to {
		return errors.New("the new name is the same")
	}
	list := currentEnvs(root)
	if slices.Contains(list, to) {
		return fmt.Errorf("environment %q is already in envs", to)
	}
	if old := legacyBlock(root); old != nil && (mapIndex(old, string(from)) >= 0 || mapIndex(old, string(to)) >= 0) {
		if err := migrateEnvironments(root); err != nil {
			return err
		}
	}
	block := mapIndex(root, whenKey(from))
	if mapIndex(root, whenKey(to)) >= 0 {
		return fmt.Errorf("environment %q already has its own differences; remove them first", to)
	}
	var names []*yaml.Node // every scalar that names the environment outside envs
	if seq := mapGet(root, "lockfiles"); seq != nil && seq.Kind == yaml.SequenceNode {
		for _, it := range seq.Content {
			if it.Kind == yaml.MappingNode && lockfileField(it, "env") == string(from) {
				names = append(names, mapGet(it, "env"))
			}
		}
	}
	if seq := mapGet(root, "techs"); seq != nil && seq.Kind == yaml.SequenceNode {
		for _, it := range seq.Content {
			if scope := mapGetIfMap(it, "envs"); scope != nil && scope.Kind == yaml.SequenceNode {
				for _, n := range scope.Content {
					if n.Value == string(from) {
						names = append(names, n)
					}
				}
			}
		}
	}
	inList := slices.Contains(list, from)
	if !inList && block < 0 && len(names) == 0 {
		return fmt.Errorf("environment %q is not used by the project", from)
	}
	if inList {
		list[slices.Index(list, from)] = to
		if err := setEnvs(root, list); err != nil {
			return err
		}
	}
	if block >= 0 {
		root.Content[block].Value = whenKey(to)
	}
	for _, n := range names {
		n.Value = string(to)
	}
	return nil
}

func mapGetIfMap(n *yaml.Node, key string) *yaml.Node {
	if n.Kind != yaml.MappingNode {
		return nil
	}
	return mapGet(n, key)
}

// EnvHint is a note about the environments of a project. Level is info or warn.
type EnvHint struct {
	Level   string
	Field   string
	Message string
	Fix     []Op // the edits that apply the advice, none when there is nothing to apply
}

// EnvHints says what is worth knowing about the environments of a project:
// that the file relies on the old default, or that nothing is called prod.
func EnvHints(p model.Project) []EnvHint {
	var out []EnvHint
	if slices.ContainsFunc(slices.Collect(maps.Values(p.Environments)), func(c model.EnvConfig) bool { return c.Old }) {
		out = append(out, EnvHint{Level: "info", Field: "environments",
			Message: "environments: is the old spelling of the when@<env> blocks (same meaning); migrate_envs rewrites it and changes nothing else",
			Fix:     []Op{{Kind: "migrate_envs"}}})
	}
	if len(p.Envs) == 0 {
		out = append(out, EnvHint{Level: "warn", Field: "envs",
			Message: "envs not set: using the old default " + joinEnvs(model.LegacyEnvs) + "; list your environments (names are free, local is a good start)",
			Fix:     []Op{{Kind: "set_envs", Envs: slices.Clone(model.LegacyEnvs)}}})
		return out
	}
	if !slices.ContainsFunc(p.Envs, model.IsProd) {
		out = append(out, EnvHint{Level: "info", Field: "envs",
			Message: "no prod environment: add prod (and any others) if you deploy there; names are free",
			Fix:     []Op{{Kind: "add_env", Env: model.EnvProd}}})
	}
	return out
}

func joinEnvs(es []model.Env) string {
	s := make([]string, len(es))
	for i, e := range es {
		s[i] = string(e)
	}
	return strings.Join(s, ", ")
}
