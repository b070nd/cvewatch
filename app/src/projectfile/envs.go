package projectfile

import (
	"errors"
	"fmt"
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

// removeEnv drops the name from envs only; versions and lockfiles that name it stay, and the check warns about them.
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
	return setEnvs(root, slices.Delete(list, i, i+1))
}

// renameEnv renames the name in envs, the environments key and the lockfile envs.
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
	environments := mapGet(root, "environments")
	var block *yaml.Node
	if environments != nil && environments.Kind == yaml.MappingNode {
		if i := mapIndex(environments, string(from)); i >= 0 {
			block = environments.Content[i]
		}
		if mapIndex(environments, string(to)) >= 0 {
			return fmt.Errorf("environment %q already has its own versions; remove them first", to)
		}
	}
	var locks []*yaml.Node
	if seq := mapGet(root, "lockfiles"); seq != nil && seq.Kind == yaml.SequenceNode {
		for _, it := range seq.Content {
			if it.Kind == yaml.MappingNode && lockfileField(it, "env") == string(from) {
				locks = append(locks, it)
			}
		}
	}
	inList := slices.Contains(list, from)
	if !inList && block == nil && len(locks) == 0 {
		return fmt.Errorf("environment %q is not used by the project", from)
	}
	if inList {
		list[slices.Index(list, from)] = to
		if err := setEnvs(root, list); err != nil {
			return err
		}
	}
	if block != nil {
		block.Value = string(to)
	}
	for _, it := range locks {
		mapGet(it, "env").Value = string(to)
	}
	return nil
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
