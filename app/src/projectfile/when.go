package projectfile

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/b070nd/cvewatch/app/src/model"
)

// whenKey is the top-level key of the differences of one environment.
func whenKey(env model.Env) string { return model.WhenPrefix + string(env) }

// envField is how validation names the differences of an environment: the
// key the file uses for them.
func envField(p model.Project, env model.Env) string {
	if p.Environments[env].Old {
		return "environments." + string(env)
	}
	return whenKey(env)
}

func legacyBlock(root *yaml.Node) *yaml.Node {
	if n := mapGet(root, "environments"); n != nil && n.Kind == yaml.MappingNode {
		return n
	}
	return nil
}

// migrateEnvironments rewrites the old environments: map as one when@<env>
// block per entry, in place and order, keeping comments.
func migrateEnvironments(root *yaml.Node) error {
	i := mapIndex(root, "environments")
	if i < 0 {
		return nil
	}
	old := root.Content[i+1]
	if old.Kind != yaml.MappingNode && !(old.Kind == yaml.ScalarNode && old.Tag == "!!null") {
		return errors.New("environments must be a mapping")
	}
	var moved []*yaml.Node
	for j := 0; j+1 < len(old.Content); j += 2 {
		k, v := *old.Content[j], old.Content[j+1]
		if mapIndex(root, whenKey(model.Env(k.Value))) >= 0 {
			return fmt.Errorf("%s exists already; merge it with environments.%s first", whenKey(model.Env(k.Value)), k.Value)
		}
		k.Value, k.Tag, k.Style = model.WhenPrefix+k.Value, "!!str", 0
		moved = append(moved, &k, v)
	}
	if len(moved) > 0 {
		key := root.Content[i]
		moved[0].HeadComment = strings.TrimSpace(strings.Join([]string{key.HeadComment, key.LineComment, moved[0].HeadComment}, "\n"))
	}
	rest := append(append([]*yaml.Node{}, moved...), root.Content[i+2:]...)
	root.Content = append(root.Content[:i], rest...)
	return nil
}

// whenBlock is the block of env, created if missing; it migrates the old map first.
func whenBlock(root *yaml.Node, env model.Env) (*yaml.Node, error) {
	if err := migrateEnvironments(root); err != nil {
		return nil, err
	}
	b, err := child(root, whenKey(env), yaml.MappingNode, false)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", whenKey(env), err)
	}
	return b, nil
}

var blockKeys = []string{"techs", "exclude", "image"}

// blockChild is child for a when@ block key; a new one goes in the order techs, exclude, image.
func blockChild(block *yaml.Node, key string, kind yaml.Kind) (*yaml.Node, error) {
	if mapGet(block, key) != nil {
		return child(block, key, kind, true)
	}
	at := len(block.Content)
	for i := 0; i+1 < len(block.Content); i += 2 {
		if slices.Index(blockKeys, block.Content[i].Value) > slices.Index(blockKeys, key) {
			at = i
			break
		}
	}
	tag := "!!map"
	if kind == yaml.SequenceNode {
		tag = "!!seq"
	}
	v := &yaml.Node{Kind: kind, Tag: tag, Style: yaml.FlowStyle}
	block.Content = append(block.Content[:at], append([]*yaml.Node{str(key, 0), v}, block.Content[at:]...)...)
	return v, nil
}

func setEnvTech(root *yaml.Node, env model.Env, tech, version string) error {
	block, err := whenBlock(root, env)
	if err != nil {
		return err
	}
	techs, err := blockChild(block, "techs", yaml.MappingNode)
	if err != nil {
		return fmt.Errorf("%s.techs: %w", whenKey(env), err)
	}
	if i := keyIndexFold(techs, tech); i >= 0 {
		setStr(techs, techs.Content[i].Value, version, yaml.DoubleQuotedStyle)
		return nil
	}
	mapAppend(techs, tech, str(version, yaml.DoubleQuotedStyle))
	return nil
}

func removeEnvTech(root *yaml.Node, env model.Env, tech string) error {
	if tech == "" {
		return errors.New("tech name is empty")
	}
	if err := migrateEnvironments(root); err != nil {
		return err
	}
	keys := []string{whenKey(env), "techs"}
	chain, err := dig(root, keys...)
	if err != nil {
		return err
	}
	if len(chain) <= len(keys) {
		return fmt.Errorf("%s.techs.%s is not set", whenKey(env), tech)
	}
	techs := chain[len(chain)-1]
	i := keyIndexFold(techs, tech)
	if i < 0 {
		return fmt.Errorf("%s.techs.%s is not set", whenKey(env), tech)
	}
	techs.Content = append(techs.Content[:i], techs.Content[i+2:]...)
	prune(chain, keys)
	return nil
}

func setImage(root *yaml.Node, env model.Env, image string) error {
	if image == "" { // an empty image clears it
		if err := migrateEnvironments(root); err != nil {
			return err
		}
		keys := []string{whenKey(env)}
		chain, err := dig(root, keys...)
		if err != nil || len(chain) <= len(keys) {
			return err
		}
		mapDel(chain[len(chain)-1], "image")
		prune(chain, keys)
		return nil
	}
	block, err := whenBlock(root, env)
	if err != nil {
		return err
	}
	setStr(block, "image", image, 0)
	return nil
}

func seqIndexFold(seq *yaml.Node, name string) int {
	for i, it := range seq.Content {
		if it.Kind == yaml.ScalarNode && strings.EqualFold(it.Value, name) {
			return i
		}
	}
	return -1
}

func excludeEnvTech(root *yaml.Node, env model.Env, tech string) error {
	block, err := whenBlock(root, env)
	if err != nil {
		return err
	}
	seq, err := blockChild(block, "exclude", yaml.SequenceNode)
	if err != nil {
		return fmt.Errorf("%s.exclude: %w", whenKey(env), err)
	}
	if seqIndexFold(seq, tech) < 0 {
		seq.Content = append(seq.Content, str(tech, 0))
	}
	return nil
}

func includeEnvTech(root *yaml.Node, env model.Env, tech string) error {
	if err := migrateEnvironments(root); err != nil {
		return err
	}
	chain, err := dig(root, whenKey(env))
	if err != nil {
		return err
	}
	var seq *yaml.Node
	if len(chain) > 1 {
		seq = mapGet(chain[1], "exclude")
	}
	if seq == nil || seq.Kind != yaml.SequenceNode || seqIndexFold(seq, tech) < 0 {
		return fmt.Errorf("%s.exclude does not list %s", whenKey(env), tech)
	}
	dropItem(seq, seqIndexFold(seq, tech))
	if len(seq.Content) == 0 {
		mapDel(chain[1], "exclude")
	}
	prune(chain, []string{whenKey(env)})
	return nil
}

// setTechEnvs limits a declared tech to the environments listed; none lifts the limit.
func setTechEnvs(root *yaml.Node, tech string, envs []model.Env) error {
	techs := mapGet(root, "techs")
	if techs == nil || techs.Kind != yaml.SequenceNode || techIndex(techs, tech) < 0 {
		return fmt.Errorf("tech %q is not in the project", tech)
	}
	var items []*yaml.Node
	seen := map[model.Env]bool{}
	for _, e := range envs {
		if err := checkEnvName("env", e); err != nil {
			return err
		}
		if !seen[e] {
			seen[e] = true
			items = append(items, str(string(e), 0))
		}
	}
	item := techs.Content[techIndex(techs, tech)]
	switch cur := mapGet(item, "envs"); {
	case len(items) == 0:
		mapDel(item, "envs")
	case cur != nil && cur.Kind == yaml.SequenceNode:
		cur.Content = items // keeps the user's style and comments
	case cur != nil:
		item.Content[mapIndex(item, "envs")+1] = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Style: yaml.FlowStyle, Content: items}
	default:
		mapAppend(item, "envs", &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Style: yaml.FlowStyle, Content: items})
	}
	return nil
}
