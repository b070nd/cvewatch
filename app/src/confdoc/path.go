package confdoc

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// ParsePath splits a field path into segments. Segments are separated by
// dots; a segment that holds a dot (a host name, an actor) is written in
// brackets: http.host_rates[services.nvd.nist.gov]. In a list, a segment is a
// position (0), or key=value to pick the item whose key has that value
// ([name=php]), or =value for an item that is itself that value.
func ParsePath(p string) ([]string, error) {
	var segs []string
	for i := 0; i < len(p); {
		switch p[i] {
		case '.':
			i++
			if i == len(p) {
				return nil, errors.New("path ends with a dot")
			}
			if p[i] == '.' || len(segs) == 0 {
				return nil, fmt.Errorf("path %q has an empty segment", p)
			}
			continue
		case '[':
			end := -1
			for j := i + 1; j < len(p); j++ {
				if p[j] == ']' && (j+1 == len(p) || p[j+1] == '.' || p[j+1] == '[') {
					end = j
					break
				}
			}
			if end < 0 {
				return nil, fmt.Errorf("path %q: unclosed bracket", p)
			}
			segs = append(segs, p[i+1:end])
			i = end + 1
		default:
			j := i
			for j < len(p) && p[j] != '.' && p[j] != '[' {
				j++
			}
			segs = append(segs, p[i:j])
			i = j
		}
		if len(segs[len(segs)-1]) == 0 {
			return nil, fmt.Errorf("path %q has an empty segment", p)
		}
	}
	return segs, nil
}

// FormatPath is the inverse of ParsePath.
func FormatPath(segs []string) string {
	out := make([]string, len(segs))
	for i, s := range segs {
		if strings.ContainsAny(s, ".[]=") {
			s = "[" + s + "]"
		}
		out[i] = s
	}
	return strings.Join(out, ".")
}

// ---- node access ----

func mapIndex(m *yaml.Node, key string) int {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return i
		}
	}
	return -1
}

// step finds the child a segment names. pos is its index in n.Content; for a
// mapping that is the index of the value (the key sits before it).
func step(n *yaml.Node, seg string) (child *yaml.Node, pos int) {
	switch n.Kind {
	case yaml.MappingNode:
		if i := mapIndex(n, seg); i >= 0 {
			return n.Content[i+1], i + 1
		}
	case yaml.SequenceNode:
		if i, err := strconv.Atoi(seg); err == nil {
			if i >= 0 && i < len(n.Content) {
				return n.Content[i], i
			}
			return nil, -1
		}
		key, want, ok := strings.Cut(seg, "=")
		if !ok {
			return nil, -1
		}
		for i, it := range n.Content {
			switch {
			case key == "" && it.Kind == yaml.ScalarNode && it.Value == want:
				return it, i
			case key != "" && it.Kind == yaml.MappingNode:
				if j := mapIndex(it, key); j >= 0 && strings.EqualFold(it.Content[j+1].Value, want) {
					return it, i
				}
			}
		}
	}
	return nil, -1
}

// isEmptyValue reports a key with nothing after it (`access:`).
func isEmptyValue(n *yaml.Node) bool {
	return n.Kind == yaml.ScalarNode && n.Tag == "!!null"
}

// dropAt removes the child at pos from n. A comment under a removed list item
// (such as a commented-out neighbour) moves to the item above, like projectfile does.
func dropAt(n *yaml.Node, pos int) {
	if n.Kind == yaml.MappingNode {
		n.Content = append(n.Content[:pos-1], n.Content[pos+1:]...)
		return
	}
	if foot := n.Content[pos].FootComment; foot != "" && pos > 0 {
		prev := n.Content[pos-1]
		prev.FootComment = strings.TrimSpace(prev.FootComment + "\n" + foot)
	}
	n.Content = append(n.Content[:pos], n.Content[pos+1:]...)
}
