package confdoc

import (
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/b070nd/cvewatch/app/src/projectfile"
)

// SecretShown is what a secret value is replaced with wherever the document is displayed.
const (
	SecretShown   = "(set)"
	secretChanged = "(set, changed)"
)

// Entry is one value of a document, flattened for display. A secret has its
// value replaced by "(set)".
type Entry struct {
	Path   string   `json:"path"`
	Value  string   `json:"value,omitempty"`
	Items  []string `json:"items,omitempty"` // for a list of plain values
	Secret bool     `json:"secret,omitempty"`
}

type leaf struct {
	segs   []string
	node   *yaml.Node // a scalar, or a sequence of scalars
	secret bool
}

// leaves lists the plain values of the document: scalars, and lists made only
// of scalars. List items that are mappings are named by their key when the
// schema gives the list one (techs.[name=php].title), else by position.
func (d *Document) leaves() []leaf {
	if d.node == nil {
		return nil
	}
	var out []leaf
	var walk func(n *yaml.Node, segs []string)
	walk = func(n *yaml.Node, segs []string) {
		switch n.Kind {
		case yaml.MappingNode:
			for i := 0; i+1 < len(n.Content); i += 2 {
				walk(n.Content[i+1], append(append([]string{}, segs...), n.Content[i].Value))
			}
		case yaml.SequenceNode:
			plain := len(n.Content) > 0
			for _, it := range n.Content {
				plain = plain && it.Kind == yaml.ScalarNode
			}
			if plain {
				out = append(out, leaf{segs: segs, node: n, secret: isSecret(d.Kind, segs)})
				return
			}
			key := ""
			if f, ok := lookup(d.Kind, segs); ok {
				key = f.Key
			}
			for i, it := range n.Content {
				seg := strconv.Itoa(i)
				if key != "" && it.Kind == yaml.MappingNode {
					if j := mapIndex(it, key); j >= 0 && it.Content[j+1].Value != "" {
						seg = key + "=" + it.Content[j+1].Value
					}
				}
				walk(it, append(append([]string{}, segs...), seg))
			}
		case yaml.ScalarNode:
			if n.Tag != "!!null" {
				out = append(out, leaf{segs: segs, node: n, secret: isSecret(d.Kind, segs)})
			}
		}
	}
	walk(d.node.Content[0], nil)
	return out
}

// isSecret says whether the value at segs, or a collection above it, is marked secret.
func isSecret(kind string, segs []string) bool {
	for k := len(segs); k >= 1; k-- {
		if f, ok := lookup(kind, segs[:k]); ok && f.Secret {
			return true
		}
	}
	return false
}

// Entries flattens the document for display; secret values are not included.
func (d *Document) Entries() []Entry {
	var out []Entry
	for _, l := range d.leaves() {
		e := Entry{Path: FormatPath(l.segs), Secret: l.secret}
		switch {
		case l.node.Kind == yaml.SequenceNode:
			for _, it := range l.node.Content {
				e.Items = append(e.Items, shown(it.Value, l.secret))
			}
		default:
			e.Value = shown(l.node.Value, l.secret)
		}
		out = append(out, e)
	}
	return out
}

func shown(v string, secret bool) string {
	if secret {
		return SecretShown
	}
	return v
}

// Text is the document as text for display, with secret values hidden.
func (d *Document) Text() string {
	if len(d.secrets()) == 0 {
		return d.src
	}
	return projectfile.RestoreLayout(d.src, d.hidden(nil))
}

// hidden encodes the document with its secrets replaced. other, when given,
// holds the secret values of the document it is compared against, so a secret
// that changed reads differently from one that stayed.
func (d *Document) hidden(other map[string]string) string {
	if d.node == nil {
		return ""
	}
	node := cloneNode(d.node)
	for _, l := range (&Document{Kind: d.Kind, node: node}).leaves() {
		if !l.secret {
			continue
		}
		show := SecretShown
		if prev, ok := other[FormatPath(l.segs)]; ok && prev != secretKey(l) {
			show = secretChanged
		}
		setShown(l.node, show)
	}
	out, _ := encode(node)
	return out
}

func setShown(n *yaml.Node, show string) {
	if n.Kind == yaml.SequenceNode {
		for _, it := range n.Content {
			setShown(it, show)
		}
		return
	}
	n.Tag, n.Value, n.Style = "!!str", show, 0
}

func secretKey(l leaf) string {
	if l.node.Kind == yaml.SequenceNode {
		var vs []string
		for _, it := range l.node.Content {
			vs = append(vs, it.Value)
		}
		return strings.Join(vs, "\x00")
	}
	return l.node.Value
}

func (d *Document) secrets() map[string]string {
	out := map[string]string{}
	for _, l := range d.leaves() {
		if l.secret {
			out[FormatPath(l.segs)] = secretKey(l)
		}
	}
	return out
}

// DocDiff is the change to one document.
type DocDiff struct {
	Doc     string `json:"doc"`
	Path    string `json:"path"`
	Created bool   `json:"created"`
	Diff    string `json:"diff"`
}

// Diff renders what the changed documents of after differ from before. Secret
// values never appear; one that changed shows as "(set, changed)".
func Diff(before, after *Set) []DocDiff {
	var out []DocDiff
	for _, d := range after.Changed() {
		prev := before.Doc(d.ID)
		if prev == nil {
			prev = &Document{ID: d.ID, Kind: d.Kind}
		}
		pb, _ := prev.Bytes()
		nb, _ := d.Bytes()
		dd := DocDiff{Doc: d.ID, Path: d.Path, Created: !d.Exists}
		if len(prev.secrets()) == 0 && len(d.secrets()) == 0 {
			dd.Diff = projectfile.Diff(pb, nb)
		} else {
			// Both sides come from the encoder, so untouched lines match exactly and
			// only real changes show.
			a := prev.hidden(nil)
			dd.Diff = projectfile.Diff([]byte(a), []byte(projectfile.RestoreLayout(a, d.hidden(prev.secrets()))))
		}
		out = append(out, dd)
	}
	return out
}
