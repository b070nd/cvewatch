package confdoc

import (
	"fmt"
	"reflect"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/b070nd/cvewatch/app/src/config"
)

const distHeader = `# cvewatch settings: shared defaults (config.yaml.dist).
#
# Every setting is listed with its help and its default, commented out.
# Uncomment a line to make it the default for everyone who uses this folder.
# config.yaml next to this file overrides any key for one person, and the TUI,
# the MCP tools and the CLI write their changes there, never here.
# A value or a list in config.yaml replaces the one here as a whole; a map,
# such as access, is merged by key.
`

// DistSettings is config.yaml.dist as cvewatch writes it: every setting of
// config.yaml, nested as in the file, each with its help and its default,
// all commented out so the file sets nothing until someone uncomments a line.
func DistSettings() []byte {
	root := &distNode{}
	for _, f := range fieldList() {
		if f.Doc != KindSettings || strings.Contains(f.Path, "*") {
			continue
		}
		root.add(strings.Split(f.Path, "."), f)
	}
	var b strings.Builder
	b.WriteString(distHeader)
	defaults := reflect.ValueOf(config.Defaults())
	for _, n := range root.kids {
		b.WriteString("\n")
		n.write(&b, 0, defaults)
	}
	return []byte(b.String())
}

// distNode is one key of the nested file: a setting, or a mapping of settings.
type distNode struct {
	key   string
	field *Field
	kids  []*distNode
}

func (n *distNode) add(segs []string, f Field) {
	for _, k := range n.kids {
		if k.key == segs[0] {
			if len(segs) == 1 {
				k.field = &f
			} else {
				k.add(segs[1:], f)
			}
			return
		}
	}
	k := &distNode{key: segs[0]}
	n.kids = append(n.kids, k)
	if len(segs) == 1 {
		k.field = &f
	} else {
		k.add(segs[1:], f)
	}
}

func (n *distNode) write(b *strings.Builder, depth int, defaults reflect.Value) {
	pad := strings.Repeat("  ", depth)
	if n.field == nil {
		fmt.Fprintf(b, "# %s%s:\n", pad, n.key)
		for _, k := range n.kids {
			k.write(b, depth+1, defaults)
		}
		return
	}
	f := *n.field
	help := f.Label
	if f.Help != "" {
		help += ": " + f.Help
	}
	if len(f.Enum) > 0 {
		if !strings.HasSuffix(help, ".") {
			help += "."
		}
		help += " One of: " + strings.Join(f.Enum, ", ") + "."
	}
	for _, line := range wrap(help, 76-len(pad)) {
		if depth == 0 {
			fmt.Fprintf(b, "# %s\n", line)
		} else {
			fmt.Fprintf(b, "# %s# %s\n", pad, line)
		}
	}
	for _, rec := range recordKeys(f) {
		for i, line := range wrap(rec, 72-len(pad)) {
			lead := "- "
			if i > 0 {
				lead = "  "
			}
			if depth == 0 {
				fmt.Fprintf(b, "#   %s%s\n", lead, line)
			} else {
				fmt.Fprintf(b, "# %s#   %s%s\n", pad, lead, line)
			}
		}
	}
	fmt.Fprintf(b, "# %s%s: %s\n", pad, n.key, distValue(f, defaults))
}

// recordKeys describes the keys of each entry of a list or map of records.
func recordKeys(coll Field) []string {
	if coll.Elem != TypeRecord {
		return nil
	}
	var out []string
	prefix := coll.Path + ".*."
	for _, f := range fieldList() {
		if f.Doc == coll.Doc && strings.HasPrefix(f.Path, prefix) && !strings.Contains(f.Path[len(prefix):], ".") {
			line := f.Path[len(prefix):]
			if f.Help != "" {
				line += ": " + f.Help
			}
			out = append(out, line)
		}
	}
	return out
}

// distValue is the default of a setting written as YAML.
func distValue(f Field, defaults reflect.Value) string {
	v, ok := valueAt(defaults, strings.Split(f.Path, "."))
	if !ok || v.IsZero() {
		switch {
		case f.Type == TypeList:
			return "[]"
		case f.Type == TypeMap:
			return "{}"
		case f.Default != "":
			return scalar(f.Default)
		case len(f.Enum) > 0:
			return scalar(f.Enum[0])
		case f.Type == TypeBool:
			return "false"
		case f.Type == TypeDuration:
			return "0s"
		case f.Type == TypeInt, f.Type == TypeFloat:
			return "0"
		}
		return `""`
	}
	if d, ok := v.Interface().(time.Duration); ok {
		return formatDuration(d)
	}
	switch v.Kind() {
	case reflect.String:
		return scalar(v.String())
	case reflect.Map, reflect.Slice:
		out, err := yaml.Marshal(v.Interface())
		if err != nil {
			return "{}"
		}
		var n yaml.Node
		if yaml.Unmarshal(out, &n) == nil && len(n.Content) > 0 {
			n.Content[0].Style = yaml.FlowStyle
			if flow, err := yaml.Marshal(n.Content[0]); err == nil {
				return strings.TrimSpace(string(flow))
			}
		}
		return strings.TrimSpace(string(out))
	}
	return fmt.Sprint(v.Interface())
}

func scalar(s string) string {
	out, err := yaml.Marshal(s)
	if err != nil {
		return fmt.Sprintf("%q", s)
	}
	return strings.TrimSpace(string(out))
}

func valueAt(v reflect.Value, segs []string) (reflect.Value, bool) {
	for _, seg := range segs {
		if v.Kind() != reflect.Struct {
			return v, false
		}
		found := false
		for i := 0; i < v.NumField(); i++ {
			if yamlName(v.Type().Field(i)) == seg {
				v, found = v.Field(i), true
				break
			}
		}
		if !found {
			return v, false
		}
	}
	return v, true
}

// wrap breaks text into lines of at most width runes, at spaces.
func wrap(text string, width int) []string {
	var lines []string
	line := ""
	for _, w := range strings.Fields(text) {
		if line != "" && len([]rune(line))+1+len([]rune(w)) > width {
			lines = append(lines, line)
			line = w
			continue
		}
		if line != "" {
			line += " "
		}
		line += w
	}
	if line != "" {
		lines = append(lines, line)
	}
	return lines
}
