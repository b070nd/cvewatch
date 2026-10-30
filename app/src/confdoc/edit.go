package confdoc

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Op is what an Edit does.
type Op string

const (
	// OpSet gives a path a value, creating the keys on the way. For a map it
	// adds or changes the entry; for a list item it replaces the item.
	OpSet Op = "set"
	// OpUnset removes a key, a map entry or a list item. Mappings left empty are removed too.
	OpUnset Op = "unset"
	// OpAppend adds an item to a list, creating the list if needed.
	OpAppend Op = "append"
	// OpReplace swaps the text of a whole document; it is the way to repair a
	// document whose YAML does not parse.
	OpReplace Op = "replace"
)

// Edit is one change to one document. Value is a string, bool, number, a list
// or a map; strings are converted to the type the schema gives the path, so a
// text field can pass "30s" or "true" straight through.
type Edit struct {
	// Doc is the document ID. Empty means the document the schema assigns the
	// path to; for feeds that is the file that already holds the feed, else sources/custom.
	Doc   string `json:"doc,omitempty"`
	Op    Op     `json:"op"`
	Path  string `json:"path,omitempty"`
	Value any    `json:"value,omitempty"`
}

// EditError says which edit failed and why. Nothing is changed when one does.
type EditError struct {
	Index int
	Edit  Edit
	Err   error
}

func (e *EditError) Error() string {
	if e.Edit.Path == "" {
		return fmt.Sprintf("%s %s: %v", e.Edit.Op, e.Edit.Doc, e.Err)
	}
	return fmt.Sprintf("%s %s: %v", e.Edit.Op, e.Edit.Path, e.Err)
}
func (e *EditError) Unwrap() error { return e.Err }

// With returns a copy of the set with the edits applied in order; the receiver
// is untouched. If one fails nothing is returned.
func (s *Set) With(edits ...Edit) (*Set, error) {
	c := s.clone()
	for i, e := range edits {
		if err := c.apply(e); err != nil {
			return nil, &EditError{Index: i, Edit: e, Err: err}
		}
	}
	return c, nil
}

func (s *Set) apply(e Edit) error {
	if e.Op == OpReplace {
		return s.applyReplace(e)
	}
	segs, err := ParsePath(e.Path)
	if err != nil {
		return err
	}
	if len(segs) == 0 {
		return errors.New("a path is required")
	}
	doc, err := s.target(e, segs)
	if err != nil {
		return err
	}
	if doc.ReadOnly {
		return fmt.Errorf("%s is built in and cannot be changed; add an entry to your own file instead", doc.ID)
	}
	if _, ok := fieldFor(doc.Kind, segs); !ok && e.Op != OpUnset { // a stray key can still be removed
		return fmt.Errorf("unknown setting %q", e.Path)
	}
	root, err := doc.rootNode()
	if err != nil {
		return err
	}
	switch e.Op {
	case OpSet:
		if e.Value == nil {
			return errors.New("a value is required (use unset to remove)")
		}
		err = setPath(doc, root, segs, e.Value)
	case OpUnset:
		err = unsetPath(root, segs)
	case OpAppend:
		err = appendPath(doc, root, segs, e.Value)
	default:
		return fmt.Errorf("unknown op %q (use set, unset, append or replace)", e.Op)
	}
	if err != nil {
		return err
	}
	doc.dirty, doc.fresh = true, nil
	return nil
}

func (s *Set) applyReplace(e Edit) error {
	text, ok := e.Value.(string)
	if !ok {
		return errors.New("replace needs the new text as its value")
	}
	doc := s.Doc(e.Doc)
	if doc == nil {
		var err error
		if doc, err = s.create(e.Doc); err != nil {
			return err
		}
	}
	if doc.ReadOnly {
		return fmt.Errorf("%s is built in and cannot be changed", doc.ID)
	}
	doc.replace(text)
	return nil
}

// target picks the document an edit changes.
func (s *Set) target(e Edit, segs []string) (*Document, error) {
	id := e.Doc
	if id == "" {
		kind := ""
		for _, f := range fieldList() {
			pat := strings.Split(f.Path, ".")
			n := min(len(pat), len(segs))
			if matches(pat[:n], segs[:n]) {
				kind = f.Doc
				break
			}
		}
		switch kind {
		case KindSettings:
			id = IDSettings
		case KindTechs:
			id = IDTechs
		case KindSources:
			id = sourcesPrefix + "custom"
			if len(segs) > 1 { // an existing feed is edited where it lives
				for _, d := range s.Docs {
					if d.Kind == KindSources && d.Layer == LayerUser && d.node != nil {
						if root := d.node.Content[0]; hasPath(root, segs[:2]) {
							id = d.ID
							break
						}
					}
				}
			}
		default:
			if e.Op != OpUnset {
				return nil, fmt.Errorf("unknown setting %q", strings.Join(segs, "."))
			}
			id = IDSettings // a stray key is most likely in config.yaml; name the document to remove one elsewhere
		}
	}
	if d := s.Doc(id); d != nil {
		return d, nil
	}
	return s.create(id)
}

func hasPath(root *yaml.Node, segs []string) bool {
	n := root
	for _, seg := range segs {
		if n = childOrNil(n, seg); n == nil {
			return false
		}
	}
	return true
}

func childOrNil(n *yaml.Node, seg string) *yaml.Node {
	c, _ := step(n, seg)
	return c
}

// elementOf finds what a path inside a list or map of values is: the item of
// a collection that has no row of its own (techs.[name=php], access.alice,
// http.host_rates[example.com]).
func elementOf(kind string, segs []string) (Field, bool) {
	if len(segs) < 2 {
		return Field{}, false
	}
	c, ok := lookup(kind, segs[:len(segs)-1])
	if !ok || (c.Type != TypeList && c.Type != TypeMap) || c.Elem == "" {
		return Field{}, false
	}
	return elemField(kind, c), true
}

// elemField is the field of one item of a list or map field.
func elemField(kind string, coll Field) Field {
	return Field{Path: coll.Path + ".*", Doc: kind, Type: coll.Elem, Enum: coll.Enum, Min: coll.Min, Max: coll.Max, Key: coll.Key}
}

// ---- values ----

var envRefRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// fieldFor is the schema view of a path: its row, or the element of the
// collection when the path names one item.
func fieldFor(kind string, segs []string) (Field, bool) {
	if f, ok := lookup(kind, segs); ok {
		return f, true
	}
	return elementOf(kind, segs)
}

// coerce converts v to the Go value the field's type calls for and checks it.
// pattern is the schema path of the field, used for the keys of a record.
func coerce(kind string, f Field, t Type, v any) (any, error) {
	switch t {
	case TypeBool:
		switch x := v.(type) {
		case bool:
			return x, nil
		case string:
			switch strings.ToLower(strings.TrimSpace(x)) {
			case "true", "yes", "on", "1":
				return true, nil
			case "false", "no", "off", "0":
				return false, nil
			}
		}
		return nil, errors.New("must be true or false")
	case TypeInt:
		n, err := toFloat(v)
		if err != nil || n != math.Trunc(n) {
			return nil, errors.New("must be a whole number")
		}
		if err := inRange(f, n, "must be"); err != nil {
			return nil, err
		}
		return int64(n), nil
	case TypeFloat:
		n, err := toFloat(v)
		if err != nil {
			return nil, errors.New("must be a number")
		}
		if err := inRange(f, n, "must be"); err != nil {
			return nil, err
		}
		return n, nil
	case TypeDuration:
		return coerceDuration(f, v)
	case TypeEnum:
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("must be one of %s", strings.Join(f.Enum, ", "))
		}
		s = strings.TrimSpace(s)
		for _, e := range f.Enum {
			if strings.EqualFold(e, s) {
				return e, nil
			}
		}
		return nil, fmt.Errorf("%q is not one of %s", s, strings.Join(f.Enum, ", "))
	case TypeEnvRef:
		s, ok := v.(string)
		if !ok || !envRefRE.MatchString(strings.TrimSpace(s)) {
			return nil, errors.New("must be the name of an environment variable (letters, digits, underscore), not its value")
		}
		return strings.TrimSpace(s), nil
	case TypeString:
		switch x := v.(type) {
		case string:
			return x, nil
		case bool, int, int64, float64:
			return fmt.Sprint(x), nil
		}
		return nil, errors.New("must be text")
	case TypeList:
		var items []any
		switch x := v.(type) {
		case string:
			for _, p := range strings.Split(x, ",") {
				if p = strings.TrimSpace(p); p != "" {
					items = append(items, p)
				}
			}
		case []string:
			for _, p := range x {
				items = append(items, p)
			}
		case []any:
			items = x
		default:
			return nil, errors.New("must be a list")
		}
		out := make([]any, 0, len(items))
		for i, it := range items {
			c, err := coerceItem(kind, f, it)
			if err != nil {
				return nil, fmt.Errorf("item %d: %w", i+1, err)
			}
			out = append(out, c)
		}
		return out, nil
	case TypeMap:
		m, ok := v.(map[string]any)
		if !ok {
			if ms, isStr := v.(map[string]string); isStr {
				m, ok = map[string]any{}, true
				for k, s := range ms {
					m[k] = s
				}
			}
		}
		if !ok {
			return nil, errors.New("must be a mapping")
		}
		out := map[string]any{}
		for k, it := range m {
			c, err := coerceItem(kind, f, it)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", k, err)
			}
			out[k] = c
		}
		return out, nil
	case TypeRecord:
		m, ok := v.(map[string]any)
		if !ok {
			return nil, errors.New("must be a mapping")
		}
		out := map[string]any{}
		for k, it := range m {
			child, ok := childField(kind, f, k)
			if !ok {
				return nil, fmt.Errorf("unknown key %q", k)
			}
			c, err := coerce(kind, child, child.Type, it)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", k, err)
			}
			out[k] = c
		}
		return out, nil
	}
	return nil, fmt.Errorf("unsupported type %q", t)
}

// coerceItem converts one list item or map value of a collection field.
func coerceItem(kind string, coll Field, v any) (any, error) {
	item := elemField(kind, coll)
	return coerce(kind, item, item.Type, v)
}

// childField is the field of key k inside a record. A nested struct (detect)
// has no row of its own, only the rows of its keys.
func childField(kind string, rec Field, k string) (Field, bool) {
	path := rec.Path + "." + k
	if f, ok := lookupPattern(kind, path); ok {
		return f, true
	}
	for _, f := range fieldList() {
		if f.Doc == kind && strings.HasPrefix(f.Path, path+".") {
			return Field{Path: path, Doc: kind, Type: TypeRecord}, true
		}
	}
	return Field{}, false
}

func lookupPattern(kind, pattern string) (Field, bool) {
	for _, f := range fieldList() {
		if f.Doc == kind && f.Path == pattern {
			return f, true
		}
	}
	return Field{}, false
}

func toFloat(v any) (float64, error) {
	switch x := v.(type) {
	case float64:
		return x, nil
	case float32:
		return float64(x), nil
	case int:
		return float64(x), nil
	case int64:
		return float64(x), nil
	case string:
		return strconv.ParseFloat(strings.TrimSpace(x), 64)
	}
	return 0, errors.New("not a number")
}

func inRange(f Field, n float64, what string) error {
	if f.Min != nil && n < *f.Min {
		return fmt.Errorf("%s at least %g", what, *f.Min)
	}
	if f.Max != nil && n > *f.Max {
		return fmt.Errorf("%s at most %g", what, *f.Max)
	}
	return nil
}

func coerceDuration(f Field, v any) (any, error) {
	var s string
	switch x := v.(type) {
	case string:
		s = strings.TrimSpace(x)
	case float64, int, int64:
		if n, _ := toFloat(x); n == 0 {
			s = "0"
		}
	}
	if s == "" {
		return nil, errors.New("must be a duration such as 30s, 2m or 4h")
	}
	if s == "0" {
		if err := inRange(f, 0, "must be"); err != nil {
			return nil, errors.New("must be longer than zero")
		}
		return int64(0), nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return nil, errors.New("must be a duration such as 30s, 2m or 4h")
	}
	if err := inRange(f, d.Seconds(), "must be"); err != nil {
		return nil, fmt.Errorf("%w seconds", err)
	}
	return s, nil
}

// ---- nodes ----

// scalarNode builds a typed scalar.
func scalarNode(v any) *yaml.Node {
	n := &yaml.Node{}
	if err := n.Encode(v); err != nil {
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: fmt.Sprint(v)}
	}
	return n
}

// buildNode makes the yaml for a coerced value of field f. sibling is an
// existing value next to the new one; a new mapping follows its flow or block style.
func buildNode(kind string, f Field, v any, sibling *yaml.Node) *yaml.Node {
	switch x := v.(type) {
	case []any:
		seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		flat := true
		for _, it := range x {
			c := buildNode(kind, elemField(kind, f), it, sibling)
			flat = flat && c.Kind == yaml.ScalarNode
			seq.Content = append(seq.Content, c)
		}
		if flat {
			seq.Style = yaml.FlowStyle
		}
		return seq
	case map[string]any:
		m := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		if sibling != nil && sibling.Kind == yaml.MappingNode && sibling.Style&yaml.FlowStyle != 0 {
			m.Style = yaml.FlowStyle
		}
		keys := sortedKeys(x)
		if f.Type == TypeRecord {
			order := childOrder(kind, f.Path)
			sort.SliceStable(keys, func(i, j int) bool {
				a, aok := order[keys[i]]
				b, bok := order[keys[j]]
				if aok != bok {
					return aok
				}
				return aok && a < b
			})
		}
		for _, k := range keys {
			child := elemField(kind, f)
			if f.Type == TypeRecord {
				child, _ = childField(kind, f, k)
			}
			m.Content = append(m.Content, scalarNode(k), buildNode(kind, child, x[k], nil))
		}
		return m
	}
	return scalarNode(v)
}

// walkTo follows segs from root and returns the node and its parent chain. A
// missing key is created as a mapping when create is set.
func walk(root *yaml.Node, segs []string, create bool) (chain []*yaml.Node, err error) {
	chain = []*yaml.Node{root}
	for i, seg := range segs {
		cur := chain[len(chain)-1]
		if isEmptyValue(cur) {
			return nil, fmt.Errorf("%s is empty", strings.Join(segs[:i], "."))
		}
		next, _ := step(cur, seg)
		if next == nil {
			if !create || cur.Kind != yaml.MappingNode {
				return chain, fmt.Errorf("%s not found", FormatPath(segs[:i+1]))
			}
			next = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			cur.Content = append(cur.Content, scalarNode(seg), next)
		} else if isEmptyValue(next) && create && i < len(segs)-1 { // `http:` with nothing after it
			next.Kind, next.Tag, next.Value, next.Style = yaml.MappingNode, "!!map", "", 0
		}
		chain = append(chain, next)
	}
	return chain, nil
}

func setPath(doc *Document, root *yaml.Node, segs []string, value any) error {
	f, ok := fieldFor(doc.Kind, segs)
	if !ok {
		return fmt.Errorf("unknown setting %q", FormatPath(segs))
	}
	val, err := coerce(doc.Kind, f, f.Type, value)
	if err != nil {
		return err
	}
	parent, last := segs[:len(segs)-1], segs[len(segs)-1]
	chain, err := walk(root, parent, true)
	if err != nil {
		return err
	}
	p := chain[len(chain)-1]
	if isEmptyValue(p) {
		p.Kind, p.Tag, p.Value, p.Style = yaml.MappingNode, "!!map", "", 0
	}
	cur, _ := step(p, last)
	var sibling *yaml.Node
	if cur != nil {
		sibling = cur
	} else if p.Kind == yaml.MappingNode && len(p.Content) >= 2 {
		sibling = p.Content[len(p.Content)-1]
	}
	node := buildNode(doc.Kind, f, val, sibling)
	switch {
	case cur != nil:
		replaceValue(cur, node)
	case p.Kind == yaml.MappingNode:
		p.Content = append(p.Content, scalarNode(last), node)
	default:
		return fmt.Errorf("%s not found", FormatPath(segs))
	}
	return nil
}

// replaceValue puts node where cur is. A scalar changed to a scalar keeps its
// comments; anything else is replaced and carries the comments over.
func replaceValue(cur, node *yaml.Node) {
	head, line, foot := cur.HeadComment, cur.LineComment, cur.FootComment
	if cur.Kind == yaml.ScalarNode && node.Kind == yaml.ScalarNode {
		cur.Tag, cur.Value, cur.Style = node.Tag, node.Value, node.Style
		return
	}
	*cur = *node
	cur.HeadComment, cur.LineComment, cur.FootComment = head, line, foot
}

func unsetPath(root *yaml.Node, segs []string) error {
	chain, err := walk(root, segs, false)
	if err != nil {
		return err
	}
	parent := chain[len(chain)-2]
	_, pos := step(parent, segs[len(segs)-1])
	dropAt(parent, pos)
	// Mappings and lists left empty go too, except the document's own top-level
	// list (`techs: []`), which stays so the file keeps its shape.
	for i := len(chain) - 2; i >= 1; i-- {
		n := chain[i]
		if len(n.Content) > 0 || (n.Kind == yaml.SequenceNode && i == 1) {
			break
		}
		up := chain[i-1]
		if up.Kind != yaml.MappingNode {
			break
		}
		_, p := step(up, segs[i-1])
		dropAt(up, p)
	}
	return nil
}

func appendPath(doc *Document, root *yaml.Node, segs []string, value any) error {
	f, ok := lookup(doc.Kind, segs)
	if !ok || f.Type != TypeList {
		return fmt.Errorf("%s is not a list", FormatPath(segs))
	}
	item, err := coerceItem(doc.Kind, f, value)
	if err != nil {
		return err
	}
	if _, isList := item.([]any); isList {
		return errors.New("an item cannot itself be a list")
	}
	chain, err := walk(root, segs[:len(segs)-1], true)
	if err != nil {
		return err
	}
	p := chain[len(chain)-1]
	last := segs[len(segs)-1]
	seq, _ := step(p, last)
	switch {
	case seq == nil:
		seq = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		p.Content = append(p.Content, scalarNode(last), seq)
	case isEmptyValue(seq):
		seq.Kind, seq.Tag, seq.Value, seq.Style = yaml.SequenceNode, "!!seq", "", 0
	case seq.Kind != yaml.SequenceNode:
		return fmt.Errorf("%s is not a list in the file", FormatPath(segs))
	}
	if len(seq.Content) == 0 {
		seq.Style = 0
	}
	var sibling *yaml.Node
	if n := len(seq.Content); n > 0 {
		sibling = seq.Content[n-1]
	}
	node := buildNode(doc.Kind, elemField(doc.Kind, f), item, sibling)
	if node.Kind == yaml.ScalarNode {
		for _, it := range seq.Content {
			if it.Kind == yaml.ScalarNode && it.Value == node.Value {
				return nil // already listed
			}
		}
		if len(seq.Content) == 0 || seq.Style&yaml.FlowStyle != 0 {
			seq.Style = yaml.FlowStyle
		}
	} else if f.Key != "" {
		if m, ok := item.(map[string]any); ok {
			if want, _ := m[f.Key].(string); want != "" {
				if c, _ := step(seq, f.Key+"="+want); c != nil {
					return fmt.Errorf("%s %q already exists", f.Key, want)
				}
			}
		}
	}
	seq.Content = append(seq.Content, node)
	return nil
}
