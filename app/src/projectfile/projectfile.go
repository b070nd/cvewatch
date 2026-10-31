// Package projectfile is the one place that creates and edits project YAML
// files. Edits are applied as data to a yaml.Node tree, so the user's comments,
// key order and style survive; callers preview them with Diff and save them
// with Write, which keeps a backup.
package projectfile

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/b070nd/cvewatch/app/src/model"
)

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

func checkName(name string) error {
	if !nameRE.MatchString(name) {
		return fmt.Errorf("projectfile: invalid project name %q (use lowercase letters, digits and dashes, at most 63 characters)", name)
	}
	return nil
}

// File is one project file held as a YAML node tree plus the text it was read from.
type File struct {
	doc *yaml.Node
	src string // the text Parse saw, used to keep the user's spacing and blank lines
}

// New returns a minimal project file for name.
func New(name string) (*File, error) {
	if err := checkName(name); err != nil {
		return nil, err
	}
	return Parse([]byte("# A cvewatch project: what one system runs, so advisories can be matched to it.\n" +
		"name: " + name + "\ntechs: []\nlockfiles: []\n"))
}

// Parse reads a project file. Unknown keys and wrong types are errors, and so
// is an empty document, because the file is meant to hold exactly one project.
func Parse(data []byte) (*File, error) {
	src := strings.ReplaceAll(strings.TrimPrefix(string(data), "\xef\xbb\xbf"), "\r\n", "\n")
	dec := yaml.NewDecoder(strings.NewReader(src))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("projectfile: the file is empty")
		}
		return nil, fmt.Errorf("projectfile: %w", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("projectfile: more than one YAML document; a project file holds one project")
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("projectfile: the top level must be a mapping with name, techs and so on")
	}
	strict := yaml.NewDecoder(strings.NewReader(src))
	strict.KnownFields(true)
	var p model.Project
	if err := strict.Decode(&p); err != nil {
		return nil, fmt.Errorf("projectfile: %w", err)
	}
	return &File{doc: &doc, src: src}, nil
}

// Project is the file as written; lockfile paths are not rewritten.
func (f *File) Project() model.Project {
	var p model.Project
	_ = f.doc.Decode(&p) // Parse and Apply keep the tree decodable
	return p
}

// Bytes renders the file with 2-space indentation and LF endings. Comments,
// key order and existing styles are kept, and lines the edits did not touch
// come back exactly as they were written.
func (f *File) Bytes() ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(f.doc); err != nil {
		return nil, fmt.Errorf("projectfile: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("projectfile: %w", err)
	}
	return []byte(restoreLayout(f.src, buf.String())), nil
}

// RestoreLayout is restoreLayout for other YAML documents that keep their
// user-written spacing the same way (the settings files).
func RestoreLayout(orig, out string) string { return restoreLayout(orig, out) }

// restoreLayout puts back what the YAML encoder normalises away: the spacing
// before line comments and blank lines. The result is only used when it still
// means the same as the encoder's output.
func restoreLayout(orig, out string) string {
	merged := mergeLayout(orig, out)
	var a, b any
	if yaml.Unmarshal([]byte(merged), &a) != nil || yaml.Unmarshal([]byte(out), &b) != nil || !reflect.DeepEqual(a, b) {
		return out
	}
	return merged
}

// Op is one edit. Kind picks which of the other fields are used.
type Op struct {
	Kind     string         `json:"kind"`
	Env      model.Env      `json:"env,omitempty"`
	Envs     []model.Env    `json:"envs,omitempty"`
	To       model.Env      `json:"to,omitempty"` // the new name, for rename_env
	Tech     string         `json:"tech,omitempty"`
	Version  string         `json:"version,omitempty"`
	Image    string         `json:"image,omitempty"`
	Since    string         `json:"since,omitempty"`    // YYYY-MM-DD, for set_since; empty clears
	Vendor   string         `json:"vendor,omitempty"`   // for set_vendor; empty clears
	Every    string         `json:"every,omitempty"`    // a period, for set_update; "default" removes it, empty leaves it
	Auto     *bool          `json:"auto,omitempty"`     // for set_update; nil leaves it
	Lockfile model.Lockfile `json:"lockfile,omitempty"` // for set_lockfile_dev its Dev is the new value
}

// SinceLayout is how the since date is written.
const SinceLayout = "2006-01-02"

// SetName gives the project a new name, keeping the comments around it.
func (f *File) SetName(name string) error {
	if err := checkName(name); err != nil {
		return err
	}
	doc := cloneNode(f.doc, map[*yaml.Node]*yaml.Node{})
	setStr(doc.Content[0], "name", name, 0)
	f.doc = doc
	return nil
}

// Apply runs the ops in order. If one fails the file is left unchanged.
func (f *File) Apply(ops ...Op) error {
	doc := cloneNode(f.doc, map[*yaml.Node]*yaml.Node{})
	for i, op := range ops {
		if err := apply(doc.Content[0], op); err != nil {
			return fmt.Errorf("projectfile: op %d (%s): %w", i+1, op.Kind, err)
		}
	}
	f.doc = doc
	return nil
}

func apply(root *yaml.Node, op Op) error {
	tech, version := strings.TrimSpace(op.Tech), strings.TrimSpace(op.Version)
	switch op.Kind {
	case "set_envs":
		return setEnvs(root, op.Envs)
	case "add_env":
		return addEnv(root, op.Env)
	case "remove_env":
		return removeEnv(root, op.Env)
	case "rename_env":
		return renameEnv(root, op.Env, op.To)
	case "set_tech":
		if tech == "" {
			return errors.New("tech name is empty")
		}
		return setTech(root, tech, version)
	case "remove_tech":
		if tech == "" {
			return errors.New("tech name is empty")
		}
		return removeTech(root, tech)
	case "set_env_tech", "remove_env_tech", "set_image", "exclude_env_tech", "include_env_tech":
		if !op.Env.Valid() {
			return fmt.Errorf("invalid env %q (lowercase letters, digits, - and _)", op.Env)
		}
		switch op.Kind {
		case "set_image":
			return setImage(root, op.Env, strings.TrimSpace(op.Image))
		case "remove_env_tech":
			return removeEnvTech(root, op.Env, tech)
		case "exclude_env_tech", "include_env_tech":
			if tech == "" {
				return errors.New("tech name is empty")
			}
			if op.Kind == "include_env_tech" {
				return includeEnvTech(root, op.Env, tech)
			}
			return excludeEnvTech(root, op.Env, tech)
		}
		if tech == "" {
			return errors.New("tech name is empty")
		}
		if version == "" {
			return errors.New("a deployed version is required")
		}
		return setEnvTech(root, op.Env, tech, version)
	case "set_tech_envs":
		if tech == "" {
			return errors.New("tech name is empty")
		}
		return setTechEnvs(root, tech, op.Envs)
	case "migrate_envs":
		return migrateEnvironments(root)
	case "add_lockfile":
		l := op.Lockfile
		if l.Type == "" || l.Path == "" {
			return errors.New("a lockfile needs a type and a path")
		}
		if l.Env != "" && !l.Env.Valid() {
			return fmt.Errorf("invalid lockfile env %q", l.Env)
		}
		return addLockfile(root, l)
	case "remove_lockfile":
		if op.Lockfile.Env != "" && !op.Lockfile.Env.Valid() {
			return fmt.Errorf("invalid lockfile env %q", op.Lockfile.Env)
		}
		return removeLockfile(root, op.Lockfile)
	case "set_lockfile_dev":
		if op.Lockfile.Env != "" && !op.Lockfile.Env.Valid() {
			return fmt.Errorf("invalid lockfile env %q", op.Lockfile.Env)
		}
		return setLockfileDev(root, op.Lockfile)
	case "set_since":
		return setSince(root, strings.TrimSpace(op.Since))
	case "set_update":
		return setUpdate(root, strings.TrimSpace(op.Every), op.Auto)
	case "set_vendor":
		return setVendor(root, strings.TrimSpace(op.Vendor))
	}
	return fmt.Errorf("unknown kind %q", op.Kind)
}

func setEnvs(root *yaml.Node, envs []model.Env) error {
	var items []*yaml.Node
	seen := map[model.Env]bool{}
	for _, e := range envs {
		if !e.Valid() {
			return fmt.Errorf("invalid env %q (lowercase letters, digits, - and _)", e)
		}
		if !seen[e] {
			seen[e] = true
			items = append(items, str(string(e), 0))
		}
	}
	if len(items) == 0 {
		mapDel(root, "envs")
		return nil
	}
	if old := mapGet(root, "envs"); old != nil && old.Kind == yaml.SequenceNode {
		old.Content = items // keeps the user's style and comments
		return nil
	}
	seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Style: yaml.FlowStyle, Content: items}
	if i := mapIndex(root, "envs"); i >= 0 {
		root.Content[i+1] = seq
		return nil
	}
	at := len(root.Content) // new envs go right after the name and the vendor
	for _, k := range []string{"name", "vendor"} {
		if i := mapIndex(root, k); i >= 0 {
			at = i + 2
		}
	}
	root.Content = append(root.Content[:at], append([]*yaml.Node{str("envs", 0), seq}, root.Content[at:]...)...)
	return nil
}

func setTech(root *yaml.Node, name, version string) error {
	techs, err := child(root, "techs", yaml.SequenceNode, false)
	if err != nil {
		return err
	}
	if i := techIndex(techs, name); i >= 0 {
		if version != "" {
			setStr(techs.Content[i], "version", version, yaml.DoubleQuotedStyle)
		}
		return nil
	}
	item := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Style: yaml.FlowStyle}
	mapAppend(item, "name", str(name, 0))
	if version != "" {
		mapAppend(item, "version", str(version, yaml.DoubleQuotedStyle))
	}
	techs.Content = append(techs.Content, item)
	return nil
}

func removeTech(root *yaml.Node, name string) error {
	techs := mapGet(root, "techs")
	if techs == nil || techs.Kind != yaml.SequenceNode || techIndex(techs, name) < 0 {
		return fmt.Errorf("tech %q is not in the project", name)
	}
	for i := techIndex(techs, name); i >= 0; i = techIndex(techs, name) {
		dropItem(techs, i)
	}
	return nil
}

func addLockfile(root *yaml.Node, l model.Lockfile) error {
	seq, err := child(root, "lockfiles", yaml.SequenceNode, false)
	if err != nil {
		return err
	}
	for _, it := range seq.Content {
		if lockfileField(it, "type") == l.Type && lockfileField(it, "path") == l.Path && lockfileField(it, "env") == string(l.Env) {
			return nil // already there
		}
	}
	item := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Style: yaml.FlowStyle}
	mapAppend(item, "type", str(l.Type, 0))
	mapAppend(item, "path", str(l.Path, 0))
	if l.Env != "" {
		mapAppend(item, "env", str(string(l.Env), 0))
	}
	if l.Dev {
		mapAppend(item, "dev", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: "true"})
	}
	seq.Content = append(seq.Content, item)
	return nil
}

func removeLockfile(root *yaml.Node, l model.Lockfile) error {
	seq := mapGet(root, "lockfiles")
	if seq == nil || seq.Kind != yaml.SequenceNode {
		return fmt.Errorf("no lockfile with path %q", l.Path)
	}
	found := false
	for i := len(seq.Content) - 1; i >= 0; i-- {
		if it := seq.Content[i]; lockfileField(it, "path") == l.Path && (l.Env == "" || lockfileField(it, "env") == string(l.Env)) {
			dropItem(seq, i)
			found = true
		}
	}
	if !found && l.Env != "" {
		return fmt.Errorf("no lockfile with path %q for env %s", l.Path, l.Env)
	}
	if !found {
		return fmt.Errorf("no lockfile with path %q", l.Path)
	}
	return nil
}

func setLockfileDev(root *yaml.Node, l model.Lockfile) error {
	seq := mapGet(root, "lockfiles")
	found := false
	if seq != nil && seq.Kind == yaml.SequenceNode {
		for _, it := range seq.Content {
			if it.Kind != yaml.MappingNode || lockfileField(it, "path") != l.Path || (l.Env != "" && lockfileField(it, "env") != string(l.Env)) {
				continue
			}
			found = true
			switch cur := mapGet(it, "dev"); {
			case !l.Dev:
				mapDel(it, "dev") // false is the default
			case cur == nil:
				mapAppend(it, "dev", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: "true"})
			default:
				cur.Kind, cur.Tag, cur.Value, cur.Style = yaml.ScalarNode, "!!bool", "true", 0
			}
		}
	}
	switch {
	case found:
		return nil
	case l.Env != "":
		return fmt.Errorf("no lockfile with path %q for env %s", l.Path, l.Env)
	}
	return fmt.Errorf("no lockfile with path %q", l.Path)
}

func setSince(root *yaml.Node, since string) error {
	if since == "" { // an empty date clears it
		mapDel(root, "since")
		return nil
	}
	if _, err := time.Parse(SinceLayout, since); err != nil {
		return fmt.Errorf("since must look like 2026-01-31: %w", err)
	}
	v := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!timestamp", Value: since}
	if cur := mapGet(root, "since"); cur != nil {
		cur.Kind, cur.Tag, cur.Value, cur.Style = yaml.ScalarNode, "!!timestamp", since, 0
		cur.Content, cur.Alias = nil, nil
		return nil
	}
	at := len(root.Content) // a new date goes after the inventory, before what differs per environment
	for _, k := range []string{"lockfiles", "techs", "envs", "vendor", "name"} {
		if i := mapIndex(root, k); i >= 0 {
			at = i + 2
			break
		}
	}
	root.Content = append(root.Content[:at], append([]*yaml.Node{str("since", 0), v}, root.Content[at:]...)...)
	return nil
}

func setVendor(root *yaml.Node, vendor string) error {
	if vendor == "" { // an empty vendor clears it
		mapDel(root, "vendor")
		return nil
	}
	if !model.ValidVendor(vendor) {
		return fmt.Errorf("invalid vendor %q (use lowercase letters, digits, - and _, at most 63 characters)", vendor)
	}
	if mapGet(root, "vendor") != nil {
		setStr(root, "vendor", vendor, 0)
		return nil
	}
	at := len(root.Content) // a new vendor goes right after the name
	if i := mapIndex(root, "name"); i >= 0 {
		at = i + 2
	}
	root.Content = append(root.Content[:at], append([]*yaml.Node{str("vendor", 0), str(vendor, 0)}, root.Content[at:]...)...)
	return nil
}

// ParseEvery reads a period of the update block: a duration such as 30m or 1h,
// or whole days such as 2d. It must be at least model.MinEvery.
func ParseEvery(text string) (time.Duration, error) {
	text = strings.TrimSpace(text)
	var d time.Duration
	var err error
	if days, ok := strings.CutSuffix(text, "d"); ok {
		var n int
		if n, err = strconv.Atoi(days); err == nil {
			d = time.Duration(n) * 24 * time.Hour
		}
	} else {
		d, err = time.ParseDuration(text)
	}
	switch {
	case err != nil:
		return 0, fmt.Errorf("every must look like 30m, 1h or 2d: %w", err)
	case d < model.MinEvery:
		return 0, fmt.Errorf("every must be at least %s, not %s", model.Span(model.MinEvery), text)
	}
	return d, nil
}

// setUpdate sets the period and whether scheduled runs include the project.
// The defaults (no period, auto on) are removed, and an empty block with them.
func setUpdate(root *yaml.Node, every string, auto *bool) error {
	if every == "" && auto == nil {
		return errors.New("give every, auto or both")
	}
	var period time.Duration
	if every != "" && every != "default" {
		d, err := ParseEvery(every)
		if err != nil {
			return err
		}
		period = d
	}
	if mapGet(root, "update") == nil {
		at := 0 // a new block goes after the inventory, before what differs per environment
		for _, k := range []string{"name", "vendor", "envs", "techs", "lockfiles", "since"} {
			if i := mapIndex(root, k); i >= 0 {
				at = max(at, i+2)
			}
		}
		root.Content = append(root.Content[:at], append([]*yaml.Node{str("update", 0), {Kind: yaml.MappingNode, Tag: "!!map"}}, root.Content[at:]...)...)
	}
	upd, err := child(root, "update", yaml.MappingNode, false)
	if err != nil {
		return err
	}
	switch {
	case every == "":
	case period == 0:
		mapDel(upd, "every")
	default:
		setStr(upd, "every", model.Span(period), 0)
	}
	switch {
	case auto == nil:
	case *auto:
		mapDel(upd, "auto") // on is the default
	case mapGet(upd, "auto") != nil:
		cur := mapGet(upd, "auto")
		cur.Kind, cur.Tag, cur.Value, cur.Style = yaml.ScalarNode, "!!bool", "false", 0
	default:
		mapAppend(upd, "auto", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: "false"})
	}
	if len(upd.Content) == 0 {
		mapDel(root, "update")
	}
	return nil
}

// ---- yaml.Node helpers ----

func str(s string, style yaml.Style) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: s, Style: style}
}

func mapIndex(m *yaml.Node, key string) int {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return i
		}
	}
	return -1
}

// keyIndexFold finds a key ignoring case.
func keyIndexFold(m *yaml.Node, key string) int {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if strings.EqualFold(m.Content[i].Value, key) {
			return i
		}
	}
	return -1
}

func mapGet(m *yaml.Node, key string) *yaml.Node {
	if i := mapIndex(m, key); i >= 0 {
		return m.Content[i+1]
	}
	return nil
}

func mapAppend(m *yaml.Node, key string, v *yaml.Node) {
	m.Content = append(m.Content, str(key, 0), v)
}

func mapDel(m *yaml.Node, key string) {
	if i := mapIndex(m, key); i >= 0 {
		m.Content = append(m.Content[:i], m.Content[i+2:]...)
	}
}

// setStr sets a string value under key. An existing scalar is edited in place
// so its comments stay; one that already holds the value is left alone.
func setStr(m *yaml.Node, key, value string, style yaml.Style) {
	v := mapGet(m, key)
	switch {
	case v == nil:
		mapAppend(m, key, str(value, style))
	case v.Kind == yaml.ScalarNode && v.Value == value:
	case v.Kind == yaml.ScalarNode:
		v.Tag, v.Value, v.Style = "!!str", value, style
	default:
		m.Content[mapIndex(m, key)+1] = str(value, style)
	}
}

// child returns the mapping or sequence under key. A missing key or an empty
// value (key with nothing after it) is turned into an empty one; flow says
// whether an empty one is written in flow style.
func child(m *yaml.Node, key string, kind yaml.Kind, flow bool) (*yaml.Node, error) {
	tag, what := "!!map", "mapping"
	if kind == yaml.SequenceNode {
		tag, what = "!!seq", "list"
	}
	v := mapGet(m, key)
	switch {
	case v == nil:
		v = &yaml.Node{Kind: kind, Tag: tag}
		mapAppend(m, key, v)
	case v.Kind == yaml.ScalarNode && v.Tag == "!!null":
		v.Kind, v.Tag, v.Value, v.Style = kind, tag, "", 0
	case v.Kind != kind:
		return nil, fmt.Errorf("%s must be a %s", key, what)
	}
	if len(v.Content) == 0 {
		v.Style = 0
		if flow {
			v.Style = yaml.FlowStyle
		}
	}
	return v, nil
}

// dig follows keys from root and returns the mapping at every level, root
// first. It stops at the first key that is missing or empty.
func dig(root *yaml.Node, keys ...string) ([]*yaml.Node, error) {
	chain := []*yaml.Node{root}
	for _, k := range keys {
		v := mapGet(chain[len(chain)-1], k)
		if v == nil || (v.Kind == yaml.ScalarNode && v.Tag == "!!null") {
			break
		}
		if v.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("%s must be a mapping", k)
		}
		chain = append(chain, v)
	}
	return chain, nil
}

// prune drops mappings left empty, from the innermost outwards.
func prune(chain []*yaml.Node, keys []string) {
	for i := len(chain) - 1; i > 0 && len(chain[i].Content) == 0; i-- {
		mapDel(chain[i-1], keys[i-1])
	}
}

// dropItem removes list item i. A comment written below the item (such as a
// commented-out neighbour) is not part of it, so it moves to the item above.
func dropItem(seq *yaml.Node, i int) {
	if foot := seq.Content[i].FootComment; foot != "" {
		switch {
		case i > 0:
			prev := seq.Content[i-1]
			prev.FootComment = strings.TrimSpace(prev.FootComment + "\n" + foot)
		case i+1 < len(seq.Content):
			next := seq.Content[i+1]
			next.HeadComment = strings.TrimSpace(foot + "\n" + next.HeadComment)
		}
	}
	seq.Content = append(seq.Content[:i], seq.Content[i+1:]...)
}

func techIndex(seq *yaml.Node, name string) int {
	for i, it := range seq.Content {
		if it.Kind == yaml.MappingNode {
			if n := mapGet(it, "name"); n != nil && strings.EqualFold(n.Value, name) {
				return i
			}
		}
	}
	return -1
}

func lockfileField(item *yaml.Node, key string) string {
	if item.Kind != yaml.MappingNode {
		return ""
	}
	if v := mapGet(item, key); v != nil {
		return v.Value
	}
	return ""
}

// cloneNode deep-copies a node tree so Apply can work on a copy.
func cloneNode(n *yaml.Node, seen map[*yaml.Node]*yaml.Node) *yaml.Node {
	c := *n
	seen[n] = &c
	c.Content = make([]*yaml.Node, len(n.Content))
	for i, k := range n.Content {
		c.Content[i] = cloneNode(k, seen)
	}
	if n.Alias != nil && seen[n.Alias] != nil {
		c.Alias = seen[n.Alias]
	}
	return &c
}
