// Package confdoc is the one place that reads and edits the configuration
// documents: config/config.yaml, config/techs.yaml and sources/*.yaml. Edits
// are applied by field path to a yaml.Node tree, so the user's comments, key
// order and style survive. A candidate is validated by assembling the whole
// configuration with the edited text in memory, using the same checks as
// config.Load, so a change that would stop the daemon from loading is caught
// before anything is written. Secrets are never shown: previews say "(set)".
package confdoc

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/b070nd/cvewatch/app/src/config"
	shipped "github.com/b070nd/cvewatch/app/src/defaults"
	"github.com/b070nd/cvewatch/app/src/projectfile"
)

// Layer says where a document comes from.
type Layer string

const (
	LayerUser    Layer = "user"    // a file in the user's folder; editable
	LayerShipped Layer = "shipped" // built into the binary; shown for reference
)

// Document IDs of the fixed documents. Source files are "sources/<name>".
const (
	IDSettings      = "config"
	IDTechs         = "techs"
	IDShippedTechs  = "shipped/techs"
	IDShippedSource = "shipped/sources"
	sourcesPrefix   = "sources/"
)

var sourceFileRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

// Document is one configuration file held as a YAML node tree plus the text it
// was read from. A document whose YAML does not parse keeps its text and the
// parse error, and can only be replaced as a whole.
type Document struct {
	ID       string
	Kind     string // KindSettings, KindTechs or KindSources
	Layer    Layer
	Path     string // empty for shipped documents
	Exists   bool   // the file is on disk
	ReadOnly bool
	ParseErr error // set when the text is not usable YAML

	node  *yaml.Node // the document node; nil for an empty or comment-only file
	src   string     // normalised text, used to keep the user's spacing
	orig  []byte     // exactly what was on disk
	dirty bool
	fresh []byte // set by replace: the text is exactly this until the next field edit
}

// Set is every document of one configuration folder.
type Set struct {
	Root string
	Docs []*Document
}

// Read loads the user's documents and the shipped ones. A missing user file is
// a document that does not exist yet. Only an unreadable file is an error;
// broken YAML is kept on the document, so a broken configuration can be opened.
func Read(root string) (*Set, error) {
	s := &Set{Root: root}
	for _, d := range []struct{ id, kind, path string }{
		{IDSettings, KindSettings, config.SettingsPath(root)},
		{IDTechs, KindTechs, config.TechsPath(root)},
	} {
		doc, err := readFile(d.id, d.kind, d.path)
		if err != nil {
			return nil, err
		}
		s.Docs = append(s.Docs, doc)
	}
	files, err := filepath.Glob(filepath.Join(config.SourcesDir(root), "*.yaml"))
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		id := sourcesPrefix + strings.TrimSuffix(filepath.Base(f), ".yaml")
		doc, err := readFile(id, KindSources, f)
		if err != nil {
			return nil, err
		}
		s.Docs = append(s.Docs, doc)
	}
	for _, d := range []struct {
		id, kind string
		data     []byte
	}{{IDShippedTechs, KindTechs, shipped.Techs()}, {IDShippedSource, KindSources, shipped.Sources()}} {
		doc := parseDoc(d.id, d.kind, "", d.data)
		doc.Layer, doc.Exists, doc.ReadOnly = LayerShipped, true, true
		s.Docs = append(s.Docs, doc)
	}
	return s, nil
}

func readFile(id, kind, path string) (*Document, error) {
	data, err := os.ReadFile(path)
	exists := err == nil
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	d := parseDoc(id, kind, path, data)
	d.Layer, d.Exists = LayerUser, exists
	return d, nil
}

func parseDoc(id, kind, path string, data []byte) *Document {
	d := &Document{ID: id, Kind: kind, Path: path, orig: data}
	d.src = strings.ReplaceAll(strings.TrimPrefix(string(data), "\xef\xbb\xbf"), "\r\n", "\n")
	dec := yaml.NewDecoder(strings.NewReader(d.src))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if !errors.Is(err, io.EOF) {
			d.ParseErr = err
		}
		return d
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		d.ParseErr = errors.New("more than one YAML document")
		return d
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		if len(doc.Content) > 0 && doc.Content[0].Kind == yaml.ScalarNode && doc.Content[0].Tag == "!!null" {
			return d // `~` or `null`: treated like an empty file
		}
		d.ParseErr = errors.New("the top level must be a mapping")
		return d
	}
	d.node = &doc
	return d
}

// Doc finds a document by ID.
func (s *Set) Doc(id string) *Document {
	for _, d := range s.Docs {
		if d.ID == id {
			return d
		}
	}
	return nil
}

// Changed lists the user documents whose text differs from what was read.
func (s *Set) Changed() []*Document {
	var out []*Document
	for _, d := range s.Docs {
		if !d.dirty || d.Layer != LayerUser {
			continue
		}
		if b, err := d.Bytes(); err != nil || !bytes.Equal(b, d.orig) && (d.Exists || len(bytes.TrimSpace(b)) > 0) {
			out = append(out, d)
		}
	}
	return out
}

func (s *Set) clone() *Set {
	c := &Set{Root: s.Root}
	for _, d := range s.Docs {
		n := *d
		if d.node != nil {
			n.node = cloneNode(d.node)
		}
		c.Docs = append(c.Docs, &n)
	}
	return c
}

func cloneNode(n *yaml.Node) *yaml.Node {
	c := *n
	c.Content = make([]*yaml.Node, len(n.Content))
	for i, k := range n.Content {
		c.Content[i] = cloneNode(k)
	}
	return &c
}

// create adds a source file that does not exist yet.
func (s *Set) create(id string) (*Document, error) {
	name, ok := strings.CutPrefix(id, sourcesPrefix)
	if !ok || !sourceFileRE.MatchString(name) {
		return nil, fmt.Errorf("unknown document %q (use config, techs or sources/<name> with lowercase letters, digits, - and _)", id)
	}
	d := &Document{ID: id, Kind: KindSources, Layer: LayerUser, Path: filepath.Join(config.SourcesDir(s.Root), name+".yaml")}
	// keep user documents ahead of the shipped ones
	at := len(s.Docs)
	for i, o := range s.Docs {
		if o.Layer == LayerShipped {
			at = i
			break
		}
	}
	s.Docs = append(s.Docs[:at], append([]*Document{d}, s.Docs[at:]...)...)
	return d, nil
}

// rootNode returns the top-level mapping, creating the document tree for an
// empty file. Text that is only comments is kept as the head comment.
func (d *Document) rootNode() (*yaml.Node, error) {
	if d.ParseErr != nil {
		return nil, fmt.Errorf("%s has a syntax error and cannot be edited by field: %v", d.ID, d.ParseErr)
	}
	if d.node == nil {
		d.node = &yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}}
		if c := strings.TrimSpace(d.src); c != "" {
			d.node.HeadComment = c
		}
	}
	return d.node.Content[0], nil
}

// Bytes is the document as it would be written: the original bytes when
// nothing changed, otherwise the encoded tree with the user's spacing, blank
// lines and comments put back. It may hold secrets; use Text for display.
func (d *Document) Bytes() ([]byte, error) {
	if !d.dirty {
		return d.orig, nil
	}
	if d.fresh != nil {
		return d.fresh, nil
	}
	if d.node == nil {
		return []byte(d.src), nil
	}
	out, err := encode(d.node)
	if err != nil {
		return nil, err
	}
	return []byte(projectfile.RestoreLayout(d.src, out)), nil
}

func encode(n *yaml.Node) (string, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(n); err != nil {
		return "", fmt.Errorf("confdoc: %w", err)
	}
	if err := enc.Close(); err != nil {
		return "", fmt.Errorf("confdoc: %w", err)
	}
	return buf.String(), nil
}

// replace swaps the whole text, re-reading it as a new document.
func (d *Document) replace(text string) {
	n := parseDoc(d.ID, d.Kind, d.Path, []byte(text))
	d.node, d.src, d.ParseErr = n.node, n.src, n.ParseErr
	d.fresh, d.dirty = []byte(text), true
}

// Access reads the access rules of config.yaml leniently: other mistakes in the
// document do not matter, only whether the rules themselves can be read. An
// error means they cannot, and callers must then treat everyone as restricted.
func (d *Document) Access() (map[string]config.Grant, error) {
	if d.ParseErr != nil {
		return nil, d.ParseErr
	}
	if d.node == nil {
		return nil, nil
	}
	n := childOrNil(d.node.Content[0], "access")
	if n == nil || isEmptyValue(n) {
		return nil, nil
	}
	var out map[string]config.Grant
	if err := n.Decode(&out); err != nil {
		return nil, fmt.Errorf("access: %w", err)
	}
	return out, nil
}

// Scalar reads one top-level value of the document as text; empty when it is not set.
func (d *Document) Scalar(key string) string {
	if d.node == nil {
		return ""
	}
	if n := childOrNil(d.node.Content[0], key); n != nil && n.Kind == yaml.ScalarNode {
		return n.Value
	}
	return ""
}
