package confdoc

import (
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/b070nd/cvewatch/app/src/config"
)

// Level of an Issue.
type Level string

const (
	LevelError   Level = "error"
	LevelWarning Level = "warning"
)

// Issue is one problem with the configuration as it would be, attributed to a
// document and a field when that is known.
type Issue struct {
	Level   Level  `json:"level"`
	Doc     string `json:"doc,omitempty"`   // document ID, or projects/<name> for a project file
	Field   string `json:"field,omitempty"` // path inside the document, in ParsePath form
	Line    int    `json:"line,omitempty"`
	Message string `json:"message"`
	// Existing marks a problem the configuration on disk already has, so a
	// change that leaves it alone is not blamed for it.
	Existing bool `json:"existing,omitempty"`
}

// Report is the result of validating a set.
type Report struct {
	Issues []Issue
	Bundle *config.Bundle // the assembled configuration; nil when a document cannot be parsed
}

// Blocked reports an error that is new, so the change must not be saved. Errors
// the configuration already had do not block a change that does not add to them,
// which lets a broken configuration be repaired one field at a time.
func (r Report) Blocked() bool {
	for _, i := range r.Issues {
		if i.Level == LevelError && !i.Existing {
			return true
		}
	}
	return false
}

// Errors lists the issues of level error.
func (r Report) Errors() []Issue {
	var out []Issue
	for _, i := range r.Issues {
		if i.Level == LevelError {
			out = append(out, i)
		}
	}
	return out
}

// MarkExisting flags the issues that the baseline report already has.
func (r *Report) MarkExisting(base Report) {
	had := map[string]bool{}
	for _, i := range base.Issues {
		had[i.key()] = true
	}
	for k := range r.Issues {
		r.Issues[k].Existing = had[r.Issues[k].key()]
	}
}

func (i Issue) key() string { return string(i.Level) + "|" + i.Doc + "|" + i.Field + "|" + i.Message }

// Validate assembles the whole configuration with the set's documents in
// place of the files and runs the same checks as config.Load, so a document
// that would stop the daemon from loading is reported here. Broken project
// files are warnings: they do not stop settings from being edited.
func (s *Set) Validate() Report { return s.ValidateWith(nil) }

// ValidateWith is Validate with more files replaced or hidden, such as project
// files a change moves; a nil value hides the file (see config.Overlay).
func (s *Set) ValidateWith(extra config.Overlay) Report {
	over := config.Overlay{}
	for p, data := range extra {
		over[p] = data
	}
	for _, d := range s.Docs {
		if d.Layer != LayerUser || d.Path == "" {
			continue
		}
		if !d.Exists && !d.dirty {
			continue
		}
		b, err := d.Bytes()
		if err != nil {
			return Report{Issues: []Issue{{Level: LevelError, Doc: d.ID, Message: err.Error()}}}
		}
		if !d.Exists && len(b) == 0 {
			continue
		}
		over[d.Path] = b
	}
	b, issues := config.Check(s.Root, over)
	r := Report{Bundle: b}
	for _, is := range issues {
		r.Issues = append(r.Issues, s.attribute(is))
	}
	if b != nil {
		for _, w := range b.Warnings {
			r.Issues = append(r.Issues, Issue{Level: LevelWarning, Message: w})
		}
		for _, br := range b.Broken {
			r.Issues = append(r.Issues, Issue{Level: LevelWarning, Doc: "projects/" + br.Name, Message: "project " + br.Name + " is broken and skipped: " + br.Err})
		}
	}
	return r
}

var linePrefix = regexp.MustCompile(`^(yaml: )?line \d+: `)

// attribute turns a config issue into one naming a document and field.
func (s *Set) attribute(is config.Issue) Issue {
	out := Issue{Level: LevelError, Doc: s.docOf(is.File), Field: is.Field, Line: is.Line, Message: linePrefix.ReplaceAllString(is.Msg, "")}
	if out.Field == "" && is.Line > 0 {
		if d := s.Doc(out.Doc); d != nil {
			// the lines refer to the text as written, so read that, not the edited tree
			b, _ := d.Bytes()
			if fresh := parseDoc(d.ID, d.Kind, d.Path, b); fresh.node != nil {
				if segs := pathAtLine(fresh.node.Content[0], is.Line); len(segs) > 0 {
					out.Field = FormatPath(segs)
				}
			}
		}
	}
	return out
}

// docOf maps a file path to a document ID.
func (s *Set) docOf(file string) string {
	if file == "" {
		return ""
	}
	for _, d := range s.Docs {
		if d.Path != "" && filepath.Clean(d.Path) == filepath.Clean(file) {
			return d.ID
		}
	}
	if filepath.Dir(file) == filepath.Clean(config.ProjectsDir(s.Root)) {
		return "projects/" + strings.TrimSuffix(filepath.Base(file), ".yaml")
	}
	return ""
}

// pathAtLine finds the deepest key or scalar value that starts on a line.
func pathAtLine(n *yaml.Node, line int) []string {
	switch n.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			if sub := pathAtLine(v, line); sub != nil {
				return append([]string{k.Value}, sub...)
			}
			if k.Line == line || (v.Kind == yaml.ScalarNode && v.Line == line) {
				return []string{k.Value}
			}
		}
	case yaml.SequenceNode:
		for i, it := range n.Content {
			if sub := pathAtLine(it, line); sub != nil {
				return append([]string{strconv.Itoa(i)}, sub...)
			}
			if it.Kind == yaml.ScalarNode && it.Line == line {
				return []string{strconv.Itoa(i)}
			}
		}
	}
	return nil
}
