package projectflow

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/b070nd/cvewatch/app/src/catalog"
	"github.com/b070nd/cvewatch/app/src/discovery"
)

type SourceKind string

const (
	SourceFolder SourceKind = "folder"
	SourceFile   SourceKind = "file"
)

// Source is what a project is proposed from: a repository folder, or a single
// Dockerfile, compose file or Kubernetes manifest. Path is absolute.
type Source struct {
	Path string
	Kind SourceKind
}

func (s Source) IsFile() bool { return s.Kind == SourceFile }

// Dir is the folder the project lives in: the source itself, or the folder of the file.
func (s Source) Dir() string {
	if s.IsFile() {
		return filepath.Dir(s.Path)
	}
	return s.Path
}

// typedPath expands ~ and makes a typed path absolute.
func typedPath(typed, noun string) (string, error) {
	p := strings.TrimSpace(typed)
	if p == "" {
		return "", fmt.Errorf("no %s given", noun)
	}
	if p == "~" || strings.HasPrefix(p, "~/") || strings.HasPrefix(p, "~"+string(filepath.Separator)) {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("cannot find the home folder for %s", p)
		}
		p = filepath.Join(home, p[1:])
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", fmt.Errorf("cannot use %s as a %s", p, noun)
	}
	return abs, nil
}

// ResolveSource accepts what a user typed (~ allowed) as a folder or as a file
// cvewatch can read, and says which it is.
func ResolveSource(typed string) (Source, error) {
	abs, err := typedPath(typed, "folder or file")
	if err != nil {
		return Source{}, err
	}
	shown := strings.TrimSpace(typed)
	fi, err := os.Stat(abs)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return Source{}, fmt.Errorf("no such folder or file: %s", shown)
	case err != nil:
		return Source{}, fmt.Errorf("cannot open %s: %w", shown, err)
	case fi.IsDir():
		return Source{Path: abs, Kind: SourceFolder}, nil
	case !fi.Mode().IsRegular():
		return Source{}, fmt.Errorf("%s is neither a file nor a folder", shown)
	case !discovery.SupportedFile(abs):
		return Source{}, fmt.Errorf("%s is a file, not a folder, and not a Dockerfile, compose file, Kubernetes manifest, Terraform file or lockfile", shown)
	}
	return Source{Path: abs, Kind: SourceFile}, nil
}

// ScanSource runs the folder scan or the single-file scan, whichever the source is.
func ScanSource(src Source, cat *catalog.Catalog) (discovery.Result, error) {
	if src.IsFile() {
		return discovery.ScanFile(src.Path, cat, discovery.Options{})
	}
	return discovery.Scan(src.Path, cat, discovery.Options{})
}
