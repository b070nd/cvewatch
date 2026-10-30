package projectflow

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode"

	"github.com/b070nd/cvewatch/app/src/discovery"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/ops"
	"github.com/b070nd/cvewatch/app/src/projectfile"
	"github.com/b070nd/cvewatch/app/src/setup"
)

type Request struct {
	Project string
	Folder  string
}

type Opened struct {
	Flow     *setup.Flow
	Creating bool
	Name     string
	Note     string
}

func ResolveFolder(typed string) (string, error) {
	p := strings.TrimSpace(typed)
	if p == "" {
		return "", errors.New("no folder given")
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
		return "", fmt.Errorf("cannot use %s as a folder", p)
	}
	fi, err := os.Stat(abs)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "", fmt.Errorf("no such folder: %s", strings.TrimSpace(typed))
	case err != nil:
		return "", fmt.Errorf("cannot open %s: %w", strings.TrimSpace(typed), err)
	case !fi.IsDir():
		return "", fmt.Errorf("%s is a file, not a folder", strings.TrimSpace(typed))
	}
	return abs, nil
}

func Open(s *ops.Session, req Request) (Opened, error) {
	var out Opened
	files, err := s.ProjectNames()
	if err != nil {
		return out, err
	}
	cat := s.Cfg.Catalog

	var res *discovery.Result
	if strings.TrimSpace(req.Folder) != "" {
		dir, err := ResolveFolder(req.Folder)
		if err != nil {
			return out, err
		}
		r, err := discovery.Scan(dir, cat, discovery.Options{})
		if err != nil {
			return out, err
		}
		res = &r
	}

	if req.Project == "" {
		taken := map[string]bool{}
		for _, n := range files {
			taken[n] = true
		}
		for _, p := range s.Cfg.Projects {
			taken[p.Name] = true
		}
		out.Flow = setup.NewFlow(cat, nil)
		out.Flow.NameTaken = func(n string) bool { return taken[n] }
		out.Creating = true
	} else {
		if _, err := s.EditProject(ops.ProjectChange{Project: req.Project}); err != nil { // access check, nothing changes
			return out, err
		}
		if !slices.Contains(files, req.Project) {
			return out, fmt.Errorf("project %q has no file under config/projects, so it cannot be edited here", req.Project)
		}
		path, err := projectfile.Path(projectsDir(s), req.Project)
		if err != nil {
			return out, err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return out, err
		}
		file, err := projectfile.Parse(data)
		if err != nil {
			return out, err
		}
		existing := file.Project()
		for i, l := range existing.Lockfiles {
			existing.Lockfiles[i].Path = absolute(s.Cfg.Root, l.Path)
			if res != nil {
				existing.Lockfiles[i].Path = inFolder(res.Root, existing.Lockfiles[i].Path)
			}
		}
		out.Flow = setup.NewFlow(cat, &existing)
		out.Flow.SetExistingBytes(data)
		out.Name = req.Project
	}

	if res != nil {
		out.Flow.UseDiscovery(res.Root, *res)
		out.Note = scanNote(*res)
	}
	return out, nil
}

func Edits(s *ops.Session, f *setup.Flow) []projectfile.Op {
	out := f.Ops()
	var stored []model.Lockfile
	if ex := f.Draft().Existing; ex != nil && slices.ContainsFunc(out, func(o projectfile.Op) bool { return o.Kind == "remove_lockfile" }) {
		stored = storedLockfiles(s, ex.Name)
	}
	for i, o := range out {
		switch o.Kind {
		case "add_lockfile":
			out[i].Lockfile.Path = relative(s.Cfg.Root, o.Lockfile.Path)
		case "remove_lockfile":
			out[i].Lockfile.Path = storedPath(s.Cfg.Root, stored, o.Lockfile.Path)
		}
	}
	return out
}

// Flow.Ops hands back absolute paths for existing lockfiles, but the file keeps its own spelling and removal matches on it.
func storedPath(root string, stored []model.Lockfile, p string) string {
	for _, l := range stored {
		if sameFile(absolute(root, l.Path), p) {
			return l.Path
		}
	}
	return relative(root, p)
}

func storedLockfiles(s *ops.Session, name string) []model.Lockfile {
	path, err := projectfile.Path(projectsDir(s), name)
	if err != nil {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	file, err := projectfile.Parse(data)
	if err != nil {
		return nil
	}
	return file.Project().Lockfiles
}

func projectsDir(s *ops.Session) string { return filepath.Join(s.Cfg.Root, "config", "projects") }

// absolute makes a project file path absolute: relative ones follow the config root.
func absolute(root, p string) string {
	if !filepath.IsAbs(p) {
		p = filepath.Join(root, filepath.FromSlash(p))
	}
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return filepath.Clean(p)
}

// inFolder spells a path under dir the way the scan will, even when a symlink leads there.
func inFolder(dir, p string) string {
	rel, err := filepath.Rel(realPath(dir), resolvedDir(p))
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return p
	}
	return filepath.Join(dir, rel)
}

func sameFile(a, b string) bool { return resolvedDir(a) == resolvedDir(b) }

// resolvedDir resolves symlinks in the folder part only, so a lockfile that is itself a link keeps its name.
func resolvedDir(p string) string {
	return filepath.Join(realPath(filepath.Dir(p)), filepath.Base(p))
}

func relative(root, p string) string {
	if !filepath.IsAbs(p) {
		return p
	}
	r, err := filepath.Abs(root)
	if err != nil {
		return p
	}
	rel, err := filepath.Rel(realPath(r), realPath(p))
	if err != nil {
		return p
	}
	return filepath.ToSlash(rel)
}

func realPath(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return p
}

func scanNote(res discovery.Result) string {
	s := fmt.Sprintf("scanned %s: %s, %s", plain(res.Root), count(len(res.Techs), "technology", "technologies"), count(len(res.Lockfiles), "lockfile", "lockfiles"))
	if res.Truncated {
		s += " (scan stopped early)"
	}
	return s
}

func count(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

func plain(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, "?"))
}
