package doctor

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/defaults"
	"github.com/b070nd/cvewatch/app/src/discovery"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/projectfile"
)

// InitOptions controls Init.
type InitOptions struct {
	Force   bool   // overwrite files that already exist
	Repo    string // a repository to look at for technologies, versions and lockfiles
	Project string // project name; default is the repository folder's name
}

// InitResult lists paths relative to the root, and plain-English next steps.
type InitResult struct {
	Written, Skipped, Notes []string
}

// Init writes the starter files under root and, when Repo is set, a project
// file describing what discovery found in that repository. Lockfile paths are
// stored relative to root, so the folder keeps working when it moves or is
// mounted elsewhere, as long as the repository keeps its place next to it.
// Existing files are left alone unless Force is set.
func Init(root string, o InitOptions) (InitResult, error) {
	var res InitResult
	if root == "" {
		root = "."
	}
	for _, name := range defaults.Names() {
		if err := res.write(root, name, defaults.Layout()[name], o.Force); err != nil {
			return res, err
		}
	}

	next := fmt.Sprintf("Next: run `cvewatch -root %s doctor`, then `cvewatch -root %s update`.", shellArg(root), shellArg(root))
	if o.Repo == "" {
		res.Notes = append(res.Notes,
			"No repository given: copy config/projects/example.yaml.example to config/projects/<yourproject>.yaml and edit it.", next)
		return res, nil
	}

	repo, err := filepath.Abs(o.Repo)
	if err != nil {
		return res, err
	}
	if fi, err := os.Stat(repo); err != nil || !fi.IsDir() {
		return res, fmt.Errorf("repository %s is not a folder", o.Repo)
	}
	name := sanitize(cmpOr(o.Project, filepath.Base(repo)))
	cfg, err := config.Load(root)
	if err != nil {
		return res, err
	}
	det, err := discovery.Scan(repo, cfg.Catalog, discovery.Options{})
	if err != nil {
		return res, err
	}
	data, maybe, err := projectFromDiscovery(name, root, det)
	if err != nil {
		return res, err
	}
	if data == nil {
		res.Notes = append(res.Notes, fmt.Sprintf(
			"Found no lockfile or technology in %s: copy config/projects/example.yaml.example to config/projects/%s.yaml and edit it.", repo, name), next)
		return res, nil
	}
	if err := res.write(root, "config/projects/"+name+".yaml", data, o.Force); err != nil {
		return res, err
	}
	res.Notes = append(res.Notes, discoveryNotes(repo, det, maybe)...)
	res.Notes = append(res.Notes,
		fmt.Sprintf("Project %q is in config/projects/%s.yaml: check the versions, they are only what the repository declares.", name, name),
		"Lockfile paths are relative to "+shellArg(root)+". In a container, mount the repository at the same place relative to the root folder.", next)
	return res, nil
}

// projectFromDiscovery builds the project file. High and medium confidence
// technologies are declared; low ones are returned so they can be offered.
// It returns nil data when there is nothing to declare.
func projectFromDiscovery(name, root string, det discovery.Result) (data []byte, maybe []discovery.TechProposal, err error) {
	f, err := projectfile.New(name)
	if err != nil {
		return nil, nil, err
	}
	var ops []projectfile.Op
	for _, t := range det.Techs {
		if t.Confidence == discovery.Low {
			maybe = append(maybe, t)
			continue
		}
		ops = append(ops, projectfile.Op{Kind: "set_tech", Tech: t.Tech, Version: t.Version})
	}
	for _, l := range det.Lockfiles {
		path := filepath.Join(det.Root, filepath.FromSlash(l.Path))
		if rel, err := filepath.Rel(root, path); err == nil {
			path = rel
		}
		ops = append(ops, projectfile.Op{Kind: "add_lockfile", Lockfile: model.Lockfile{Type: l.Type, Path: filepath.ToSlash(path)}})
	}
	if len(ops) == 0 {
		return nil, maybe, nil
	}
	if err := f.Apply(ops...); err != nil {
		return nil, nil, err
	}
	data, err = f.Bytes()
	return data, maybe, err
}

func discoveryNotes(repo string, det discovery.Result, maybe []discovery.TechProposal) []string {
	var out []string
	if len(det.Lockfiles) > 0 {
		var parts []string
		for _, l := range det.Lockfiles {
			parts = append(parts, fmt.Sprintf("%s (%s)", l.Path, l.Type))
		}
		out = append(out, fmt.Sprintf("Found in %s: %s.", repo, strings.Join(parts, ", ")))
	}
	var parts []string
	for _, t := range det.Techs {
		if t.Confidence != discovery.Low {
			parts = append(parts, strings.TrimSpace(t.Tech+" "+t.Version))
		}
	}
	if len(parts) > 0 {
		out = append(out, "Technologies: "+strings.Join(parts, ", ")+".")
	}
	if len(maybe) > 0 {
		var names []string
		for _, t := range maybe {
			names = append(names, t.Tech)
		}
		out = append(out, "Possible, not declared (low confidence, confirm with `cvewatch discover`): "+strings.Join(names, ", ")+".")
	}
	if det.Truncated {
		out = append(out, "The repository is large: only part of it was scanned.")
	}
	return out
}

// write stores one file, creating its folder, unless it exists and force is off.
func (r *InitResult) write(root, rel string, data []byte, force bool) error {
	path := filepath.Join(root, filepath.FromSlash(rel))
	if _, err := os.Lstat(path); err == nil && !force {
		r.Skipped = append(r.Skipped, rel)
		return nil
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return err
	}
	r.Written = append(r.Written, rel)
	return nil
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func shellArg(s string) string {
	if strings.ContainsAny(s, " \t'\"") {
		return strconv.Quote(s)
	}
	return s
}

var nonName = regexp.MustCompile(`[^a-z0-9]+`)

// sanitize makes a project name of [a-z0-9-].
func sanitize(s string) string {
	s = strings.Trim(nonName.ReplaceAllString(strings.ToLower(s), "-"), "-")
	if s == "" {
		return "project"
	}
	return s
}

type foundFile struct{ typ, name string }
