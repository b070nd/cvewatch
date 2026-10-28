package doctor

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/b070nd/cvewatch/app/src/defaults"
)

// InitOptions controls Init.
type InitOptions struct {
	Force   bool   // overwrite files that already exist
	Repo    string // a repository to look at for lockfiles and runtime versions
	Project string // project name; default is the repository folder's name
}

// InitResult lists paths relative to the root, and plain-English next steps.
type InitResult struct {
	Written, Skipped, Notes []string
}

// Init writes the shipped starter files under root and, when Repo is set, a
// project file describing what it found at the top level of that repository.
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
	det, err := detect(repo)
	if err != nil {
		return res, err
	}
	if len(det.files) == 0 && len(det.techs) == 0 {
		res.Notes = append(res.Notes, fmt.Sprintf(
			"Found no lockfile or version file at the top of %s: copy config/projects/example.yaml.example to config/projects/%s.yaml and edit it.", repo, name), next)
		return res, nil
	}
	if err := res.write(root, "config/projects/"+name+".yaml", det.projectFile(name, repo), o.Force); err != nil {
		return res, err
	}
	res.Notes = append(res.Notes, det.notes(repo)...)
	res.Notes = append(res.Notes, fmt.Sprintf("Project %q is in config/projects/%s.yaml: check the versions, they are only what the repository declares.", name, name), next)
	return res, nil
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

// detection is what the top level of a repository declares.
type detection struct {
	files []foundFile       // lockfiles, in directory order
	techs map[string]string // tech name -> version, "" when unknown
}

func (d *detection) tech(name, version string) {
	if d.techs == nil {
		d.techs = map[string]string{}
	}
	if version != "" || d.techs[name] == "" {
		d.techs[name] = version
	}
}

var (
	// lockTypes maps exact file names; the tech list says what each implies.
	lockTypes = map[string]struct {
		typ  string
		tech string
	}{
		"composer.lock":     {"composer", "php"},
		"package-lock.json": {"npm", "nodejs"},
		"go.mod":            {"go", "go"},
		"requirements.txt":  {"pip", "python"},
		"poetry.lock":       {"poetry", "python"},
		"Pipfile.lock":      {"pipfile", "python"},
		"gradle.lockfile":   {"gradle", ""},
		"pom.xml":           {"maven", ""},
		"bom.json":          {"cyclonedx", ""},
		"sbom.json":         {"cyclonedx", ""},
	}
	// versionFiles hold one runtime version each.
	versionFiles = map[string]string{
		".nvmrc": "nodejs", ".node-version": "nodejs", ".php-version": "php", ".python-version": "python",
	}
	versionLike = regexp.MustCompile(`^\d+(\.\d+){0,2}$`)
	goDirective = regexp.MustCompile(`(?m)^go\s+(\d+)\.(\d+)`)
)

func detect(repo string) (detection, error) {
	var d detection
	entries, err := os.ReadDir(repo)
	if err != nil {
		return d, err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		switch lt, ok := lockTypes[n]; {
		case ok:
			d.files = append(d.files, foundFile{lt.typ, n})
			if lt.tech != "" {
				d.tech(lt.tech, "")
			}
		case strings.HasSuffix(n, ".cdx.json"):
			d.files = append(d.files, foundFile{"cyclonedx", n})
		case strings.HasSuffix(n, ".spdx.json"):
			d.files = append(d.files, foundFile{"spdx", n})
		}
	}
	// Versions come second so a version file also implies its tech.
	if v := goVersion(filepath.Join(repo, "go.mod")); v != "" {
		d.tech("go", v)
	}
	for file, tech := range versionFiles {
		if v := firstLine(filepath.Join(repo, file)); versionLike.MatchString(v) {
			d.tech(tech, v)
		}
	}
	return d, nil
}

// readSmall reads at most limit bytes of a regular file; a missing file is "".
func readSmall(path string, limit int64) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	b, _ := io.ReadAll(io.LimitReader(f, limit))
	return string(b)
}

func firstLine(path string) string {
	first, _, _ := strings.Cut(readSmall(path, 1024), "\n")
	return strings.TrimPrefix(strings.TrimSpace(first), "v")
}

// goVersion returns the go directive of a go.mod as a series, "1.22".
func goVersion(path string) string {
	m := goDirective.FindStringSubmatch(readSmall(path, 1<<20))
	if m == nil {
		return ""
	}
	return m[1] + "." + m[2]
}

func (d detection) techNames() []string {
	names := make([]string, 0, len(d.techs))
	for n := range d.techs {
		names = append(names, n)
	}
	slices.Sort(names)
	return names
}

func (d detection) projectFile(name, repo string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "# Project %s, detected by `cvewatch init` from %s.\n", name, repo)
	b.WriteString("# Versions are what the repository declares; set the ones actually deployed per\n")
	b.WriteString("# environment under `environments:` if they differ. Lockfiles are re-read every run.\n")
	fmt.Fprintf(&b, "name: %s\n", name)
	if len(d.techs) == 0 {
		b.WriteString("techs: []\n")
	} else {
		b.WriteString("techs:\n")
		for _, t := range d.techNames() {
			if v := d.techs[t]; v != "" {
				fmt.Fprintf(&b, "  - {name: %s, version: %s}\n", t, strconv.Quote(v))
			} else {
				fmt.Fprintf(&b, "  - {name: %s}\n", t)
			}
		}
	}
	if len(d.files) == 0 {
		b.WriteString("lockfiles: []\n")
	} else {
		b.WriteString("lockfiles:\n")
		for _, f := range d.files {
			fmt.Fprintf(&b, "  - {type: %s, path: %s}\n", f.typ, strconv.Quote(filepath.Join(repo, f.name)))
		}
	}
	return []byte(b.String())
}

func (d detection) notes(repo string) []string {
	var out []string
	if len(d.files) > 0 {
		var parts []string
		for _, f := range d.files {
			parts = append(parts, fmt.Sprintf("%s (%s)", f.name, f.typ))
		}
		out = append(out, fmt.Sprintf("Found in %s: %s.", repo, strings.Join(parts, ", ")))
	}
	if len(d.techs) > 0 {
		var parts []string
		for _, t := range d.techNames() {
			parts = append(parts, strings.TrimSpace(t+" "+d.techs[t]))
		}
		out = append(out, "Technologies: "+strings.Join(parts, ", ")+".")
	}
	return out
}
