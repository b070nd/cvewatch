// Package discovery looks at a folder (a repository or a monorepo) and
// proposes the technologies, versions and inventory sources it finds, each
// with the evidence behind it, so a wizard, a TUI or an agent can answer
// "why do you think we run nginx?". It only reads; it never writes a project
// file and never runs anything from the folder, which is treated as untrusted.
package discovery

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/b070nd/cvewatch/app/src/catalog"
	"github.com/b070nd/cvewatch/app/src/matrix"
	"github.com/b070nd/cvewatch/app/src/model"
)

// Confidence says how much a proposal can be trusted.
type Confidence string

const (
	High   Confidence = "high"
	Medium Confidence = "medium"
	Low    Confidence = "low"
)

func (c Confidence) rank() int {
	switch c {
	case High:
		return 3
	case Medium:
		return 2
	}
	return 1
}

// Evidence is one reason for a proposal.
type Evidence struct {
	File   string `json:"file"` // relative to the scanned root, forward slashes
	Detail string `json:"detail"`
}

// TechProposal is one catalog technology the folder seems to use.
type TechProposal struct {
	Tech       string     `json:"tech"` // catalog name
	Title      string     `json:"title"`
	Version    string     `json:"version"` // empty means unknown
	Confidence Confidence `json:"confidence"`
	Evidence   []Evidence `json:"evidence"`
	// Infra is true when the technology only appears in container or
	// orchestration files (base images, compose services, Kubernetes images,
	// packages installed in a Dockerfile); Category is then its catalog
	// category, so a UI can group infrastructure.
	Infra    bool   `json:"infra,omitempty"`
	Category string `json:"category,omitempty"`
}

// LockProposal is a file cvewatch can read as an inventory source.
type LockProposal struct {
	Type     string `json:"type"`
	Path     string `json:"path"`     // relative to the scanned root, forward slashes
	Packages int    `json:"packages"` // how many packages it yielded, 0 if unreadable
}

// Result is everything a scan found.
type Result struct {
	Root      string         `json:"root"`           // absolute; the parent folder when a single file was scanned
	File      string         `json:"file,omitempty"` // absolute, set when a single file was scanned
	Techs     []TechProposal `json:"techs"`
	Lockfiles []LockProposal `json:"lockfiles"`
	Notes     []string       `json:"notes"`
	Truncated bool           `json:"truncated"`
}

// Options bounds a scan. Zero values mean the defaults.
type Options struct {
	MaxDepth    int   // default 3; the scanned root is depth 0
	MaxFiles    int   // default 3000 files visited
	MaxFileSize int64 // default 1 MiB read per file
}

const (
	maxEvidence = 8
	hintBytes   = 4 << 10
	yamlMax     = 256 << 10
)

// skipDirs are never entered: dependencies, build output and tool caches.
var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, "dist": true, "build": true,
	"target": true, ".venv": true, "venv": true, "__pycache__": true, ".terraform": true,
	".gradle": true, ".idea": true, ".next": true, ".cache": true,
}

// hit is one detector's claim about one technology.
type hit struct {
	tech    model.Tech
	version string
	conf    Confidence
	file    string
	detail  string
	claim   string // what the file says, for notes: "says 8.2" or "requires >=8.1"
	quiet   bool   // never worth a disagreement note (a dependency range)
	infra   bool   // came from a container or orchestration file
}

type hint struct {
	tech model.Tech
	re   *regexp.Regexp
}

type scanner struct {
	cat   *catalog.Catalog
	o     Options
	hints map[string][]hint // lowercase file name -> version hints
	hits  []hit
	locks []LockProposal
	notes map[string]bool
	big   bool
	trunc bool
	one   bool // a single file is scanned, so unresolved variables are worth a note
}

// file is one regular file being looked at; its content is read at most once.
type file struct {
	s         *scanner
	abs, rel  string
	base, low string
	size      int64
	data      []byte
	loaded    bool
}

// Scan inspects dir. It fails only when dir is not a readable directory;
// everything else a detector trips over becomes a Note.
func Scan(dir string, cat *catalog.Catalog, o Options) (Result, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return Result{}, err
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return Result{}, err
	}
	if fi, err := os.Stat(real); err != nil || !fi.IsDir() {
		return Result{}, fmt.Errorf("discovery: %s is not a directory", dir)
	}
	if _, err := os.ReadDir(real); err != nil {
		return Result{}, fmt.Errorf("discovery: cannot read %s: %w", dir, err)
	}
	if cat == nil {
		cat = catalog.New(nil)
	}
	if o.MaxDepth <= 0 {
		o.MaxDepth = 3
	}
	if o.MaxFiles <= 0 {
		o.MaxFiles = 3000
	}
	if o.MaxFileSize <= 0 {
		o.MaxFileSize = 1 << 20
	}
	s := &scanner{cat: cat, o: o, notes: map[string]bool{}}
	s.compileHints()
	s.walk(real)
	return s.result(abs), nil
}

func (s *scanner) note(format string, a ...any) { s.notes[fmt.Sprintf(format, a...)] = true }

// compileHints compiles every catalog version regexp once, ignoring bad ones.
func (s *scanner) compileHints() {
	s.hints = map[string][]hint{}
	for _, t := range s.cat.All() {
		for _, v := range t.Detect.Versions {
			re, err := regexp.Compile(v.Pattern)
			if err != nil || re.NumSubexp() != 1 || v.File == "" {
				continue
			}
			k := strings.ToLower(v.File)
			s.hints[k] = append(s.hints[k], hint{t, re})
		}
	}
}

func (s *scanner) walk(root string) {
	files := 0
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if p == root {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if err != nil {
			s.note("cannot read %s", rel)
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil // never follow links
		}
		if d.IsDir() {
			if skipDirs[d.Name()] || strings.Count(rel, "/")+1 > s.o.MaxDepth {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if files++; files > s.o.MaxFiles {
			s.trunc = true
			s.note("stopped after %d files; the folder has more", s.o.MaxFiles)
			return fs.SkipAll
		}
		info, err := d.Info()
		if err != nil {
			s.note("cannot read %s", rel)
			return nil
		}
		s.file(&file{s: s, abs: p, rel: rel, base: d.Name(), low: strings.ToLower(d.Name()), size: info.Size()})
		return nil
	})
}

// file runs every detector on f; one failing never stops the others.
func (s *scanner) file(f *file) {
	detectors := []struct {
		name string
		fn   func(*file)
	}{
		{"lockfile", s.lockfile}, {"marker", s.marker}, {"version hint", s.versionHints},
		{"asdf", s.toolVersions}, {"go.mod", s.goMod}, {"package.json", s.packageJSON},
		{"composer.json", s.composerJSON}, {"dockerfile", s.dockerfile},
		{"yaml", s.yamlFile}, {"terraform", s.terraform},
	}
	for _, d := range detectors {
		func() {
			defer func() {
				if r := recover(); r != nil {
					s.note("%s detector failed on %s: %v", d.name, f.rel, r)
				}
			}()
			d.fn(f)
		}()
	}
}

// bytes returns the file content, or nil when it is too large or unreadable.
func (f *file) bytes() []byte {
	if f.loaded {
		return f.data
	}
	f.loaded = true
	if f.size > f.s.o.MaxFileSize {
		if !f.s.big {
			f.s.big = true
			f.s.note("files larger than %d bytes were not read", f.s.o.MaxFileSize)
		}
		return nil
	}
	fh, err := os.Open(f.abs)
	if err != nil {
		f.s.note("cannot read %s", f.rel)
		return nil
	}
	defer fh.Close()
	f.data, err = io.ReadAll(io.LimitReader(fh, f.s.o.MaxFileSize))
	if err != nil {
		f.s.note("cannot read %s", f.rel)
		f.data = nil
	}
	return f.data
}

// add records a hit for the file.
func (s *scanner) add(f *file, t model.Tech, version string, c Confidence, detail string) *hit {
	s.hits = append(s.hits, hit{tech: t, version: version, conf: c, file: f.rel, detail: detail})
	return &s.hits[len(s.hits)-1]
}

// ---- detectors ----

// lockfile (1, 2): readable inventory sources, and the technologies their packages imply.
func (s *scanner) lockfile(f *file) {
	typ, ok := matrix.DetectType(f.base)
	if !ok {
		return
	}
	lp := LockProposal{Type: typ, Path: f.rel}
	defer func() { s.locks = append(s.locks, lp) }()
	if f.size > s.o.MaxFileSize*8 {
		s.note("lockfile %s is too large to read", f.rel)
		return
	}
	res, err := matrix.LoadResult(model.Lockfile{Type: typ, Path: f.abs})
	if err != nil {
		s.note("cannot read lockfile %s", f.rel)
		return
	}
	lp.Packages = len(res.Packages)
	for _, p := range res.Packages {
		if t, ok := s.cat.ForPackage(p.Ecosystem, p.Name); ok {
			s.add(f, t, p.Version, High, fmt.Sprintf("package %s in %s", p.Name, f.rel))
		}
	}
}

// marker (11): file names that give a technology away.
func (s *scanner) marker(f *file) {
	for _, t := range s.cat.ForFile(f.base) {
		s.add(f, t, "", Low, "marker file "+f.base).infra = isDockerfile(f.low) || isComposeFile(f.low)
	}
}

var (
	exactVersion = regexp.MustCompile(`^v?[0-9]+(\.[0-9]+)*$`)
	numberGroup  = regexp.MustCompile(`[0-9]+(\.[0-9]+)*`)
)

// versionHints (3): the catalog says which file holds which version.
func (s *scanner) versionHints(f *file) {
	hs := s.hints[f.low]
	if len(hs) == 0 {
		return
	}
	data := f.bytes()
	if len(data) > hintBytes {
		data = data[:hintBytes]
	}
	for _, h := range hs {
		m := h.re.FindStringSubmatch(string(data))
		if m == nil || strings.TrimSpace(m[1]) == "" {
			continue
		}
		v, c := strings.TrimSpace(m[1]), Medium
		if exactVersion.MatchString(v) {
			v, c = strings.TrimPrefix(v, "v"), High
		}
		s.add(f, h.tech, v, c, fmt.Sprintf("version %s read from %s", v, f.base))
	}
}

// toolVersions (4): asdf pins "<plugin> <version>".
func (s *scanner) toolVersions(f *file) {
	if f.low != ".tool-versions" {
		return
	}
	for _, line := range strings.Split(string(f.bytes()), "\n") {
		line, _, _ = strings.Cut(line, "#")
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		t, ok := s.cat.ForTerm(parts[0])
		if !ok {
			continue
		}
		v, c := strings.TrimPrefix(parts[1], "v"), High
		if v == "" || v[0] < '0' || v[0] > '9' { // "system", "ref:..."
			v, c = "", Low
		}
		s.add(f, t, v, c, "asdf pins "+parts[0]+" "+parts[1])
	}
}

var goDirective = regexp.MustCompile(`(?m)^go\s+([0-9]+(?:\.[0-9]+)*)`)

// goMod (5): the `go 1.22` directive is the language series.
func (s *scanner) goMod(f *file) {
	if f.low != "go.mod" {
		return
	}
	m := goDirective.FindStringSubmatch(string(f.bytes()))
	if t, ok := s.cat.ForTerm("go"); ok && m != nil {
		s.add(f, t, m[1], High, "go directive "+m[1])
	}
}

// series reduces a constraint such as ">=18" or "^20.1.0" to its first
// number group, cut to at most two parts ("18", "20.1"). The bool is true
// when the constraint was already an exact version.
func series(constraint string) (string, bool) {
	c := strings.TrimSpace(constraint)
	if exactVersion.MatchString(c) {
		return strings.TrimPrefix(c, "v"), true
	}
	v := numberGroup.FindString(c)
	if parts := strings.Split(v, "."); len(parts) > 2 {
		v = strings.Join(parts[:2], ".")
	}
	return v, false
}

// depVersion is the first version number of a dependency constraint, or "".
func depVersion(constraint string) string {
	if strings.ContainsAny(constraint, "/:") { // git, file and workspace specs
		return ""
	}
	return numberGroup.FindString(constraint)
}

// runtimeHit records an engines/require constraint for a language runtime.
func (s *scanner) runtimeHit(f *file, term, where, constraint string) {
	t, ok := s.cat.ForTerm(term)
	if !ok || constraint == "" {
		return
	}
	v, exact := series(constraint)
	if v == "" {
		return
	}
	h := s.add(f, t, v, Low, where+" "+constraint)
	if exact {
		h.conf, h.claim = High, "says "+v
	} else {
		h.claim = "requires " + constraint
	}
}

// depHits records dependency names, which imply technologies with only a weak version.
func (s *scanner) depHits(f *file, eco string, deps map[string]any) {
	names := make([]string, 0, len(deps))
	for n := range deps {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		t, ok := s.cat.ForPackage(eco, n)
		if !ok {
			continue
		}
		c, _ := deps[n].(string)
		h := s.add(f, t, depVersion(c), Low, fmt.Sprintf("dependency %s %s in %s", n, c, f.base))
		h.quiet = true
	}
}

func asMap(v any) map[string]any { m, _ := v.(map[string]any); return m }

func (s *scanner) readJSON(f *file) map[string]any {
	var doc map[string]any
	if err := json.Unmarshal(f.bytes(), &doc); err != nil {
		s.note("%s is not valid JSON", f.rel)
		return nil
	}
	return doc
}

// packageJSON (6): engines.node and npm dependencies.
func (s *scanner) packageJSON(f *file) {
	if f.low != "package.json" {
		return
	}
	doc := s.readJSON(f)
	if v, ok := asMap(doc["engines"])["node"].(string); ok {
		s.runtimeHit(f, "nodejs", "engines.node", v)
	}
	s.depHits(f, "npm", asMap(doc["dependencies"]))
	s.depHits(f, "npm", asMap(doc["devDependencies"]))
}

// composerJSON (6): require.php and composer packages.
func (s *scanner) composerJSON(f *file) {
	if f.low != "composer.json" {
		return
	}
	doc := s.readJSON(f)
	req := asMap(doc["require"])
	if v, ok := req["php"].(string); ok {
		s.runtimeHit(f, "php", "require.php", v)
	}
	s.depHits(f, "composer", req)
}

// ---- container images ----

// tagVersion is the leading digits-and-dots run of an image tag, or "".
func tagVersion(ref string) string {
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	i := strings.LastIndex(ref, ":")
	if i < 0 || strings.Contains(ref[i:], "/") {
		return ""
	}
	tag := ref[i+1:]
	n := 0
	for n < len(tag) && (tag[n] == '.' || tag[n] >= '0' && tag[n] <= '9') {
		n++
	}
	v := strings.Trim(tag[:n], ".")
	if v == "" || tag[0] == '.' {
		return ""
	}
	return v
}

// image handles one image reference from any detector (7 to 10).
func (s *scanner) image(f *file, ref string) {
	ref = strings.TrimSpace(ref)
	if ref == "" || ref == "scratch" {
		return
	}
	if strings.Contains(ref, "$") {
		if s.one {
			s.note("%s: image %s uses a variable with no default", f.rel, ref)
		}
		return
	}
	t, ok := s.cat.ForImage(ref)
	if !ok {
		return
	}
	v, c := tagVersion(ref), Medium
	if v == "" {
		v = codenameVersion(t.Name, ref)
	}
	if v == "" {
		c = Low
	}
	s.add(f, t, v, c, "image "+ref).infra = true
}

// yamlFile (8, 9): compose files and Kubernetes manifests.
func (s *scanner) yamlFile(f *file) {
	if !strings.HasSuffix(f.low, ".yaml") && !strings.HasSuffix(f.low, ".yml") || f.size > yamlMax {
		return
	}
	data := f.bytes()
	if strings.HasPrefix(f.low, "docker-compose") || strings.HasPrefix(f.low, "compose") {
		s.compose(f, data)
		return
	}
	s.kubernetes(f, data)
}
