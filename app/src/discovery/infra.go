package discovery

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/b070nd/cvewatch/app/src/catalog"
	"github.com/b070nd/cvewatch/app/src/matrix"
)

func isDockerfile(low string) bool {
	return strings.HasPrefix(low, "dockerfile") || strings.HasSuffix(low, ".dockerfile") ||
		strings.HasPrefix(low, "containerfile") || strings.HasSuffix(low, ".containerfile")
}

func isComposeFile(low string) bool {
	return (strings.HasSuffix(low, ".yaml") || strings.HasSuffix(low, ".yml")) &&
		(strings.HasPrefix(low, "docker-compose") || strings.HasPrefix(low, "compose"))
}

// SupportedFile says whether ScanFile can read a file of this name: a
// Dockerfile or Containerfile, a compose file or Kubernetes manifest (any
// yaml), Terraform, or a lockfile.
func SupportedFile(name string) bool {
	low := strings.ToLower(filepath.Base(name))
	if isDockerfile(low) || strings.HasSuffix(low, ".yaml") || strings.HasSuffix(low, ".yml") || strings.HasSuffix(low, ".tf") {
		return true
	}
	_, ok := matrix.DetectType(filepath.Base(name))
	return ok
}

// ErrIgnored is returned for a file git ignores, unless Options.IncludeIgnored is set.
var ErrIgnored = errors.New("ignored by .gitignore")

type ignoredError string

func (e ignoredError) Error() string        { return "discovery: " + string(e) + " is ignored by .gitignore" }
func (e ignoredError) Is(target error) bool { return target == ErrIgnored }

// ScanFile inspects one file with the same detectors a folder scan uses on it.
// Root is the folder the file is in, so a project name can default to it, and
// evidence names the file without a path.
func ScanFile(path string, cat *catalog.Catalog, o Options) (Result, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return Result{}, err
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return Result{}, err
	}
	fi, err := os.Stat(real)
	if err != nil || !fi.Mode().IsRegular() {
		return Result{}, fmt.Errorf("discovery: %s is not a file", path)
	}
	base := filepath.Base(abs)
	if !SupportedFile(base) {
		return Result{}, errors.New("discovery: " + base + " is not a Dockerfile, compose file, Kubernetes manifest, Terraform file or lockfile")
	}
	if !o.IncludeIgnored && NewIgnore(filepath.Dir(abs)).Ignored(abs, false) {
		return Result{}, ignoredError(base)
	}
	if cat == nil {
		cat = catalog.New(nil)
	}
	if o.MaxFileSize <= 0 {
		o.MaxFileSize = 1 << 20
	}
	s := &scanner{cat: cat, o: o, notes: map[string]bool{}, one: true}
	s.compileHints()
	s.file(&file{s: s, abs: real, rel: base, base: base, low: strings.ToLower(base), size: fi.Size()})
	res := s.result(filepath.Dir(abs))
	res.File = abs
	return res, nil
}

var varRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(?:(:?)([-+])([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)`)

// expandVars substitutes $X, ${X}, ${X:-default} and ${X-default} from vars; a
// reference that cannot be resolved stays as written, so the caller can see it.
func expandVars(s string, vars map[string]string) string {
	if !strings.Contains(s, "$") {
		return s
	}
	return varRef.ReplaceAllStringFunc(s, func(m string) string {
		g := varRef.FindStringSubmatch(m)
		name := g[1]
		if name == "" {
			name = g[5]
		}
		v, set := vars[name]
		switch {
		case g[3] == "-" && (!set || g[2] == ":" && v == ""):
			return g[4]
		case g[3] == "+":
			return m
		case set:
			return v
		}
		return m
	})
}

// dockerLines joins continued lines and drops comments and blank lines.
func dockerLines(data []byte) []string {
	var out []string
	var cur strings.Builder
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasSuffix(line, "\\") {
			cur.WriteString(strings.TrimSuffix(line, "\\"))
			cur.WriteByte(' ')
			continue
		}
		cur.WriteString(line)
		if t := strings.TrimSpace(cur.String()); t != "" {
			out = append(out, t)
		}
		cur.Reset()
	}
	if t := strings.TrimSpace(cur.String()); t != "" {
		out = append(out, t)
	}
	return out
}

// dockerfile (7): FROM lines, skipping scratch, earlier stages and variables
// that have no default. ARG values given before the first FROM fill variables
// in the FROM lines; RUN lines that install packages are read too.
func (s *scanner) dockerfile(f *file) {
	if !isDockerfile(f.low) {
		return
	}
	args := map[string]string{}
	stages := map[string]bool{}
	seenFrom := false
	for _, line := range dockerLines(f.bytes()) {
		parts := strings.Fields(line)
		switch strings.ToUpper(parts[0]) {
		case "ARG":
			if seenFrom {
				continue // a stage's ARG cannot be used by a FROM
			}
			for _, a := range parts[1:] {
				if k, v, ok := strings.Cut(a, "="); ok {
					args[k] = strings.Trim(v, `"'`)
				}
			}
		case "RUN":
			s.packages(f, strings.TrimSpace(line[len(parts[0]):]))
		case "FROM":
			seenFrom = true
			rest := slices.DeleteFunc(parts[1:], func(a string) bool { return strings.HasPrefix(a, "--") })
			if len(rest) == 0 {
				continue
			}
			if !stages[strings.ToLower(rest[0])] {
				s.image(f, expandVars(rest[0], args))
			}
			if len(rest) >= 3 && strings.EqualFold(rest[1], "AS") {
				stages[strings.ToLower(rest[2])] = true
			}
		}
	}
}

var (
	pkgSplit     = regexp.MustCompile(`&&|\|\||[;|]`)
	pkgVersioned = regexp.MustCompile(`^([a-z][a-z-]*?)-?([0-9][0-9.]*)$`)
)

// packages (7): `apt-get install` and `apk add` words that are catalog
// technologies. A pinned version (nginx=1.24.0-1) is kept; otherwise the
// proposal is only a hint.
func (s *scanner) packages(f *file, run string) {
	for _, seg := range pkgSplit.Split(run, -1) {
		w := strings.Fields(seg)
		for len(w) > 0 && (w[0] == "sudo" || strings.Contains(w[0], "=")) {
			w = w[1:]
		}
		if len(w) < 2 {
			continue
		}
		tool, install := w[0], ""
		switch {
		case (tool == "apt-get" || tool == "apt" || tool == "apt-fast") && slices.Contains(w[1:], "install"):
			install = "install"
		case tool == "apk" && slices.Contains(w[1:], "add"):
			install = "add"
		default:
			continue
		}
		args := w[slices.Index(w, install)+1:]
		for i := 0; i < len(args); i++ {
			a := args[i]
			switch {
			case a == "--virtual" || a == "-t":
				i++ // the next word names the group, not a package
			case strings.HasPrefix(a, "-") || strings.HasPrefix(a, "."):
			default:
				s.pkg(f, tool, install, a)
			}
		}
	}
}

func (s *scanner) pkg(f *file, tool, verb, word string) {
	name, ver, _ := strings.Cut(word, "=")
	if i := strings.IndexAny(name, "~<>"); i >= 0 {
		name, ver = name[:i], strings.TrimLeft(name[i:], "~<>=")
	}
	name = strings.ToLower(name)
	if strings.ContainsAny(name, "${}\"'`") || name == "" {
		return
	}
	t, ok := s.cat.ForTerm(name)
	if !ok {
		m := pkgVersioned.FindStringSubmatch(name)
		if m == nil {
			return
		}
		if t, ok = s.cat.ForTerm(m[1]); !ok {
			return
		}
		name, ver = m[1], cmpOr(ver, m[2])
	}
	v, c := "", Low
	if ver = numberGroup.FindString(ver); ver != "" {
		v, c = strings.Trim(ver, "."), Medium
	}
	s.add(f, t, v, c, fmt.Sprintf("%s %s %s", tool, verb, word)).infra = true
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

var codenames = map[string]map[string]string{
	"debian": {"trixie": "13", "bookworm": "12", "bullseye": "11", "buster": "10", "stretch": "9"},
	"ubuntu": {"noble": "24.04", "jammy": "22.04", "focal": "20.04", "bionic": "18.04", "xenial": "16.04"},
}

// codenameVersion maps a release name tag (debian:bookworm-slim) to its version.
func codenameVersion(tech, ref string) string {
	i := strings.LastIndex(ref, ":")
	if i < 0 {
		return ""
	}
	name, _, _ := strings.Cut(strings.ToLower(ref[i+1:]), "-")
	return codenames[strings.ToLower(tech)][name]
}
