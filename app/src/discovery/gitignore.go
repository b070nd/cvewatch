package discovery

import (
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode"
)

const maxIgnoreFile = 1 << 20

// Ignore answers whether git would ignore a path below a folder, from the
// .gitignore files between the repository root (the nearest folder with a
// .git, found upwards) and the path, and .git/info/exclude. It reads files
// lazily and never runs git. The folder it was made for, and the folders
// above it, are never themselves ignored: the user chose to be there.
type Ignore struct {
	start, top, home string
	rules            map[string][]rule // folder -> rules in force inside it, lowest precedence first
	dirs             map[string]bool   // folder -> ignored
}

// rule is one parsed .gitignore line.
type rule struct {
	segs     []string // glob segments; one segment when not anchored
	toks     [][]tok  // the segments compiled
	negate   bool
	dirOnly  bool
	anchored bool   // matches the path from base, not the name at any depth
	base     string // folder of the .gitignore
}

// NewIgnore prepares the rules for the paths below dir.
func NewIgnore(dir string) *Ignore {
	g := &Ignore{start: filepath.Clean(dir), rules: map[string][]rule{}, dirs: map[string]bool{}}
	if h, err := os.UserHomeDir(); err == nil {
		g.home = filepath.Clean(h)
	}
	g.top = g.findTop()
	return g
}

// findTop is the nearest folder at or above start that holds a .git. The home
// folder never counts: a dotfiles repository there must not hide everything.
func (g *Ignore) findTop() string {
	for dir := g.start; ; {
		if dir != g.home && exists(filepath.Join(dir, ".git")) {
			return dir
		}
		up := filepath.Dir(dir)
		if up == dir {
			return g.start
		}
		dir = up
	}
}

func exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

// Ignored says whether path (absolute, below the folder given to NewIgnore) is
// ignored. A path inside an ignored folder is ignored whatever a later
// pattern says, as in git.
func (g *Ignore) Ignored(path string, isDir bool) bool {
	rel, err := filepath.Rel(g.start, path)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+sep) {
		return false
	}
	segs := strings.Split(filepath.ToSlash(rel), "/")
	dir := g.start
	for _, seg := range segs[:len(segs)-1] {
		dir = filepath.Join(dir, seg)
		if g.dirIgnored(dir) {
			return true
		}
	}
	return g.verdict(path, isDir)
}

func (g *Ignore) dirIgnored(dir string) bool {
	v, ok := g.dirs[dir]
	if !ok {
		v = g.verdict(dir, true)
		g.dirs[dir] = v
	}
	return v
}

// verdict applies the rules in force in path's folder; the last match wins.
func (g *Ignore) verdict(path string, isDir bool) bool {
	if filepath.Base(path) == ".git" {
		return true
	}
	rs := g.rulesIn(filepath.Dir(path))
	for i := len(rs) - 1; i >= 0; i-- {
		if rs[i].matches(path, isDir) {
			return !rs[i].negate
		}
	}
	return false
}

// rulesIn is the rules in force inside dir: those of every folder from the
// repository root down, ending with dir's own .gitignore. A nested repository
// does not inherit the rules above it.
func (g *Ignore) rulesIn(dir string) []rule {
	if rs, ok := g.rules[dir]; ok {
		return rs
	}
	var rs []rule
	switch {
	case dir == g.top:
		rs = parseIgnoreFile(filepath.Join(dir, ".git", "info", "exclude"), dir)
	case dir == filepath.Dir(dir) || !under(g.top, dir):
		// outside the repository, or the file system root: nothing applies
	default:
		rs = g.rulesIn(filepath.Dir(dir))
		if exists(filepath.Join(dir, ".git")) {
			rs = nil
		}
	}
	if dir != g.home {
		rs = slices.Concat(rs, parseIgnoreFile(filepath.Join(dir, ".gitignore"), dir))
	}
	g.rules[dir] = rs
	return rs
}

func under(parent, p string) bool {
	rel, err := filepath.Rel(parent, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+sep)
}

func parseIgnoreFile(file, base string) []rule {
	fh, err := os.Open(file)
	if err != nil {
		return nil
	}
	defer fh.Close()
	data, err := io.ReadAll(io.LimitReader(fh, maxIgnoreFile))
	if err != nil {
		return nil
	}
	return parseRules(strings.TrimPrefix(string(data), "\ufeff"), base)
}

func parseRules(text, base string) []rule {
	var out []rule
	for _, line := range strings.Split(text, "\n") {
		if r, ok := parseRule(line, base); ok {
			out = append(out, r)
		}
	}
	return out
}

// parseRule reads one line of the gitignore(5) format.
func parseRule(line, base string) (rule, bool) {
	line = strings.TrimSuffix(line, "\r")
	if line == "" || line[0] == '#' {
		return rule{}, false
	}
	for strings.HasSuffix(line, " ") && !escaped(line, len(line)-1) { // trailing spaces count only when escaped
		line = line[:len(line)-1]
	}
	r := rule{base: base}
	if strings.HasPrefix(line, "!") {
		r.negate, line = true, line[1:]
	}
	if strings.HasSuffix(line, "/") {
		r.dirOnly, line = true, strings.TrimSuffix(line, "/")
	}
	r.anchored = strings.Contains(line, "/")
	line = strings.TrimPrefix(line, "/")
	if line == "" {
		return rule{}, false
	}
	r.segs = strings.Split(line, "/")
	for _, s := range r.segs {
		r.toks = append(r.toks, compileSeg(s))
	}
	return r, true
}

// escaped says whether the byte at i is preceded by an odd number of backslashes.
func escaped(s string, i int) bool {
	n := 0
	for i--; i >= 0 && s[i] == '\\'; i-- {
		n++
	}
	return n%2 == 1
}

func (r rule) matches(path string, isDir bool) bool {
	if r.dirOnly && !isDir {
		return false
	}
	if !r.anchored {
		return matchToks(r.toks[0], []rune(filepath.Base(path)))
	}
	rel, err := filepath.Rel(r.base, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+sep) {
		return false
	}
	return matchPath(r.segs, r.toks, strings.Split(filepath.ToSlash(rel), "/"))
}

// matchPath matches pattern segments against path segments; a ** segment
// stands for any number of folders, and a trailing ** for everything inside.
func matchPath(segs []string, toks [][]tok, path []string) bool {
	if len(segs) == 0 {
		return len(path) == 0
	}
	if segs[0] == "**" {
		if len(segs) == 1 {
			return len(path) > 0
		}
		for i := 0; i <= len(path); i++ {
			if matchPath(segs[1:], toks[1:], path[i:]) {
				return true
			}
		}
		return false
	}
	return len(path) > 0 && matchToks(toks[0], []rune(path[0])) && matchPath(segs[1:], toks[1:], path[1:])
}

type tokKind int

const (
	tLit   tokKind = iota // one given character
	tAny                  // ?
	tStar                 // *
	tClass                // [...]
	tNever                // an invalid escape: the pattern matches nothing
)

type tok struct {
	kind  tokKind
	r     rune
	class charClass
}

type charClass struct {
	neg    bool
	ranges [][2]rune
	named  []func(rune) bool
}

func (c charClass) has(r rune) bool {
	in := false
	for _, rg := range c.ranges {
		if r >= rg[0] && r <= rg[1] {
			in = true
		}
	}
	for _, f := range c.named {
		if f(r) {
			in = true
		}
	}
	return in != c.neg
}

var posixClasses = map[string]func(rune) bool{
	"alpha": unicode.IsLetter, "digit": unicode.IsDigit, "alnum": func(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) },
	"upper": unicode.IsUpper, "lower": unicode.IsLower, "space": unicode.IsSpace, "punct": unicode.IsPunct,
	"xdigit": func(r rune) bool { return r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F' },
}

// compileSeg turns one pattern segment into tokens; a ** inside a longer
// segment is an ordinary *.
func compileSeg(s string) []tok {
	p := []rune(s)
	var out []tok
	for i := 0; i < len(p); i++ {
		switch p[i] {
		case '*':
			if n := len(out); n == 0 || out[n-1].kind != tStar {
				out = append(out, tok{kind: tStar})
			}
		case '?':
			out = append(out, tok{kind: tAny})
		case '\\':
			if i+1 >= len(p) {
				return []tok{{kind: tNever}}
			}
			i++
			out = append(out, tok{kind: tLit, r: p[i]})
		case '[':
			if c, n, ok := parseClass(p[i:]); ok {
				out = append(out, tok{kind: tClass, class: c})
				i += n - 1
				continue
			}
			out = append(out, tok{kind: tLit, r: '['}) // no closing bracket: a plain [
		default:
			out = append(out, tok{kind: tLit, r: p[i]})
		}
	}
	return out
}

// parseClass reads [abc], [a-z], [!x], [^x] and [[:digit:]] at the start of p
// and returns how many runes it used.
func parseClass(p []rune) (charClass, int, bool) {
	var c charClass
	i := 1
	if i < len(p) && (p[i] == '!' || p[i] == '^') {
		c.neg, i = true, i+1
	}
	first := true
	for i < len(p) {
		r := p[i]
		switch {
		case r == ']' && !first:
			return c, i + 1, true
		case r == '[' && i+1 < len(p) && p[i+1] == ':':
			end := slices.Index(p[i+2:], ':')
			if end >= 0 && i+2+end+1 < len(p) && p[i+2+end+1] == ']' {
				if f, ok := posixClasses[string(p[i+2:i+2+end])]; ok {
					c.named = append(c.named, f)
					i += end + 4
					first = false
					continue
				}
			}
		case r == '\\' && i+1 < len(p):
			i++
			r = p[i]
		}
		lo, hi := r, r
		if i+2 < len(p) && p[i+1] == '-' && p[i+2] != ']' {
			hi = p[i+2]
			i += 2
			if hi == '\\' && i+1 < len(p) {
				i++
				hi = p[i]
			}
		}
		c.ranges = append(c.ranges, [2]rune{lo, hi})
		i++
		first = false
	}
	return c, 0, false
}

// matchToks is wildcard matching without recursion: on a mismatch it retries
// from the last *, so it stays fast on long names.
func matchToks(toks []tok, s []rune) bool {
	ti, si, star, mark := 0, 0, -1, 0
	for si < len(s) {
		if ti < len(toks) {
			t := toks[ti]
			ok := false
			switch t.kind {
			case tStar:
				star, mark = ti, si
				ti++
				continue
			case tLit:
				ok = t.r == s[si]
			case tAny:
				ok = true
			case tClass:
				ok = t.class.has(s[si])
			case tNever:
				return false
			}
			if ok {
				ti, si = ti+1, si+1
				continue
			}
		}
		if star < 0 {
			return false
		}
		mark++
		ti, si = star+1, mark
	}
	for ti < len(toks) && toks[ti].kind == tStar {
		ti++
	}
	return ti == len(toks)
}
