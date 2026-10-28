package version

import (
	"cmp"
	"errors"
	"math"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/b070nd/cvewatch/app/src/ecosystem"
	"github.com/b070nd/cvewatch/app/src/model"
)

// scheme is one ecosystem's idea of what a version is: how to read a string
// into a comparable key, how keys order, and which versions name a series.
// The range and evaluation logic in range.go works over any scheme.
type scheme struct {
	parse func(string) (any, bool)
	cmp   func(a, b any) int
	// series gives the exclusive end of the series that k names (such as 8.2,
	// meaning [8.2.0, 8.3.0)), or false when k is an exact version.
	series func(k any) (hi any, ok bool)
	// ops are the comparison operators of range notation, longest first.
	ops []string
	// expand turns an operator and version into bounds for notations only
	// this scheme has; handled is false to fall back to the standard reading.
	expand func(op, v string) (conds []cond, handled bool, err error)
}

// schemeFor picks the scheme of an ecosystem; unknown ones get the default.
func schemeFor(eco string) *scheme {
	switch ecosystem.Canonical(eco) {
	case model.EcoPyPI:
		return &pypiScheme
	case model.EcoMaven:
		return &mavenScheme
	case model.EcoGo:
		return &goScheme
	}
	return &defaultScheme
}

// CompareFor orders two versions of an ecosystem as -1, 0 or 1, by that
// ecosystem's rules (PEP 440 for pypi, Maven ComparableVersion for maven,
// semver with pseudo-versions for go, the default scheme otherwise). ok is
// false when either is unparsable in that scheme.
func CompareFor(eco, a, b string) (int, bool) { return compareWith(schemeFor(eco), a, b) }

// ParseRangeFor is ParseRange for an ecosystem: every bound must parse in its
// scheme. For pypi it also reads PEP 440 specifiers: ==1.2.* is [1.2, 1.3),
// ~=1.4.2 is >=1.4.2, <1.5, and != is an error because it is not a range.
func ParseRangeFor(eco, expr string) ([]model.Range, error) {
	return parseRange(schemeFor(eco), expr)
}

// EvaluateFor is Evaluate for an ecosystem, with the same exact-version and
// series logic over that ecosystem's ordering.
func EvaluateFor(eco, installed string, ranges []model.Range) model.Applicability {
	return evaluate(schemeFor(eco), installed, ranges)
}

// cmpNum compares two non-negative decimal strings of any length.
func cmpNum(a, b string) int {
	a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
	if c := cmp.Compare(len(a), len(b)); c != 0 {
		return c
	}
	return strings.Compare(a, b)
}

// ---------------------------------------------------------------- PyPI (PEP 440)

// pep is a PEP 440 version reduced to what ordering needs.
type pep struct {
	epoch  int
	rel    []int // release segments as written
	preR   int   // -1 dev-only, 0 a, 1 b, 2 rc, 3 no pre-release
	preN   int
	post   int // -1 when not a post-release
	dev    int // math.MaxInt when not a dev release
	suffix bool
}

var pepRE = regexp.MustCompile(`(?i)^v?(?:(\d+)!)?(\d+(?:\.\d+)*)` +
	`([-_.]?(alpha|a|beta|b|preview|pre|c|rc)[-_.]?(\d+)?)?` +
	`((?:-(\d+))|(?:[-_.]?(post|rev|r)[-_.]?(\d+)?))?` +
	`([-_.]?(dev)[-_.]?(\d+)?)?` +
	`(?:\+([a-z0-9]+(?:[-_.][a-z0-9]+)*))?$`)

func atoiOpt(s string) (int, bool) {
	if s == "" {
		return 0, true
	}
	n, err := strconv.Atoi(s)
	return n, err == nil
}

func parsePEP(s string) (any, bool) {
	m := pepRE.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return nil, false
	}
	p := pep{preR: 3, post: -1, dev: math.MaxInt}
	var ok bool
	if p.epoch, ok = atoiOpt(m[1]); !ok {
		return nil, false
	}
	for _, seg := range strings.Split(m[2], ".") {
		n, err := strconv.Atoi(seg)
		if err != nil {
			return nil, false
		}
		p.rel = append(p.rel, n)
	}
	if m[4] != "" {
		switch strings.ToLower(m[4]) {
		case "a", "alpha":
			p.preR = 0
		case "b", "beta":
			p.preR = 1
		default:
			p.preR = 2
		}
		if p.preN, ok = atoiOpt(m[5]); !ok {
			return nil, false
		}
	}
	switch {
	case m[7] != "":
		p.post, ok = atoiOpt(m[7])
	case m[8] != "":
		p.post, ok = atoiOpt(m[9])
	default:
		ok = true
	}
	if !ok {
		return nil, false
	}
	if m[11] != "" {
		if p.dev, ok = atoiOpt(m[12]); !ok {
			return nil, false
		}
	}
	if p.preR == 3 && p.post < 0 && p.dev != math.MaxInt {
		p.preR = -1 // 1.0.dev1 sorts before every pre-release of 1.0
	}
	p.suffix = m[4] != "" || m[6] != "" || m[11] != "" || m[13] != ""
	return p, true
}

func cmpPEP(x, y any) int {
	a, b := x.(pep), y.(pep)
	if c := cmp.Compare(a.epoch, b.epoch); c != 0 {
		return c
	}
	for i := 0; i < len(a.rel) || i < len(b.rel); i++ {
		var p, q int
		if i < len(a.rel) {
			p = a.rel[i]
		}
		if i < len(b.rel) {
			q = b.rel[i]
		}
		if c := cmp.Compare(p, q); c != 0 {
			return c
		}
	}
	if c := cmp.Compare(a.preR, b.preR); c != 0 {
		return c
	}
	if c := cmp.Compare(a.preN, b.preN); c != 0 {
		return c
	}
	if c := cmp.Compare(a.post, b.post); c != 0 {
		return c
	}
	return cmp.Compare(a.dev, b.dev)
}

// pepSeries: 1.2 names [1.2, 1.3.dev0), 1.3.dev0 being the lowest 1.3.
func pepSeries(k any) (any, bool) {
	p := k.(pep)
	if p.suffix || len(p.rel) > 2 {
		return nil, false
	}
	hi := pep{epoch: p.epoch, rel: append([]int(nil), p.rel...), preR: -1, post: -1}
	hi.rel[len(hi.rel)-1]++
	return hi, true
}

// pepBump writes the first n release segments with the last one raised by one:
// the exclusive upper bound of a prefix match or compatible release.
func pepBump(p pep, n int) string {
	segs := make([]string, n)
	for i := range segs {
		v := 0
		if i < len(p.rel) {
			v = p.rel[i]
		}
		if i == n-1 {
			v++
		}
		segs[i] = strconv.Itoa(v)
	}
	s := strings.Join(segs, ".")
	if p.epoch != 0 {
		s = strconv.Itoa(p.epoch) + "!" + s
	}
	return s
}

func pepExpand(op, v string) ([]cond, bool, error) {
	switch op {
	case "!=":
		return nil, false, errors.New("!= cannot be expressed as a range")
	case "~=":
		k, ok := parsePEP(v)
		if !ok {
			return nil, false, errors.New("unparsable version")
		}
		p := k.(pep)
		if len(p.rel) < 2 {
			return nil, false, errors.New("~= needs at least two release segments")
		}
		return []cond{{">=", v}, {"<", pepBump(p, len(p.rel)-1)}}, true, nil
	case "", "=", "==", "===":
		prefix, ok := strings.CutSuffix(v, ".*")
		if !ok {
			return nil, false, nil
		}
		k, ok := parsePEP(prefix)
		if !ok || k.(pep).suffix {
			return nil, false, errors.New("unparsable version")
		}
		return []cond{{">=", prefix}, {"<", pepBump(k.(pep), len(k.(pep).rel))}}, true, nil
	}
	return nil, false, nil
}

var pypiScheme = scheme{
	parse:  parsePEP,
	cmp:    cmpPEP,
	series: pepSeries,
	ops:    []string{"===", "~=", "!=", ">=", "<=", "==", ">", "<", "="},
	expand: pepExpand,
}

// ---------------------------------------------------------------- Go (semver)

// gover is a Go module version: semver with an optional v prefix. Pseudo
// versions are ordinary pre-releases, so their timestamp orders them.
type gover struct {
	n      [3]int
	parts  int
	pre    []string
	hasPre bool
}

func parseGo(s string) (any, bool) {
	s = strings.TrimSpace(s)
	if s != "" && (s[0] == 'v' || s[0] == 'V') {
		s = s[1:]
	}
	s, _, _ = strings.Cut(s, "+") // +incompatible and other build metadata
	core, pre, hasPre := strings.Cut(s, "-")
	var g gover
	segs := strings.Split(core, ".")
	if len(segs) > 3 {
		return nil, false
	}
	for i, seg := range segs {
		n, err := strconv.Atoi(seg)
		if err != nil {
			return nil, false
		}
		g.n[i] = n
	}
	g.parts = len(segs)
	if hasPre {
		g.hasPre = true
		g.pre = strings.Split(pre, ".")
		for _, id := range g.pre {
			if id == "" {
				return nil, false
			}
			for _, c := range id {
				if c != '-' && !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
					return nil, false
				}
			}
		}
	}
	return g, true
}

func cmpGo(x, y any) int {
	a, b := x.(gover), y.(gover)
	for i := range a.n {
		if c := cmp.Compare(a.n[i], b.n[i]); c != 0 {
			return c
		}
	}
	switch {
	case a.hasPre == b.hasPre && !a.hasPre:
		return 0
	case !a.hasPre:
		return 1
	case !b.hasPre:
		return -1
	}
	for i := 0; i < len(a.pre) && i < len(b.pre); i++ {
		p, q := a.pre[i], b.pre[i]
		pn, qn := allDigits(p), allDigits(q)
		var c int
		switch {
		case pn && qn:
			c = cmpNum(p, q)
		case pn:
			c = -1
		case qn:
			c = 1
		default:
			c = strings.Compare(p, q)
		}
		if c != 0 {
			return c
		}
	}
	return cmp.Compare(len(a.pre), len(b.pre))
}

// goSeries: v1.2 names [v1.2.0, v1.3.0-0), v1.3.0-0 being the lowest v1.3.0.
func goSeries(k any) (any, bool) {
	g := k.(gover)
	if g.parts > 2 || g.hasPre {
		return nil, false
	}
	g.n[g.parts-1]++
	g.hasPre, g.pre = true, []string{"0"}
	return g, true
}

var goScheme = scheme{
	parse:  parseGo,
	cmp:    cmpGo,
	series: goSeries,
	ops:    []string{">=", "<=", "==", ">", "<", "="},
}

// ---------------------------------------------------------------- Maven

// mitem is one item of Maven's ComparableVersion tree: a number, a qualifier
// or a nested list (what follows a '-' or a digit/letter transition).
type mitem struct {
	kind byte   // 'i' number, 's' qualifier, 'l' list
	str  string // number without leading zeros, or alias-resolved qualifier
	list []*mitem
}

// Known qualifiers in order; an empty one (release) sits at index 5.
var mavenQualifiers = []string{"alpha", "beta", "milestone", "rc", "snapshot", "", "sp"}

func mavenKey(q string) string {
	for i, k := range mavenQualifiers {
		if k == q {
			return strconv.Itoa(i)
		}
	}
	return "7-" + q // unknown qualifiers sort after sp, lexically
}

func newMavenString(s string, followedByDigit bool) *mitem {
	if followedByDigit && len(s) == 1 {
		switch s {
		case "a":
			s = "alpha"
		case "b":
			s = "beta"
		case "m":
			s = "milestone"
		}
	}
	switch s {
	case "ga", "final", "release":
		s = ""
	case "cr":
		s = "rc"
	}
	return &mitem{kind: 's', str: s}
}

func newMavenItem(isDigit bool, s string) *mitem {
	if isDigit {
		return &mitem{kind: 'i', str: strings.TrimLeft(s, "0")}
	}
	return newMavenString(s, false)
}

func (it *mitem) isNull() bool {
	switch it.kind {
	case 'l':
		return len(it.list) == 0
	default:
		return it.str == ""
	}
}

// normalize drops trailing items that equal nothing (0, "", empty lists).
func (it *mitem) normalize() {
	for i := len(it.list) - 1; i >= 0; i-- {
		if last := it.list[i]; last.isNull() {
			it.list = append(it.list[:i], it.list[i+1:]...)
		} else if last.kind != 'l' {
			break
		}
	}
}

func parseMavenTree(s string) *mitem {
	root := &mitem{kind: 'l'}
	list, stack := root, []*mitem{root}
	push := func() {
		n := &mitem{kind: 'l'}
		list.list = append(list.list, n)
		list = n
		stack = append(stack, n)
	}
	add := func(it *mitem) { list.list = append(list.list, it) }
	isDig, start := false, 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '.' || c == '-':
			if i == start {
				add(&mitem{kind: 'i'})
			} else {
				add(newMavenItem(isDig, s[start:i]))
			}
			start = i + 1
			if c == '-' {
				push()
			}
		case c >= '0' && c <= '9':
			if !isDig && i > start {
				add(newMavenString(s[start:i], true))
				start = i
				push()
			}
			isDig = true
		default:
			if isDig && i > start {
				add(newMavenItem(true, s[start:i]))
				start = i
				push()
			}
			isDig = false
		}
	}
	if len(s) > start {
		add(newMavenItem(isDig, s[start:]))
	}
	for i := len(stack) - 1; i >= 0; i-- {
		stack[i].normalize()
	}
	return root
}

// cmpMavenItem orders items as ComparableVersion does; nil stands for the
// missing item of a shorter list.
func cmpMavenItem(a, b *mitem) int {
	if a == nil {
		if b == nil {
			return 0
		}
		return -cmpMavenItem(b, nil)
	}
	switch a.kind {
	case 'i':
		switch {
		case b == nil:
			if a.str == "" {
				return 0
			}
			return 1
		case b.kind == 'i':
			return cmpNum(a.str, b.str)
		}
		return 1
	case 's':
		switch {
		case b == nil:
			return strings.Compare(mavenKey(a.str), mavenKey(""))
		case b.kind == 's':
			return strings.Compare(mavenKey(a.str), mavenKey(b.str))
		}
		return -1
	}
	switch {
	case b == nil:
		if len(a.list) == 0 {
			return 0
		}
		return cmpMavenItem(a.list[0], nil)
	case b.kind == 'i':
		return -1
	case b.kind == 's':
		return 1
	}
	for i := 0; i < len(a.list) || i < len(b.list); i++ {
		var l, r *mitem
		if i < len(a.list) {
			l = a.list[i]
		}
		if i < len(b.list) {
			r = b.list[i]
		}
		if c := cmpMavenItem(l, r); c != 0 {
			return c
		}
	}
	return 0
}

// mver is a parsed Maven version. hi is the series end for a plain 1- or
// 2-number version (1.2 gives 1.3-alpha, the lowest 1.3), else empty.
type mver struct {
	root *mitem
	hi   string
}

var mavenSeriesRE = regexp.MustCompile(`^(\d+)(?:\.(\d+))?$`)

func parseMaven(s string) (any, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || strings.IndexFunc(s, unicode.IsSpace) >= 0 || strings.IndexFunc(s, unicode.IsDigit) < 0 {
		return nil, false
	}
	v := mver{root: parseMavenTree(s)}
	if m := mavenSeriesRE.FindStringSubmatch(s); m != nil {
		last := m[1]
		if m[2] != "" {
			last = m[2]
		}
		if n, err := strconv.Atoi(last); err == nil {
			if m[2] == "" {
				v.hi = strconv.Itoa(n+1) + "-alpha"
			} else {
				v.hi = m[1] + "." + strconv.Itoa(n+1) + "-alpha"
			}
		}
	}
	return v, true
}

func mavenSeries(k any) (any, bool) {
	hi := k.(mver).hi
	if hi == "" {
		return nil, false
	}
	return parseMaven(hi)
}

var mavenScheme = scheme{
	parse:  parseMaven,
	cmp:    func(a, b any) int { return cmpMavenItem(a.(mver).root, b.(mver).root) },
	series: mavenSeries,
	ops:    []string{">=", "<=", "==", ">", "<", "="},
}
