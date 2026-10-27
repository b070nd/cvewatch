// Package version decides whether the version a project runs falls inside the
// affected ranges a vulnerability feed gives.
package version

import (
	"cmp"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/b070nd/cvewatch/app/src/model"
)

const maxParts = 6

// ver is a parsed version. Missing numeric parts are zero, so 1.2 equals 1.2.0.
type ver struct {
	n        [maxParts]int
	parts    int    // numeric parts as written
	patch    int    // Magento-style -pN level; counts as one extra component
	hasPatch bool   // a patch level was written
	pre      string // lower-cased pre-release suffix, empty for a release
}

// parse reads a version string; ok is false when it has no leading number.
func parse(s string) (v ver, ok bool) {
	s = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(s), "="))
	if s != "" && (s[0] == 'v' || s[0] == 'V') {
		s = s[1:]
	}
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i] // build metadata is ignored
	}
	i := 0
	for {
		j := i
		for j < len(s) && isDigit(s[j]) {
			j++
		}
		if j == i || v.parts == maxParts {
			return ver{}, false
		}
		n, err := strconv.Atoi(s[i:j])
		if err != nil {
			return ver{}, false
		}
		v.n[v.parts] = n
		v.parts++
		i = j
		if i+1 < len(s) && s[i] == '.' && isDigit(s[i+1]) {
			i++
			continue
		}
		break
	}
	rest := strings.TrimLeft(s[i:], "-._ ")
	if len(rest) > 1 && (rest[0] == 'p' || rest[0] == 'P') && allDigits(rest[1:]) {
		n, err := strconv.Atoi(rest[1:])
		if err != nil {
			return ver{}, false
		}
		v.patch, v.hasPatch = n, true
	} else {
		v.pre = strings.ToLower(rest)
	}
	return v, true
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return false
		}
	}
	return true
}

func (a ver) cmp(b ver) int {
	for i := range a.n {
		if c := cmp.Compare(a.n[i], b.n[i]); c != 0 {
			return c
		}
	}
	if c := cmp.Compare(a.patch, b.patch); c != 0 {
		return c
	}
	return comparePre(a.pre, b.pre)
}

// comparePre orders pre-release suffixes; a release outranks any pre-release.
func comparePre(a, b string) int {
	switch {
	case a == b:
		return 0
	case a == "":
		return 1
	case b == "":
		return -1
	}
	ta, tb := tokens(a), tokens(b)
	for i := 0; i < len(ta) && i < len(tb); i++ {
		if c := compareToken(ta[i], tb[i]); c != 0 {
			return c
		}
	}
	return cmp.Compare(len(ta), len(tb))
}

// tokens splits on punctuation and on digit/letter boundaries: rc10 is rc, 10.
func tokens(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i < len(s) && s[i] != '.' && s[i] != '-' && s[i] != '_' &&
			(i == start || isDigit(s[i]) == isDigit(s[i-1])) {
			continue
		}
		if i > start {
			out = append(out, s[start:i])
		}
		start = i
		if i < len(s) && (s[i] == '.' || s[i] == '-' || s[i] == '_') {
			start = i + 1
		}
	}
	return out
}

// compareToken puts numbers before words and orders numbers by value.
func compareToken(a, b string) int {
	na, nb := isDigit(a[0]), isDigit(b[0])
	switch {
	case na && nb:
		a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
		if c := cmp.Compare(len(a), len(b)); c != 0 {
			return c
		}
		return strings.Compare(a, b)
	case na:
		return -1
	case nb:
		return 1
	}
	return strings.Compare(a, b)
}

// Compare orders two versions as -1, 0 or 1. ok is false when either is unparsable.
func Compare(a, b string) (int, bool) {
	va, okA := parse(a)
	vb, okB := parse(b)
	if !okA || !okB {
		return 0, false
	}
	return va.cmp(vb), true
}

var ops = []string{">=", "<=", "==", ">", "<", "="}

// ParseRange reads advisory range notation such as ">= 1.0, < 1.2.3 || = 2.0".
// Space or comma means AND, "||" means OR; each AND group becomes one Range.
// Two lower or two upper bounds in one group keep the tighter. An empty
// expression gives no ranges.
func ParseRange(expr string) ([]model.Range, error) {
	if strings.TrimSpace(expr) == "" {
		return nil, nil
	}
	var out []model.Range
	for _, group := range strings.Split(expr, "||") {
		r, err := parseGroup(group)
		if err != nil {
			return nil, fmt.Errorf("version: invalid range %q: %w", clip(expr), err)
		}
		out = append(out, r)
	}
	return out, nil
}

func parseGroup(g string) (model.Range, error) {
	var r model.Range
	fields := strings.Fields(strings.ReplaceAll(g, ",", " "))
	if len(fields) == 0 {
		return r, errors.New("empty condition")
	}
	for i := 0; i < len(fields); i++ {
		f, op := fields[i], ""
		for _, o := range ops {
			if strings.HasPrefix(f, o) {
				op, f = o, f[len(o):]
				break
			}
		}
		if f == "" {
			if i++; i == len(fields) {
				return r, errors.New("operator without a version")
			}
			f = fields[i]
		}
		if _, ok := parse(f); !ok {
			return r, errors.New("unparsable version")
		}
		switch op {
		case ">=", ">":
			setMin(&r, f, op == ">")
		case "<=", "<":
			setMax(&r, f, op == "<")
		default:
			setMin(&r, f, false)
			setMax(&r, f, false)
		}
	}
	return r, nil
}

// setMin keeps the tighter (higher, or exclusive when equal) lower bound.
func setMin(r *model.Range, v string, excl bool) {
	if c, _ := Compare(v, r.Min); r.Min == "" || c > 0 || c == 0 && excl {
		r.Min, r.MinExcl = v, excl
	}
}

// setMax keeps the tighter (lower, or exclusive when equal) upper bound.
func setMax(r *model.Range, v string, excl bool) {
	if c, _ := Compare(v, r.Max); r.Max == "" || c < 0 || c == 0 && excl {
		r.Max, r.MaxExcl = v, excl
	}
}

func clip(s string) string {
	if r := []rune(s); len(r) > 80 {
		return string(r[:80])
	}
	return s
}

// bound is one end of a span; unset means unbounded.
type bound struct {
	v         ver
	set, excl bool
}

// span is a Range with its bounds parsed.
type span struct{ lo, hi bound }

func toSpan(r model.Range) (s span, ok bool) {
	if r.Min != "" {
		v, ok := parse(r.Min)
		if !ok {
			return s, false
		}
		s.lo = bound{v, true, r.MinExcl}
	}
	if r.Max != "" {
		v, ok := parse(r.Max)
		if !ok {
			return s, false
		}
		s.hi = bound{v, true, r.MaxExcl}
	}
	return s, true
}

func (s span) empty() bool {
	if !s.lo.set || !s.hi.set {
		return false
	}
	c := s.lo.v.cmp(s.hi.v)
	return c > 0 || c == 0 && (s.lo.excl || s.hi.excl)
}

func (s span) contains(v ver) bool {
	if s.lo.set {
		if c := v.cmp(s.lo.v); c < 0 || c == 0 && s.lo.excl {
			return false
		}
	}
	if s.hi.set {
		if c := v.cmp(s.hi.v); c > 0 || c == 0 && s.hi.excl {
			return false
		}
	}
	return true
}

// meets reports whether the span shares a version with the half-open [lo, hi).
func (s span) meets(lo, hi ver) bool {
	if s.hi.set {
		if c := s.hi.v.cmp(lo); c < 0 || c == 0 && s.hi.excl {
			return false
		}
	}
	return !s.lo.set || s.lo.v.cmp(hi) < 0
}

// covers reports whether the union of spans contains all of [lo, hi). It
// sweeps upward from lo, always jumping to the span that reaches furthest.
func covers(spans []span, lo, hi ver) bool {
	cur, done := lo, false // done: cur itself is already covered
	for cur.cmp(hi) < 0 {
		next, nextDone, found := cur, done, false
		for _, s := range spans {
			if s.lo.set {
				if c := s.lo.v.cmp(cur); c > 0 || c == 0 && s.lo.excl && !done {
					continue
				}
			}
			if !s.hi.set {
				return true
			}
			end, endDone := s.hi.v, !s.hi.excl
			if c := end.cmp(next); c > 0 || c == 0 && endDone && !nextDone {
				next, nextDone, found = end, endDone, true
			}
		}
		if !found {
			return false
		}
		cur, done = next, nextDone
	}
	return true
}

// Evaluate says whether the installed version is inside the affected ranges.
// A version with three or more numbers (or a suffix) is exact. One or two
// numbers name a series such as 8.2, the interval [8.2.0, 8.3.0): affected
// when ranges cover all of it, not affected when none touches it, otherwise
// unknown. No ranges, or an unparsable version, is unknown, and so is a result
// of not affected that rests on a range whose bounds cannot be read.
func Evaluate(installed string, ranges []model.Range) model.Applicability {
	v, ok := parse(installed)
	if !ok || len(ranges) == 0 {
		return model.AppUnknown
	}
	var spans []span
	unreadable := false
	for _, r := range ranges {
		s, ok := toSpan(r)
		switch {
		case !ok:
			unreadable = true
		case !s.empty():
			spans = append(spans, s)
		}
	}
	miss := model.AppNotAffected
	if unreadable {
		miss = model.AppUnknown
	}

	if v.parts > 2 || v.hasPatch || v.pre != "" {
		for _, s := range spans {
			if s.contains(v) {
				return model.AppAffected
			}
		}
		return miss
	}
	hi := v
	hi.n[v.parts-1]++
	if covers(spans, v, hi) {
		return model.AppAffected
	}
	for _, s := range spans {
		if s.meets(v, hi) {
			return model.AppUnknown
		}
	}
	return miss
}
