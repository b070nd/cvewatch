// Package version decides whether the version a project runs falls inside the
// affected ranges a vulnerability feed gives.
package version

import (
	"cmp"
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
// It uses the default scheme; CompareFor picks the scheme by ecosystem.
func Compare(a, b string) (int, bool) { return compareWith(&defaultScheme, a, b) }

// ParseRange reads advisory range notation such as ">= 1.0, < 1.2.3 || = 2.0".
// Space or comma means AND, "||" means OR; each AND group becomes one Range.
// Two lower or two upper bounds in one group keep the tighter. An empty
// expression gives no ranges.
func ParseRange(expr string) ([]model.Range, error) { return parseRange(&defaultScheme, expr) }

// Evaluate says whether the installed version is inside the affected ranges.
// A version with three or more numbers (or a suffix) is exact. One or two
// numbers name a series such as 8.2, the interval [8.2.0, 8.3.0): affected
// when ranges cover all of it, not affected when none touches it, otherwise
// unknown. No ranges, or an unparsable version, is unknown, and so is a result
// of not affected that rests on a range whose bounds cannot be read.
func Evaluate(installed string, ranges []model.Range) model.Applicability {
	return evaluate(&defaultScheme, installed, ranges)
}

// defaultScheme is the semver-like scheme of composer, npm, cpe and unknown ecosystems.
var defaultScheme = scheme{
	parse: func(s string) (any, bool) {
		v, ok := parse(s)
		return v, ok
	},
	cmp: func(a, b any) int { return a.(ver).cmp(b.(ver)) },
	series: func(k any) (any, bool) {
		v := k.(ver)
		if v.parts > 2 || v.hasPatch || v.pre != "" {
			return nil, false
		}
		v.n[v.parts-1]++
		return v, true
	},
	ops: []string{">=", "<=", "==", ">", "<", "="},
}
