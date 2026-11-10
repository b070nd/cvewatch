package relevance

import (
	"regexp"
	"strings"
)

// subject is a text prepared once for every term that is looked for in it.
type subject struct {
	text  string
	lower string
	ascii bool
}

func newSubject(text string) subject {
	// ToLower handles the Kelvin sign; long s is the other non-ASCII rune
	// in an ASCII letter's Unicode simple-fold class. Keep this as a candidate
	// prefilter only: the expression still decides Unicode word boundaries.
	lower := strings.ReplaceAll(strings.ToLower(text), "ſ", "s")
	return subject{text: text, lower: lower, ascii: isASCII(text)}
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// words is wordRe without the cost for the usual case. ASCII terms in ASCII
// text use substring lookup and boundary checks. Unicode text uses a conservative
// substring prefilter before the expression, which retains the original rule.
type words struct {
	terms []string // lowercase
	fast  bool     // every term is non-empty ASCII
	re    *regexp.Regexp
}

func newWords(terms []string) words {
	w := words{fast: true, re: wordRe(terms)}
	for _, t := range terms {
		t = strings.ToLower(strings.TrimSpace(t))
		w.fast = w.fast && t != "" && isASCII(t)
		w.terms = append(w.terms, t)
	}
	return w
}

func (w words) match(s subject) bool {
	if !w.fast {
		return w.re.MatchString(s.text)
	}
	for _, t := range w.terms {
		if !s.ascii {
			if strings.Contains(s.lower, t) {
				return w.re.MatchString(s.text)
			}
		} else if hasWord(s.lower, t) {
			return true
		}
	}
	return false
}

// hasWord reports whether term stands in text with no letter or digit on
// either side. Both are lowercase ASCII.
func hasWord(text, term string) bool {
	for from := 0; ; {
		i := strings.Index(text[from:], term)
		if i < 0 {
			return false
		}
		i += from
		end := i + len(term)
		if (i == 0 || !alnum(text[i-1])) && (end == len(text) || !alnum(text[end])) {
			return true
		}
		from = i + 1
	}
}

func alnum(c byte) bool { return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' }

// wordRe matches any term as a whole word, case-insensitively, so "go" does
// not fire inside "google" and "php" does not fire inside "phpunit".
func wordRe(terms []string) *regexp.Regexp {
	parts := make([]string, len(terms))
	for i, t := range terms {
		parts[i] = regexp.QuoteMeta(strings.TrimSpace(t))
	}
	return regexp.MustCompile(`(?i)(?:^|[^a-z0-9])(?:` + strings.Join(parts, "|") + `)(?:[^a-z0-9]|$)`)
}

// names finds which of many scoped package names (vendor/package,
// group:artifact, module paths) stand in a text, in one pass over the text
// instead of one search per name. Every such name holds a '/' or ':' with a
// character on either side; those three bytes are the key under which the
// name is filed, so only the separators of the text are looked up. It is
// built once and never changes.
type names struct {
	list     []string          // distinct names, lowercase, in the order added
	anchored map[[3]byte][]int // the bytes around a name's first separator -> names
	loose    []looseName       // names that cannot be anchored: searched one by one
}

type looseName struct {
	i int
	w words
}

// add files a name and returns its index. The name is lowercase and trimmed.
func (n *names) add(name string) int {
	i := len(n.list)
	n.list = append(n.list, name)
	sep := strings.IndexAny(name, "/:")
	if !isASCII(name) || sep <= 0 || sep >= len(name)-1 {
		n.loose = append(n.loose, looseName{i, newWords([]string{name})})
		return i
	}
	if n.anchored == nil {
		n.anchored = map[[3]byte][]int{}
	}
	key := [3]byte{name[sep-1], name[sep], name[sep+1]}
	n.anchored[key] = append(n.anchored[key], i)
	return i
}

// in returns the indexes of the names that stand in the text as whole words,
// ascending. The rule is the one of words.match for a single name.
func (n *names) in(s subject) []int {
	var out []int
	seen := func(i int) bool {
		for _, o := range out {
			if o == i {
				return true
			}
		}
		return false
	}
	if len(n.anchored) > 0 {
		low := s.lower
		for p := 1; p+1 < len(low); p++ {
			if c := low[p]; c != '/' && c != ':' {
				continue
			}
			for _, i := range n.anchored[[3]byte{low[p-1], low[p], low[p+1]}] {
				if !seen(i) && stands(n.list[i], s) {
					out = append(out, i)
				}
			}
		}
	}
	for _, l := range n.loose {
		if l.w.match(s) {
			out = append(out, l.i)
		}
	}
	if len(out) > 1 {
		sortInts(out)
	}
	return out
}

// stands is words.match for one lowercase ASCII name.
func stands(name string, s subject) bool {
	if s.ascii {
		return hasWord(s.lower, name)
	}
	return strings.Contains(s.lower, name) && wordRe([]string{name}).MatchString(s.text)
}

func sortInts(a []int) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j] < a[j-1]; j-- {
			a[j], a[j-1] = a[j-1], a[j]
		}
	}
}
