// Package match decides whether a feed item concerns a supported technology
// and which projects it touches.
package match

import (
	"regexp"
	"strings"

	"cvewatch/src/model"
)

type compiled struct {
	name    string
	re      *regexp.Regexp
	exclude *regexp.Regexp // nil when the tech has no excludes
}

// Matcher finds configured technologies inside item text.
type Matcher struct{ techs []compiled }

func New(techs []model.Tech) *Matcher {
	m := &Matcher{}
	for _, t := range techs {
		c := compiled{name: strings.ToLower(t.Name), re: wordRe(t.Terms())}
		if len(t.Excludes) > 0 {
			c.exclude = wordRe(t.Excludes)
		}
		m.techs = append(m.techs, c)
	}
	return m
}

// wordRe matches any term as a whole word, case-insensitively, so "go" does
// not fire inside "google" and "php" does not fire inside "phpunit".
func wordRe(terms []string) *regexp.Regexp {
	parts := make([]string, len(terms))
	for i, t := range terms {
		parts[i] = regexp.QuoteMeta(strings.TrimSpace(t))
	}
	return regexp.MustCompile(`(?i)(?:^|[^a-z0-9])(?:` + strings.Join(parts, "|") + `)(?:[^a-z0-9]|$)`)
}

// Techs returns the lowercase names of configured techs the item is about:
// an alias is mentioned and no exclude term is.
func (m *Matcher) Techs(it model.Item) []string {
	text := it.TechText()
	var out []string
	for _, t := range m.techs {
		if t.re.MatchString(text) && (t.exclude == nil || !t.exclude.MatchString(text)) {
			out = append(out, t.name)
		}
	}
	return out
}

// Project lists what makes the item relevant to the project, or nil if it is
// not. A project is hit when it declares a matched tech, or when one of its
// lockfile packages is named by the feed. Free text is only searched for
// scoped names (vendor/package): bare names like "express" are too common.
func Project(p model.Project, pkgs []model.Package, techs []string, it model.Item) []string {
	var out []string

	hit := map[string]bool{}
	for _, t := range techs {
		hit[t] = true
	}
	for _, pt := range p.Techs {
		if hit[strings.ToLower(pt.Name)] {
			out = append(out, label(pt.Name, pt.Version))
		}
	}

	structured := map[string]bool{}
	for _, n := range it.Packages {
		structured[strings.ToLower(n)] = true
	}
	text := strings.ToLower(it.Text())
	for _, pkg := range pkgs {
		if structured[pkg.Name] || (strings.Contains(pkg.Name, "/") && mentions(text, pkg.Name)) {
			out = append(out, label(pkg.Name, pkg.Version))
		}
	}
	return out
}

func mentions(text, name string) bool {
	return wordRe([]string{name}).MatchString(text)
}

func label(name, version string) string {
	if version == "" {
		return name
	}
	return name + "@" + version
}

var (
	wordSplit = regexp.MustCompile(`[^a-z0-9]+`)
	filler    = map[string]bool{
		"the": true, "and": true, "for": true, "with": true, "from": true, "that": true, "this": true,
		"has": true, "was": true, "are": true, "via": true, "can": true, "allows": true, "before": true,
		"after": true, "through": true, "vulnerability": true, "vulnerable": true, "security": true,
		"flaw": true, "found": true, "issue": true, "detected": true, "identified": true,
		"discovered": true, "weakness": true, "affects": true, "version": true, "versions": true,
	}
)

func words(s string) map[string]bool {
	out := map[string]bool{}
	for _, w := range wordSplit.Split(strings.ToLower(model.StripIDs(s)), -1) {
		if len(w) >= 3 && !filler[w] {
			out[w] = true
		}
	}
	return out
}

// Similar reports whether two titles describe the same issue: they share at
// least 60% of their distinctive words (ids and filler words ignored).
// Very short titles never match, so they cannot merge by accident.
func Similar(a, b string) bool {
	wa, wb := words(a), words(b)
	if len(wa) < 4 || len(wb) < 4 {
		return false
	}
	shared := 0
	for w := range wa {
		if wb[w] {
			shared++
		}
	}
	return float64(shared)/float64(len(wa)+len(wb)-shared) >= 0.6
}
