// Package relevance decides whether a feed item matters to a project and
// whether the version the project runs is affected. It is the single place
// where the rules live: aliases, excludes, structured CPE and package data,
// title-only matching and version ranges. Every decision comes with reasons.
package relevance

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/version"
)

type tech struct {
	name    string
	re      *regexp.Regexp
	exclude *regexp.Regexp // nil when the tech has no excludes
	cpe     map[string]bool
}

// Judge applies the configured technologies to items. It is immutable and
// rebuilt from config every run, so edits take effect on the next cycle.
type Judge struct{ techs []tech }

func New(techs []model.Tech) *Judge {
	j := &Judge{}
	for _, t := range techs {
		c := tech{name: strings.ToLower(t.Name), re: wordRe(t.Terms()), cpe: map[string]bool{}}
		if len(t.Excludes) > 0 {
			c.exclude = wordRe(t.Excludes)
		}
		for _, n := range t.CPE {
			c.cpe[strings.ToLower(strings.TrimSpace(n))] = true
		}
		j.techs = append(j.techs, c)
	}
	return j
}

// Verdict is what judging one item produced.
type Verdict struct {
	Techs   []string // techs the item is about, lowercase
	Matches []Match  // projects that run something affected or possibly affected
	Notes   []string // why a tech did not match, for explanations
}

// Relevant reports whether any tech or project matched.
func (v Verdict) Relevant() bool { return len(v.Techs) > 0 || len(v.Matches) > 0 }

// Match is the outcome for one project.
type Match struct {
	Project   string
	Installed []model.Installed
	Applies   model.Applicability // the most urgent over everything installed
	Reasons   []string
}

// hit is a tech the item is about, with the versions NVD-style data says are affected.
type hit struct {
	ranges []model.Range
	known  bool // ranges came from structured data
	why    string
}

// Judge evaluates one item against the projects' declared techs and lockfile packages.
func (j *Judge) Judge(it model.Item, projects []model.Project, pkgs map[string][]model.Package) Verdict {
	var v Verdict
	hits := map[string]hit{}
	for _, t := range j.techs {
		h, note, ok := t.judge(it)
		if note != "" {
			v.Notes = append(v.Notes, note)
		}
		if ok {
			hits[t.name] = h
			v.Techs = append(v.Techs, t.name)
		}
	}

	for _, p := range projects {
		m := Match{Project: p.Name, Applies: model.AppNotAffected}
		for _, pt := range p.Techs {
			h, ok := hits[strings.ToLower(pt.Name)]
			if !ok {
				continue
			}
			in := model.Installed{Name: pt.Name, Version: pt.Version, Via: "tech"}
			m.add(in, applies(in.Version, h.ranges, h.known), h.why)
		}
		for _, pkg := range pkgs[p.Name] {
			in := model.Installed{Name: pkg.Name, Version: pkg.Version, Ecosystem: pkg.Ecosystem, Via: "package"}
			if rs, structured, ok := packageHit(it, pkg); ok {
				why := "named in the advisory's package list"
				if !structured {
					why = "named in the text"
				}
				m.add(in, applies(in.Version, rs, structured), why)
			}
		}
		if len(m.Installed) > 0 {
			v.Matches = append(v.Matches, m)
		}
	}
	return v
}

func (m *Match) add(in model.Installed, a model.Applicability, why string) {
	m.Installed = append(m.Installed, in)
	if len(m.Installed) == 1 {
		m.Applies = a
	} else {
		m.Applies = m.Applies.Worse(a)
	}
	m.Reasons = append(m.Reasons, fmt.Sprintf("%s: %s, %s", in.Label(), why, verdictWords(a)))
}

func verdictWords(a model.Applicability) string {
	switch a {
	case model.AppAffected:
		return "version is in the affected range"
	case model.AppNotAffected:
		return "version is outside the affected range"
	}
	return "version could not be checked"
}

func applies(installed string, ranges []model.Range, known bool) model.Applicability {
	if !known {
		return model.AppUnknown
	}
	return version.Evaluate(installed, ranges)
}

// judge decides one tech. Structured CPE data wins over text when the tech
// knows its CPE names: that is what removes "mentioned in passing" noise.
func (t tech) judge(it model.Item) (h hit, note string, ok bool) {
	if len(t.cpe) > 0 {
		for _, a := range it.Affected {
			if a.Ecosystem == "cpe" && t.cpe[a.Name] {
				h.ranges = append(h.ranges, a.Ranges...)
				h.known = len(a.Ranges) > 0
			}
		}
		// Any structured data (CPE products or package lists) says what the
		// advisory is about, so a passing mention of the tech in the text is ignored.
		if len(it.Affected) > 0 {
			if h.known || t.matchesCPE(it) {
				h.why = "named in the advisory's product data"
				return h, "", true
			}
			if t.re.MatchString(it.TechText()) { // only explain techs the text did mention
				return h, fmt.Sprintf("%s: mentioned in the text, but the advisory's product data names other products", t.name), false
			}
			return h, "", false
		}
		if it.StructuredOnly {
			if t.re.MatchString(it.TechText()) {
				return h, fmt.Sprintf("%s: mentioned in the text, but there is no product data yet; waiting for the feed to analyse it", t.name), false
			}
			return h, "", false
		}
	}
	text := it.TechText()
	if !t.re.MatchString(text) {
		return h, "", false
	}
	if t.exclude != nil {
		if m := t.exclude.FindString(text); m != "" {
			return h, fmt.Sprintf("%s: excluded because the text also says %q", t.name, strings.TrimSpace(strings.Trim(m, " .,;:()[]\"'"))), false
		}
	}
	h.why = "named in the title"
	if !it.TitleOnly {
		h.why = "named in the text"
	}
	return h, "", true
}

func (t tech) matchesCPE(it model.Item) bool {
	for _, a := range it.Affected {
		if a.Ecosystem == "cpe" && t.cpe[a.Name] {
			return true
		}
	}
	return false
}

// packageHit finds a lockfile package in the item. Structured package data
// is exact; free text is searched only for scoped names (vendor/package),
// and only when the feed gave no structured packages at all.
func packageHit(it model.Item, pkg model.Package) (ranges []model.Range, structured, ok bool) {
	hasStructured := false
	for _, a := range it.Affected {
		if a.Ecosystem == "cpe" {
			continue
		}
		hasStructured = true
		if a.Ecosystem == pkg.Ecosystem && a.Name == pkg.Name {
			ranges = append(ranges, a.Ranges...)
			ok = true
		}
	}
	if ok {
		return ranges, len(ranges) > 0, true
	}
	if !hasStructured && strings.Contains(pkg.Name, "/") && wordRe([]string{pkg.Name}).MatchString(strings.ToLower(it.Text())) {
		return nil, false, true
	}
	return nil, false, false
}

// Reassess re-checks what a project runs against affected data that arrived
// after the finding was created, for example NVD ranges for a CVE first seen
// in the news. It never lowers certainty without data: no data means unknown.
func (j *Judge) Reassess(installed []model.Installed, affected []model.Affected) (model.Applicability, []string) {
	var (
		out     = model.AppNotAffected
		reasons []string
	)
	for i, in := range installed {
		a := model.AppUnknown
		if ranges := j.rangesFor(in, affected); len(ranges) > 0 {
			a = version.Evaluate(in.Version, ranges)
		}
		if i == 0 {
			out = a
		} else {
			out = out.Worse(a)
		}
		reasons = append(reasons, fmt.Sprintf("%s: %s", in.Label(), verdictWords(a)))
	}
	if len(installed) == 0 {
		return model.AppUnknown, nil
	}
	return out, reasons
}

func (j *Judge) rangesFor(in model.Installed, affected []model.Affected) []model.Range {
	var out []model.Range
	for _, a := range affected {
		switch {
		case in.Via == "package" && a.Ecosystem == in.Ecosystem && a.Name == in.Name:
			out = append(out, a.Ranges...)
		case in.Via == "tech" && a.Ecosystem == "cpe":
			for _, t := range j.techs {
				if t.name == strings.ToLower(in.Name) && t.cpe[a.Name] {
					out = append(out, a.Ranges...)
				}
			}
		}
	}
	return out
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
