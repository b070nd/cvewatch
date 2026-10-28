// Package relevance decides whether a feed item matters to a project and
// whether the version the project runs is affected. It is the single place
// where the rules live: aliases, excludes, structured CPE and package data,
// title-only matching and version ranges. Every decision comes with reasons.
package relevance

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/b070nd/cvewatch/app/src/ecosystem"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/version"
)

type tech struct {
	name    string
	scheme  string // version ordering for what the tech runs: "", pypi, maven, go
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
		c := tech{name: strings.ToLower(t.Name), scheme: t.Scheme, re: wordRe(t.Terms()), cpe: map[string]bool{}}
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

// Names lists the technologies the judge knows, lowercase.
func (j *Judge) Names() []string {
	out := make([]string, len(j.techs))
	for i, t := range j.techs {
		out[i] = t.name
	}
	return out
}

// Verdict is what judging one item produced.
type Verdict struct {
	Techs   []string // techs the item is about, lowercase
	Matches []Match  // projects that run something affected or possibly affected
	Notes   []string // why a tech did not match, for explanations
}

// Relevant reports whether any tech or project matched.
func (v Verdict) Relevant() bool { return len(v.Techs) > 0 || len(v.Matches) > 0 }

// Target is one project environment as relevance sees it: what runs there.
// The inventory module builds them from config, lockfiles and SBOMs.
type Target struct {
	Project  string
	Env      model.Env
	Techs    []model.ProjectTech // declared techs with this environment's versions
	Packages []model.Package
	Image    string    // image tag or digest, recorded only
	Since    time.Time // items published before this are not judged; zero judges all
}

// Find returns what the target currently runs for an earlier match, so a
// finding can be re-checked after a lockfile or declared version changed.
// A package is found by ecosystem and name; if several versions are
// installed the one equal to the old version wins.
func (t Target) Find(old model.Installed) (model.Installed, bool) {
	switch old.Via {
	case "tech":
		for _, pt := range t.Techs {
			if strings.EqualFold(pt.Name, old.Name) {
				return model.Installed{Name: pt.Name, Version: pt.Version, Via: "tech"}, true
			}
		}
	case "package":
		var first *model.Package
		for i, p := range t.Packages {
			if pkgKey(p.Ecosystem, p.Name) != pkgKey(old.Ecosystem, old.Name) {
				continue
			}
			if p.Version == old.Version {
				return model.Installed{Name: p.Name, Version: p.Version, Ecosystem: p.Ecosystem, Via: "package"}, true
			}
			if first == nil {
				first = &t.Packages[i]
			}
		}
		if first != nil {
			return model.Installed{Name: first.Name, Version: first.Version, Ecosystem: first.Ecosystem, Via: "package"}, true
		}
	}
	return model.Installed{}, false
}

// pkgKey is the identity of a package across lockfiles, SBOMs and advisories.
func pkgKey(eco, name string) string {
	return ecosystem.Canonical(eco) + "|" + ecosystem.NormalizeName(eco, name)
}

// Match is the outcome for one project environment.
type Match struct {
	Project   string
	Env       model.Env
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

// Judge evaluates one item against what each project environment runs.
func (j *Judge) Judge(it model.Item, targets []Target) Verdict {
	var v Verdict
	// Only technologies some project environment runs are judged. The catalog
	// holds many more; judging them all would store and report advisories
	// nobody here is exposed to.
	declared := map[string]bool{}
	for _, tg := range targets {
		for _, pt := range tg.Techs {
			declared[strings.ToLower(pt.Name)] = true
		}
	}
	schemes := map[string]string{}
	hits := map[string]hit{}
	for _, t := range j.techs {
		if !declared[t.name] {
			continue
		}
		schemes[t.name] = t.scheme
		h, note, ok := t.judge(it)
		if note != "" {
			v.Notes = append(v.Notes, note)
		}
		if ok {
			hits[t.name] = h
			v.Techs = append(v.Techs, t.name)
		}
	}

	noted := map[string]bool{}
	for _, tg := range targets {
		m := Match{Project: tg.Project, Env: tg.Env, Applies: model.AppNotAffected}
		for _, pt := range tg.Techs {
			h, ok := hits[strings.ToLower(pt.Name)]
			if !ok {
				continue
			}
			in := model.Installed{Name: pt.Name, Version: pt.Version, Via: "tech", Ecosystem: schemes[strings.ToLower(pt.Name)]}
			m.add(in, applies(in, h.ranges, h.known), h.why)
		}
		for _, pkg := range tg.Packages {
			in := model.Installed{Name: pkg.Name, Version: pkg.Version, Ecosystem: pkg.Ecosystem, Via: "package"}
			if rs, structured, ok := packageHit(it, pkg); ok {
				why := "named in the advisory's package list"
				if !structured {
					why = "named in the text"
				}
				m.add(in, applies(in, rs, structured), why)
			}
		}
		if len(m.Installed) == 0 {
			continue
		}
		if before := !tg.Since.IsZero() && !it.Published.IsZero() && it.Published.Before(tg.Since); before {
			if !noted[tg.Project] {
				noted[tg.Project] = true
				v.Notes = append(v.Notes, fmt.Sprintf("%s: published %s, before the project's start date %s",
					tg.Project, it.Published.UTC().Format("2006-01-02"), tg.Since.UTC().Format("2006-01-02")))
			}
			continue
		}
		v.Matches = append(v.Matches, m)
	}
	if len(v.Matches) == 0 && len(noted) > 0 {
		v.Techs = nil
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

// applies compares the installed version with the ranges in the ordering of
// its own ecosystem (PEP 440 for PyPI, Maven rules for Maven, and so on).
func applies(in model.Installed, ranges []model.Range, known bool) model.Applicability {
	if !known {
		return model.AppUnknown
	}
	return version.EvaluateFor(in.Ecosystem, in.Version, ranges)
}

// judge decides one tech. Structured CPE data wins over text when the tech
// knows its CPE names: that is what removes "mentioned in passing" noise.
func (t tech) judge(it model.Item) (h hit, note string, ok bool) {
	if len(t.cpe) > 0 {
		for _, a := range it.Affected {
			if a.Ecosystem == model.EcoCPE && t.cpe[a.Name] {
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
		if a.Ecosystem == model.EcoCPE && t.cpe[a.Name] {
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
	want := pkgKey(pkg.Ecosystem, pkg.Name)
	for _, a := range it.Affected {
		if a.Ecosystem == model.EcoCPE {
			continue
		}
		hasStructured = true
		if pkgKey(a.Ecosystem, a.Name) == want {
			ranges = append(ranges, a.Ranges...)
			ok = true
		}
	}
	if ok {
		return ranges, len(ranges) > 0, true
	}
	scoped := strings.ContainsAny(pkg.Name, "/:") // vendor/package, group:artifact, module paths
	if !hasStructured && scoped && wordRe([]string{pkg.Name}).MatchString(strings.ToLower(it.Text())) {
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
			a = version.EvaluateFor(in.Ecosystem, in.Version, ranges)
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
		case in.Via == "package" && pkgKey(a.Ecosystem, a.Name) == pkgKey(in.Ecosystem, in.Name):
			out = append(out, a.Ranges...)
		case in.Via == "tech" && a.Ecosystem == model.EcoCPE:
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
