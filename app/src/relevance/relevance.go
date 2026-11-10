// Package relevance decides whether a feed item matters to a project and
// whether the version the project runs is affected. It is the single place
// where the rules live: aliases, excludes, structured CPE and package data,
// explicit product names, title-only matching, version ranges and the
// matching profiles. Every decision comes with its basis and with reasons.
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

// RulesVersion names the matching rules. It is part of what findings are
// judged against, so raising it makes every ledger judge its findings again.
//
//	2  explicit product names bound text matches; matches carry their basis;
//	   a match that no longer holds is retired; matching profiles
const RulesVersion = 2

type tech struct {
	name    string
	scheme  string // version ordering for what the tech runs: "", pypi, maven, go
	re      words
	exclude *regexp.Regexp // nil when the tech has no excludes
	cpe     map[string]bool
}

// Judge holds the technology rules. It is immutable and rebuilt from config
// every run, so edits take effect on the next cycle. Compile ties it to an
// inventory; that is what judges items.
type Judge struct{ techs []tech }

func New(techs []model.Tech) *Judge {
	j := &Judge{}
	for _, t := range techs {
		c := tech{name: strings.ToLower(t.Name), scheme: t.Scheme, re: newWords(t.Terms()), cpe: map[string]bool{}}
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

// Judge evaluates one item against what each project environment runs. It
// compiles the targets first; callers that judge many items compile once.
func (j *Judge) Judge(it model.Item, targets []Target) Verdict {
	return j.Compile(targets).Judge(it)
}

// Verdict is what judging one item produced.
type Verdict struct {
	Techs   []string // techs the item is about, lowercase
	Matches []Match  // projects that run something affected or possibly affected
	// Held are matches kept back because the item was published before the
	// project's start date or outside the alert horizon. They create no
	// finding, but they do say the match itself still holds.
	Held  []Match
	Notes []string // why a tech did not match, for explanations
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
	Image    string        // image tag or digest, recorded only
	Since    time.Time     // items published before this are not judged; zero judges all
	Horizon  Window        // the alert horizon; items published outside it are not judged
	Profile  model.Profile // how much evidence a match needs; empty is balanced
}

// Window is a span of publication dates with inclusive ends; a zero end is open.
type Window struct{ From, To time.Time }

// Outside reports whether a dated item falls outside the window. An item
// without a date is never outside.
func (w Window) Outside(published time.Time) bool {
	return !published.IsZero() && (!w.From.IsZero() && published.Before(w.From) || !w.To.IsZero() && published.After(w.To))
}

// Find returns what the target currently runs for an earlier match, so a
// finding can tell "no longer installed" from "no longer matched".
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
	Installed []model.Installed   // each with the basis it matched on
	Applies   model.Applicability // the most urgent over everything installed
	Reasons   []string
}

func (m *Match) add(in model.Installed, a model.Applicability) {
	m.Installed = append(m.Installed, in)
	if len(m.Installed) == 1 {
		m.Applies = a
	} else {
		m.Applies = m.Applies.Worse(a)
	}
	m.Reasons = append(m.Reasons, fmt.Sprintf("%s: %s, %s", in.Label(), basisWords(in), verdictWords(a)))
}

// basisWords says in plain words what tied the installed thing to the item.
func basisWords(in model.Installed) string {
	if len(in.Basis) == 0 {
		return "matched"
	}
	switch in.Basis[0] {
	case model.BasisPackage:
		return "named in the advisory's package list"
	case model.BasisCPE, model.BasisProduct:
		return "named in the advisory's product data"
	case model.BasisTitle:
		return "named in the title"
	}
	return "named in the text"
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

// hit is a tech the item is about, with the versions NVD-style data says are affected.
type hit struct {
	ranges []model.Range
	known  bool // ranges came from structured data
	basis  model.Basis
	// waiting: the text names the tech, but the source is structured-only and
	// its product data has not arrived. Only the discovery profile takes it.
	waiting bool
}

// judge decides one tech. The source's own product identity wins over text:
// that is what removes "mentioned in passing" noise.
func (t tech) judge(it model.Item, text subject) (h hit, note string, ok bool) {
	// Explicit product names bound the text fallback, also for sources such
	// as KEV and CVE records that need not supply CPEs. The technology's name
	// or an alias can identify the product; a mention in the description cannot.
	if len(it.Products) > 0 && !t.matchesCPE(it) {
		for _, p := range it.Products {
			for _, term := range t.re.terms {
				if strings.EqualFold(p.Name, term) || strings.EqualFold(strings.TrimSpace(p.Vendor+" "+p.Name), term) {
					return hit{basis: model.BasisProduct}, "", true
				}
			}
		}
		if t.re.match(text) {
			return h, fmt.Sprintf("%s: mentioned in the text, but the advisory's product data names other products", t.name), false
		}
		return h, "", false
	}
	if len(t.cpe) > 0 {
		for _, a := range it.Affected {
			if a.Ecosystem == model.EcoCPE && t.cpe[a.Name] {
				h.ranges = append(h.ranges, a.Ranges...)
				h.known = h.known || len(a.Ranges) > 0
			}
		}
		// Any structured data (CPE products or package lists) says what the
		// advisory is about, so a passing mention of the tech in the text is ignored.
		if len(it.Affected) > 0 {
			if h.known || t.matchesCPE(it) {
				h.basis = model.BasisCPE
				return h, "", true
			}
			if t.re.match(text) { // only explain techs the text did mention
				return h, fmt.Sprintf("%s: mentioned in the text, but the advisory's product data names other products", t.name), false
			}
			return h, "", false
		}
		if it.StructuredOnly {
			if !t.re.match(text) {
				return h, "", false
			}
			return hit{basis: textBasis(it), waiting: true},
				fmt.Sprintf("%s: mentioned in the text, but there is no product data yet; waiting for the feed to analyse it", t.name),
				t.excluded(text) == ""
		}
	}
	if !t.re.match(text) {
		return h, "", false
	}
	if x := t.excluded(text); x != "" {
		return h, x, false
	}
	h.basis = textBasis(it)
	return h, "", true
}

// excluded returns the note for a text that also holds one of the tech's
// exclude terms, or "".
func (t tech) excluded(text subject) string {
	if t.exclude == nil {
		return ""
	}
	if m := t.exclude.FindString(text.text); m != "" {
		return fmt.Sprintf("%s: excluded because the text also says %q", t.name, strings.TrimSpace(strings.Trim(m, " .,;:()[]\"'")))
	}
	return ""
}

func textBasis(it model.Item) model.Basis {
	if it.TitleOnly {
		return model.BasisTitle
	}
	return model.BasisText
}

func (t tech) matchesCPE(it model.Item) bool {
	for _, a := range it.Affected {
		if a.Ecosystem == model.EcoCPE && t.cpe[a.Name] {
			return true
		}
	}
	return false
}
