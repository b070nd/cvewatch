package relevance

import (
	"fmt"
	"slices"
	"strings"

	"github.com/b070nd/cvewatch/app/src/ecosystem"
	"github.com/b070nd/cvewatch/app/src/model"
)

// Matcher judges items against one inventory. Compile turns the targets into
// an index once: which targets declare which tech, and where every package
// sits by its identity and by its name. Judging an item then costs the size
// of the item, not the size of the inventory. A Matcher never changes after
// Compile, so it may be shared between goroutines and gives the same verdict
// for the same item every time.
type Matcher struct {
	targets []Target
	techs   []declared         // the rules of techs some target declares, in catalog order
	byKey   map[string][]place // package identity -> where it is installed
	scoped  names              // scoped package names, for text without product data
	named   [][]place          // per scoped name: where it is installed
	// products finds scoped packages by an advisory's product name: canonical
	// ecosystem -> normalized name -> where it is installed.
	products map[string]map[string][]place
	ecos     []string // the keys of products, sorted
}

// declared is a tech rule with the targets that run the tech.
type declared struct {
	rule tech
	uses []place // pos is the index in the target's Techs
	// patient: no target that declares the tech has the discovery profile,
	// so a text match waiting for product data is explained, not taken.
	patient bool
}

// place is one installed thing: a target and a position in its Techs or Packages.
type place struct{ target, pos int }

// Compile indexes the targets for the judge's rules. Only technologies some
// target runs are judged: the catalog holds many more, and judging them all
// would store and report advisories nobody here is exposed to.
func (j *Judge) Compile(targets []Target) *Matcher {
	m := &Matcher{targets: targets, byKey: map[string][]place{}, products: map[string]map[string][]place{}}
	uses := map[string][]place{}
	eager := map[string]bool{}
	for ti, tg := range targets {
		for pi, pt := range tg.Techs {
			name := strings.ToLower(pt.Name)
			uses[name] = append(uses[name], place{ti, pi})
			eager[name] = eager[name] || tg.Profile == model.ProfileDiscovery
		}
		for pi, pkg := range tg.Packages {
			at := place{ti, pi}
			key := pkgKey(pkg.Ecosystem, pkg.Name)
			m.byKey[key] = append(m.byKey[key], at)
			if !strings.ContainsAny(pkg.Name, "/:") { // vendor/package, group:artifact, module paths
				continue
			}
			eco := ecosystem.Canonical(pkg.Ecosystem)
			if m.products[eco] == nil {
				m.products[eco] = map[string][]place{}
			}
			norm := ecosystem.NormalizeName(pkg.Ecosystem, pkg.Name)
			m.products[eco][norm] = append(m.products[eco][norm], at)
		}
	}
	// Names are filed in target and package order, so the index is the same
	// for the same inventory.
	byName := map[string]int{}
	for ti, tg := range targets {
		for pi, pkg := range tg.Packages {
			if !strings.ContainsAny(pkg.Name, "/:") {
				continue
			}
			name := strings.ToLower(strings.TrimSpace(pkg.Name))
			i, ok := byName[name]
			if !ok {
				i = m.scoped.add(name)
				byName[name] = i
				m.named = append(m.named, nil)
			}
			m.named[i] = append(m.named[i], place{ti, pi})
		}
	}
	for eco := range m.products {
		m.ecos = append(m.ecos, eco)
	}
	slices.Sort(m.ecos)
	for _, t := range j.techs {
		if u := uses[t.name]; len(u) > 0 {
			m.techs = append(m.techs, declared{rule: t, uses: u, patient: !eager[t.name]})
		}
	}
	return m
}

// found is one installed thing an item matched, before it is grouped by target.
type found struct {
	at      place
	pkg     bool
	in      model.Installed
	applies model.Applicability
	waiting bool
}

// Judge evaluates one item against what each project environment runs.
func (m *Matcher) Judge(it model.Item) Verdict {
	var v Verdict
	text := newSubject(it.TechText())
	plain := text
	if it.TitleOnly {
		plain = newSubject(it.Text())
	}

	var all []found
	hitTechs := map[string]bool{}
	for _, d := range m.techs {
		h, note, ok := d.rule.judge(it, text)
		if note != "" && (!h.waiting || d.patient || !ok) {
			v.Notes = append(v.Notes, note)
		}
		if !ok {
			continue
		}
		for _, u := range d.uses {
			pt := m.targets[u.target].Techs[u.pos]
			in := model.Installed{Name: pt.Name, Version: pt.Version, Via: "tech", Ecosystem: d.rule.scheme, Basis: []model.Basis{h.basis}}
			all = append(all, found{at: u, in: in, applies: applies(in, h.ranges, h.known), waiting: h.waiting})
		}
	}
	all = m.packages(all, it, plain)
	if len(all) == 0 {
		return v
	}

	// Group by target, in target order; within a target techs come first,
	// each kind in the order the target lists it.
	slices.SortStableFunc(all, func(a, b found) int {
		if a.at.target != b.at.target {
			return a.at.target - b.at.target
		}
		if a.pkg != b.pkg {
			if b.pkg {
				return -1
			}
			return 1
		}
		return a.at.pos - b.at.pos
	})
	noted := map[string]bool{}
	strict := map[string]bool{}
	for i := 0; i < len(all); {
		ti := all[i].at.target
		tg := m.targets[ti]
		mt := Match{Project: tg.Project, Env: tg.Env, Applies: model.AppNotAffected}
		for ; i < len(all) && all[i].at.target == ti; i++ {
			f := all[i]
			switch profile := tg.Profile.Or(model.ProfileBalanced); {
			case f.waiting && profile != model.ProfileDiscovery:
				continue
			case profile == model.ProfileStrict && f.in.Weak():
				if !strict[tg.Project] {
					strict[tg.Project] = true
					v.Notes = append(v.Notes, fmt.Sprintf("%s: %s is named only in the text; the strict profile needs the advisory's product data", tg.Project, f.in.Name))
				}
				continue
			}
			mt.add(f.in, f.applies)
			if !f.pkg {
				hitTechs[strings.ToLower(f.in.Name)] = true
			}
		}
		if len(mt.Installed) == 0 {
			continue
		}
		if before := !tg.Since.IsZero() && !it.Published.IsZero() && it.Published.Before(tg.Since); before {
			if !noted[tg.Project] {
				noted[tg.Project] = true
				v.Notes = append(v.Notes, fmt.Sprintf("%s: published %s, before the project's start date %s",
					tg.Project, it.Published.UTC().Format("2006-01-02"), tg.Since.UTC().Format("2006-01-02")))
			}
			v.Held = append(v.Held, mt)
			continue
		}
		if tg.Horizon.Outside(it.Published) {
			if !noted[tg.Project] {
				noted[tg.Project] = true
				v.Notes = append(v.Notes, fmt.Sprintf("%s: published %s, outside the alert horizon",
					tg.Project, it.Published.UTC().Format("2006-01-02")))
			}
			v.Held = append(v.Held, mt)
			continue
		}
		v.Matches = append(v.Matches, mt)
	}
	if len(v.Matches) > 0 || len(noted) == 0 {
		for _, d := range m.techs { // catalog order, as the rules ran
			if hitTechs[d.rule.name] {
				v.Techs = append(v.Techs, d.rule.name)
			}
		}
	}
	return v
}

// packages adds the lockfile packages the item names. Structured package
// data is exact. An explicit product name can identify a scoped package when
// the source gave no package list. Free text is searched only for scoped
// names, and only when the source gave no product or package identity at all.
func (m *Matcher) packages(all []found, it model.Item, plain subject) []found {
	add := func(at place, ranges []model.Range, basis model.Basis) {
		pkg := m.targets[at.target].Packages[at.pos]
		in := model.Installed{Name: pkg.Name, Version: pkg.Version, Ecosystem: pkg.Ecosystem, Via: "package", Basis: []model.Basis{basis}}
		all = append(all, found{at: at, pkg: true, in: in, applies: applies(in, ranges, len(ranges) > 0)})
	}
	if len(it.Affected) == 0 && len(it.Products) == 0 {
		for _, i := range m.scoped.in(plain) {
			for _, at := range m.named[i] {
				add(at, nil, model.BasisText)
			}
		}
		return all
	}
	// A key with no ranges still means the source named that package, with
	// unknown version applicability.
	var listed map[string][]model.Range
	var keys []string
	for _, a := range it.Affected {
		if a.Ecosystem == model.EcoCPE {
			continue
		}
		if listed == nil {
			listed = map[string][]model.Range{}
		}
		key := pkgKey(a.Ecosystem, a.Name)
		if _, ok := listed[key]; !ok {
			keys = append(keys, key)
		}
		listed[key] = append(listed[key], a.Ranges...)
	}
	for _, key := range keys {
		for _, at := range m.byKey[key] {
			add(at, listed[key], model.BasisPackage)
		}
	}
	if len(keys) > 0 {
		return all
	}
	// Product names, no package list: keep applicability unknown, and never
	// search the description instead.
	taken := map[place]bool{}
	for _, p := range it.Products {
		for _, eco := range m.ecos {
			for _, at := range m.products[eco][ecosystem.NormalizeName(eco, p.Name)] {
				if !taken[at] {
					taken[at] = true
					add(at, nil, model.BasisProduct)
				}
			}
		}
	}
	return all
}

// Disproved reports whether the item's own product identity rules out an
// earlier match of something that is still installed. A match the item
// merely fails to reproduce is not disproved: a stored record is one view of
// several reports, and silence proves nothing. For a technology the item
// must name products, or carry structured data while the technology knows
// its CPE names; for a package the item must carry any product identity,
// because then its text is not searched. The caller has already seen that
// the item does not match the target.
func (m *Matcher) Disproved(it model.Item, in model.Installed) bool {
	if in.Via == "package" {
		return len(it.Affected) > 0 || len(it.Products) > 0
	}
	if len(it.Products) > 0 {
		return true
	}
	for _, d := range m.techs {
		if d.rule.name == strings.ToLower(in.Name) {
			return len(d.rule.cpe) > 0 && len(it.Affected) > 0
		}
	}
	return false
}

// Targets lists what the matcher was compiled for.
func (m *Matcher) Targets() []Target { return m.targets }
