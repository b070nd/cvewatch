package ledger

import (
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/b070nd/cvewatch/app/src/model"
)

// mergeWindow is how far apart two reports may be dated and still count as
// one issue when they share no id.
const mergeWindow = 14 * 24 * time.Hour

// similarity is the share of distinctive title words two reports must have in common.
const similarity = 0.6

// Identify decides whether an item is about an issue we already track.
//
//   - Items sharing an id with a known record belong to it. If they bridge
//     two records, those are unified, so a GHSA-only record and a CVE-only
//     record become one the moment an item names both.
//   - A relevant item without a shared id joins a tracked, relevant record
//     whose title is close enough and which is dated within mergeWindow.
//     Irrelevant items never merge, so noise cannot swallow a real issue.
//
// An article naming several CVEs (a roundup, a comparison) must not merge
// distinct vulnerabilities, so only an advisory carrying exactly one CVE id
// and one GHSA id, the two names of a single flaw, can unify records. Any
// other multi-id item is linked to every record it names instead.
//
// It returns the record to absorb the item into, or nil if the item is new,
// the records that were folded away (so callers can remove their reports),
// and the other records the item was linked to (so callers can refresh theirs).
func (l *Ledger) Identify(it model.Item, relevant bool) (v *model.Vulnerability, gone, linked []*model.Vulnerability) {
	var hits []*model.Vulnerability
	for _, k := range it.Keys() {
		if id, ok := l.byKey[k]; ok {
			if v := l.d.Vulns[id]; !slices.Contains(hits, v) {
				hits = append(hits, v)
			}
		}
	}
	switch len(hits) {
	case 0:
		if relevant {
			return l.similar(it), nil, nil
		}
		return nil, nil, nil
	case 1:
		return hits[0], nil, nil
	}
	if model.RefKind(it.SourceType) == model.RefAdvisory && len(hits) == 2 && isAliasPair(it.IDs) {
		main, gone := l.unify(hits)
		return main, gone, nil
	}
	ref := []model.Ref{refOf(it)}
	for _, o := range hits[1:] {
		o.Refs = mergeRefs(o.Refs, ref)
	}
	return hits[0], nil, hits[1:]
}

// isAliasPair reports exactly one CVE id and one GHSA id.
func isAliasPair(ids []string) bool {
	var cve, ghsa int
	for _, id := range ids {
		switch {
		case strings.HasPrefix(id, "CVE-"):
			cve++
		case strings.HasPrefix(id, "GHSA-"):
			ghsa++
		}
	}
	return cve == 1 && ghsa == 1 && len(ids) == 2
}

func (l *Ledger) similar(it model.Item) *model.Vulnerability {
	for _, base := range l.Relevant() {
		if !it.Published.IsZero() {
			if gap := base.Published.Sub(it.Published); gap >= mergeWindow || gap <= -mergeWindow {
				continue
			}
		}
		if Similar(base.Title, it.Title) {
			return base
		}
	}
	return nil
}

// unify folds several records into the one first seen, moves their findings
// across, and returns it with the records that disappeared.
func (l *Ledger) unify(vs []*model.Vulnerability) (*model.Vulnerability, []*model.Vulnerability) {
	slices.SortFunc(vs, func(a, b *model.Vulnerability) int {
		if c := a.FirstSeen.Compare(b.FirstSeen); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})
	main, gone := vs[0], vs[1:]
	for _, g := range gone {
		main.Aliases = appendMissing(main.Aliases, append([]string{g.ID}, g.Aliases...)...)
		main.Refs = mergeRefs(main.Refs, g.Refs)
		main.Affected = mergeAffected(main.Affected, g.Affected)
		main.Fixes = mergeFixes(main.Fixes, g.Fixes)
		main.Techs = appendMissing(main.Techs, g.Techs...)
		if main.KEV == nil {
			main.KEV = g.KEV
		}
		if main.EPSS == nil {
			main.EPSS = g.EPSS
		}
		if main.Summary == "" {
			main.Summary = g.Summary
		}
		if g.Severity.Rank() > main.Severity.Rank() {
			main.Severity = g.Severity
		}
		if r := g.Rating(); r.Better(main.Rating()) {
			main.SetRating(r)
		}
		for key, f := range l.d.Findings {
			if f.VulnID != g.ID {
				continue
			}
			delete(l.d.Findings, key)
			f.VulnID = main.ID
			if _, taken := l.d.Findings[f.Key()]; !taken {
				l.d.Findings[f.Key()] = f
			}
		}
		delete(l.d.Vulns, g.ID)
	}
	l.index(main)
	return main, gone
}

// Change says what a repeat sighting added to a known record.
type Change struct {
	Any      bool // anything at all: a new link, id, severity, range or fix
	Evidence bool // new affected ranges or fixes, which can change who is affected
}

// Absorb folds a repeat sighting into a known record.
func (l *Ledger) Absorb(v *model.Vulnerability, it model.Item) Change {
	var c Change
	changed := false
	if refs := mergeRefs(v.Refs, []model.Ref{refOf(it)}); !slices.Equal(refs, v.Refs) {
		v.Refs, changed = refs, true
	}
	if aliases := appendMissing(slices.Clone(v.Aliases), without(it.Keys(), v.ID)...); len(aliases) != len(v.Aliases) {
		v.Aliases, changed = aliases, true
	}
	l.index(v)
	if it.Severity.Rank() > v.Severity.Rank() {
		v.Severity, changed = it.Severity, true
	}
	if r := it.Rating(); r.Better(v.Rating()) { // see model.Rating for the precedence
		v.SetRating(r)
		changed = true
	}
	if a := mergeAffected(v.Affected, it.Affected); !affectedEqual(a, v.Affected) {
		v.Affected, changed, c.Evidence = a, true, true
	}
	if f := mergeFixes(v.Fixes, it.Fixes); len(f) != len(v.Fixes) {
		v.Fixes, changed, c.Evidence = f, true, true
	}
	if it.KEV != nil && v.KEV == nil {
		v.KEV, changed = it.KEV, true // a later KEV listing counts, even though it shares its URL with the NVD entry
	}
	if !it.Published.IsZero() && it.Published.Before(v.Published) {
		v.Published, changed = it.Published, true
	}
	c.Any = changed
	return c
}

func refOf(it model.Item) model.Ref {
	return model.Ref{Source: it.SourceID, Kind: model.RefKind(it.SourceType), URL: it.URL, Title: it.Title, Published: it.Published}
}

// mergeRefs adds refs whose URL is new and fills gaps in known ones.
func mergeRefs(have, more []model.Ref) []model.Ref {
	out := slices.Clone(have)
	for _, r := range more {
		i := slices.IndexFunc(out, func(o model.Ref) bool { return o.URL == r.URL })
		switch {
		case i < 0:
			out = append(out, r)
		default:
			if out[i].Title == "" {
				out[i].Title = r.Title
			}
			if out[i].Published.IsZero() {
				out[i].Published = r.Published
			}
			if out[i].Kind == "" {
				out[i].Kind = r.Kind
			}
		}
	}
	return out
}

func mergeAffected(have, more []model.Affected) []model.Affected {
	out := slices.Clone(have)
	for _, a := range more {
		i := slices.IndexFunc(out, func(o model.Affected) bool { return o.Ecosystem == a.Ecosystem && o.Name == a.Name })
		if i < 0 {
			out = append(out, a)
			continue
		}
		for _, r := range a.Ranges {
			if !slices.Contains(out[i].Ranges, r) {
				out[i].Ranges = append(slices.Clone(out[i].Ranges), r)
			}
		}
		if out[i].Fixed == "" {
			out[i].Fixed = a.Fixed
		}
	}
	return out
}

func affectedEqual(a, b []model.Affected) bool {
	return slices.EqualFunc(a, b, func(x, y model.Affected) bool {
		return x.Ecosystem == y.Ecosystem && x.Name == y.Name && x.Fixed == y.Fixed && slices.Equal(x.Ranges, y.Ranges)
	})
}

func mergeFixes(have, more []model.Fix) []model.Fix {
	out := slices.Clone(have)
	for _, f := range more {
		if !slices.ContainsFunc(out, func(o model.Fix) bool { return o.Kind == f.Kind && o.Detail == f.Detail && o.URL == f.URL }) {
			out = append(out, f)
		}
	}
	return out
}

func appendMissing(have []string, more ...string) []string {
	for _, s := range more {
		if s != "" && !slices.Contains(have, s) {
			have = append(have, s)
		}
	}
	return have
}

func without(ids []string, drop string) []string {
	return slices.DeleteFunc(slices.Clone(ids), func(s string) bool { return s == drop })
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
	return float64(shared)/float64(len(wa)+len(wb)-shared) >= similarity
}
