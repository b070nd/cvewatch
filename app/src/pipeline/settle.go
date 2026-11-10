package pipeline

import (
	"fmt"
	"slices"
	"strings"

	"github.com/b070nd/cvewatch/app/src/audit"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/relevance"
)

// settle brings the findings of one vulnerability in line with what the
// matcher says about its stored record now. It is the one place where a
// finding is created after the first sighting, follows the inventory, gets a
// new verdict from data that arrived late, is retired, and comes back.
//
// The rules, in order:
//   - A match with no finding creates one, when create is set.
//   - A finding whose match still holds takes the installed versions, the
//     basis and the verdict of the match. Only an open finding follows a
//     changed inventory; the verdict of late data reaches closed ones too.
//   - A finding whose match is gone is retired only on proof: what matched is
//     no longer installed, the record's own product identity names something
//     else, or the project's strict profile no longer takes a text match. A
//     match the record merely does not reproduce stays: silence proves
//     nothing, and a lockfile that cannot be read hides nothing.
//   - A retired finding stays open with nothing installed and counts as not
//     affected, so it is neither listed nor alerted. Status, owner, notes,
//     evidence and deliveries are never touched.
//
// It only looks at the targets the matcher was compiled for, and reports the
// findings it created.
func (c *cycle) settle(v *model.Vulnerability, m *relevance.Matcher, create bool) []model.Finding {
	it := ItemOf(v, c.r.Cfg.Sources)
	verdict := m.Judge(it)
	want := map[string]relevance.Match{}
	for _, mt := range verdict.Matches {
		want[targetKey(mt.Project, mt.Env)] = mt
	}
	for _, mt := range verdict.Held {
		want[targetKey(mt.Project, mt.Env)] = mt
	}
	inScope := map[string]relevance.Target{}
	for _, tg := range m.Targets() {
		inScope[targetKey(tg.Project, tg.Env)] = tg
	}

	for _, f := range c.r.Ledger.FindingsOf(v.ID) {
		tg, ok := inScope[targetKey(f.Project, f.Env)]
		if !ok {
			continue // another run's project, or an environment that is not declared: applyEnvs decides
		}
		if mt, present := want[targetKey(f.Project, f.Env)]; present {
			c.follow(v, f, tg, mt, it, m)
		} else {
			c.retire(v, f, tg, it, m)
		}
	}
	if !create || len(verdict.Matches) == 0 {
		return nil
	}
	made := AddFindings(c.r.Ledger, v.ID, verdict.Matches, c.now)
	if len(made) > 0 {
		for _, t := range verdict.Techs {
			if !slices.Contains(v.Techs, t) {
				v.Techs = append(v.Techs, t)
			}
		}
		c.dirty[v.ID] = true
	}
	return made
}

func targetKey(project string, env model.Env) string { return project + "|" + string(env) }

// follow updates a finding whose match still holds.
func (c *cycle) follow(v *model.Vulnerability, f model.Finding, tg relevance.Target, mt relevance.Match, it model.Item, m *relevance.Matcher) {
	if sameInstalled(f.Installed, mt.Installed) {
		verdictChanged := f.Applies != mt.Applies
		if !verdictChanged && sameBasis(f.Installed, mt.Installed) {
			return
		}
		c.r.Ledger.Mutate(f.Key(), func(g *model.Finding) {
			g.Installed = mt.Installed // the basis may be new: older findings carry none
			if verdictChanged {
				g.Applies, g.Reasons, g.Updated = mt.Applies, mt.Reasons, c.now
			}
		})
		if verdictChanged {
			c.dirty[v.ID] = true
		}
		return
	}
	if f.Status != model.StatusOpen {
		return // a closed finding keeps what it was closed for
	}
	if len(f.Installed) == 0 {
		if f.Retired == "" {
			return // from before installed versions were recorded: nothing to compare
		}
		word := "installed again: "
		if f.Retired == model.RetiredUnmatched {
			word = "matches again: "
		}
		labels := labelsOf(mt.Installed)
		c.inventoryChange(f, mt.Installed, mt.Applies, mt.Reasons, "", word+strings.Join(labels, ", ")+"; now "+string(mt.Applies))
		return
	}

	// The installed set differs. Say how, entry by entry; an old entry the
	// match no longer has is dropped only on proof.
	now, applies, reasons := slices.Clone(mt.Installed), mt.Applies, slices.Clone(mt.Reasons)
	unreadable := len(c.inv.Unreadable(f.Project, f.Env)) > 0
	var changes, gone, unmatched []string
	moved := map[int]bool{} // entries of the match an old entry changed its version to
	for _, old := range f.Installed {
		if slices.ContainsFunc(mt.Installed, old.Same) {
			continue
		}
		if i := slices.IndexFunc(mt.Installed, func(n model.Installed) bool { return sameThing(n, old) }); i >= 0 {
			changes = append(changes, old.Label()+" → "+mt.Installed[i].Label())
			moved[i] = true
			continue
		}
		switch _, installed := tg.Find(old); {
		case !installed && old.Via == "package" && unreadable:
			return // unknown, not gone: the finding stays as it was
		case !installed:
			gone = append(gone, old.Label())
		case !c.holdUnmatched && (m.Disproved(it, old) || strictWeak(tg, old)):
			unmatched = append(unmatched, old.Label())
		default: // still installed and nothing rules it out (or a person is to rule): it stays, unchecked
			now = append(now, old)
			applies = applies.Worse(model.AppUnknown)
			reasons = append(reasons, old.Label()+": matched on an earlier report, version could not be checked")
		}
	}
	var added []string
	for i, n := range mt.Installed {
		if !moved[i] && !slices.ContainsFunc(f.Installed, n.Same) {
			added = append(added, n.Label())
		}
	}
	parts := slices.Concat(changes, prefixed("removed ", gone), prefixed("no longer matched ", unmatched), prefixed("added ", added))
	if len(parts) == 0 {
		return
	}
	c.inventoryChange(f, now, applies, reasons, "", strings.Join(parts, "; ")+"; now "+string(applies))
}

// retire gives up on a finding whose match is gone, when that is proven.
func (c *cycle) retire(v *model.Vulnerability, f model.Finding, tg relevance.Target, it model.Item, m *relevance.Matcher) {
	if f.Status != model.StatusOpen || len(f.Installed) == 0 {
		return
	}
	unreadable := len(c.inv.Unreadable(f.Project, f.Env)) > 0
	var gone, unmatched []string
	for _, old := range f.Installed {
		switch _, installed := tg.Find(old); {
		case !installed && old.Via == "package" && unreadable:
			return // unknown, not gone
		case !installed:
			gone = append(gone, old.Label())
		case m.Disproved(it, old) || strictWeak(tg, old):
			unmatched = append(unmatched, old.Label())
		default:
			return // still installed and nothing rules it out
		}
	}
	if len(unmatched) > 0 && c.holdUnmatched {
		c.held++
		return
	}
	why, reasons := model.RetiredUninstalled, []string{"no longer installed: " + strings.Join(gone, ", ")}
	if len(unmatched) > 0 {
		why = model.RetiredUnmatched
		reasons = []string{"no longer matched: " + strings.Join(unmatched, ", ") + " (" + unmatchedWhy(tg, it) + ")"}
		if len(gone) > 0 {
			reasons = append(reasons, "no longer installed: "+strings.Join(gone, ", "))
		}
	}
	note := strings.Join(slices.Concat(prefixed("removed ", gone), prefixed("no longer matched ", unmatched)), "; ") + "; now " + string(model.AppNotAffected)
	c.inventoryChange(f, nil, model.AppNotAffected, reasons, why, note)
	if why == model.RetiredUnmatched {
		c.res.Retired++
		c.retired = append(c.retired, f)
	}
}

// strictWeak reports whether the project's strict profile no longer takes
// the entry: it is known to have matched on text alone.
func strictWeak(tg relevance.Target, in model.Installed) bool {
	return tg.Profile == model.ProfileStrict && in.Weak()
}

func unmatchedWhy(tg relevance.Target, it model.Item) string {
	if len(it.Affected) > 0 || len(it.Products) > 0 {
		return "the advisory's product data names other products"
	}
	return fmt.Sprintf("the %s profile needs the advisory's product data", tg.Profile)
}

// sameThing reports whether two entries are the same technology or package,
// whatever the version.
func sameThing(a, b model.Installed) bool {
	return a.Via == b.Via && strings.EqualFold(a.Name, b.Name) && (a.Via != "package" || strings.EqualFold(a.Ecosystem, b.Ecosystem))
}

func sameInstalled(a, b []model.Installed) bool {
	return slices.EqualFunc(a, b, func(x, y model.Installed) bool { return x.Same(y) })
}

func sameBasis(a, b []model.Installed) bool {
	return slices.EqualFunc(a, b, func(x, y model.Installed) bool { return slices.Equal(x.Basis, y.Basis) })
}

func labelsOf(in []model.Installed) []string {
	labels := make([]string, len(in))
	for i, x := range in {
		labels[i] = x.Label()
	}
	return labels
}

// inventoryChange records a new installed state on a finding, in its history and in the audit trail.
func (c *cycle) inventoryChange(f model.Finding, now []model.Installed, applies model.Applicability, reasons []string, retired model.Retirement, note string) {
	c.r.Ledger.Mutate(f.Key(), func(m *model.Finding) {
		m.Installed, m.Matched, m.Applies, m.Reasons, m.Retired, m.Updated = now, labelsOf(now), applies, reasons, retired, c.now
		m.History = append(m.History, model.Disposition{Time: c.now, Actor: "cvewatch", Action: "inventory", Note: note})
	})
	c.events = append(c.events, audit.Event{Time: c.now, Actor: "cvewatch", Action: "inventory", Vuln: f.VulnID,
		Project: f.Project, Env: string(f.Env), Note: note})
	c.dirty[f.VulnID] = true
	c.res.Reconciled++
}

func prefixed(p string, xs []string) []string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = p + x
	}
	return out
}
