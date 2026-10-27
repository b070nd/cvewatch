// Package ledger holds the monitor's domain state in memory: which
// vulnerabilities are known, which findings exist per project and
// environment, and where each feed left off. It owns identity: deciding that
// two reports are the same issue, and merging what they say.
//
// Persistence is not its concern. A storage adapter loads and saves State.
// A Ledger is not safe for concurrent use.
package ledger

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/b070nd/cvewatch/app/src/model"
)

// State is everything that is persisted.
type State struct {
	Vulns    map[string]*model.Vulnerability `json:"vulns"`
	Findings map[string]*model.Finding       `json:"findings"`
	Feeds    map[string]model.FeedState      `json:"feeds"`
}

type Ledger struct {
	d     State
	byKey map[string]string // any id or alias -> primary vulnerability id
}

// New wraps loaded state, filling in empty maps and building the id index.
func New(s State) *Ledger {
	if s.Vulns == nil {
		s.Vulns = map[string]*model.Vulnerability{}
	}
	if s.Findings == nil {
		s.Findings = map[string]*model.Finding{}
	}
	if s.Feeds == nil {
		s.Feeds = map[string]model.FeedState{}
	}
	l := &Ledger{d: s, byKey: map[string]string{}}
	for _, v := range s.Vulns {
		l.index(v)
	}
	return l
}

// State returns what should be persisted.
func (l *Ledger) State() State { return l.d }

func (l *Ledger) index(v *model.Vulnerability) {
	for _, k := range v.Keys() {
		l.byKey[k] = v.ID
	}
}

// Lookup returns the known vulnerability matching any of the keys, or nil.
func (l *Ledger) Lookup(keys []string) *model.Vulnerability {
	for _, k := range keys {
		if id, ok := l.byKey[k]; ok {
			return l.d.Vulns[id]
		}
	}
	return nil
}

func (l *Ledger) Vuln(id string) *model.Vulnerability { return l.d.Vulns[id] }

// Create records a first sighting. Callers decide afterwards how much of it
// to keep if it turns out to be irrelevant.
func (l *Ledger) Create(it model.Item, now time.Time, techs []string) *model.Vulnerability {
	keys := it.Keys()
	v := &model.Vulnerability{
		ID: keys[0], Aliases: slices.Clone(keys[1:]), Title: it.Title, Summary: it.Summary,
		Severity: it.Severity, CVSS: it.CVSS, Published: it.Published, FirstSeen: now,
		Refs: []model.Ref{refOf(it)}, Affected: slices.Clone(it.Affected), Fixes: slices.Clone(it.Fixes),
		Techs: techs,
	}
	if v.Severity == "" {
		v.Severity = model.SevUnknown
	}
	if v.Published.IsZero() {
		v.Published = now
	}
	l.d.Vulns[v.ID] = v
	l.index(v)
	return v
}

// Relevant returns vulnerabilities that have at least one finding, ordered by id.
func (l *Ledger) Relevant() []*model.Vulnerability {
	seen := map[string]bool{}
	var out []*model.Vulnerability
	for _, f := range l.d.Findings {
		if v := l.d.Vulns[f.VulnID]; v != nil && !seen[v.ID] {
			seen[v.ID] = true
			out = append(out, v)
		}
	}
	slices.SortFunc(out, func(a, b *model.Vulnerability) int { return strings.Compare(a.ID, b.ID) })
	return out
}

// AddFinding inserts a finding unless it already exists, so reruns never
// reset a status. It reports whether the finding is new.
func (l *Ledger) AddFinding(f model.Finding) bool {
	if _, ok := l.d.Findings[f.Key()]; ok {
		return false
	}
	l.d.Findings[f.Key()] = &f
	return true
}

// Findings returns copies ordered by project, vulnerability, then promotion order of the env.
func (l *Ledger) Findings() []model.Finding {
	out := make([]model.Finding, 0, len(l.d.Findings))
	for _, f := range l.d.Findings {
		out = append(out, *f)
	}
	slices.SortFunc(out, func(a, b model.Finding) int {
		if c := strings.Compare(a.Project, b.Project); c != 0 {
			return c
		}
		if c := strings.Compare(a.VulnID, b.VulnID); c != 0 {
			return c
		}
		return slices.Index(model.AllEnvs, a.Env) - slices.Index(model.AllEnvs, b.Env)
	})
	return out
}

func (l *Ledger) FindingsOf(vulnID string) []model.Finding {
	return slices.DeleteFunc(l.Findings(), func(f model.Finding) bool { return f.VulnID != vulnID })
}

// UpdateFindings lets fn adjust every finding of one vulnerability in place.
func (l *Ledger) UpdateFindings(vulnID string, fn func(*model.Finding)) {
	for _, f := range l.d.Findings {
		if f.VulnID == vulnID {
			fn(f)
		}
	}
}

// SetStatus updates findings of one vulnerability in a project; an empty env
// means every environment. It returns how many findings changed.
func (l *Ledger) SetStatus(vulnID, project string, env model.Env, st model.Status, note string, now time.Time) (int, error) {
	n := 0
	for _, f := range l.d.Findings {
		if f.VulnID != vulnID || f.Project != project || (env != "" && f.Env != env) {
			continue
		}
		f.Status, f.Note, f.Updated = st, note, now
		n++
	}
	if n == 0 {
		return 0, fmt.Errorf("no finding for %s in project %q env %q", vulnID, project, env)
	}
	return n, nil
}

// MarkAlerted records that a finding reached the notifier.
func (l *Ledger) MarkAlerted(key string, at time.Time) {
	if f := l.d.Findings[key]; f != nil {
		f.AlertedAt = at
	}
}

// Prune forgets vulnerabilities that never produced a finding and were first
// seen before the cutoff. Findings and what they refer to are kept for good.
// It returns how many records were dropped.
func (l *Ledger) Prune(before time.Time) int {
	keep := map[string]bool{}
	for _, f := range l.d.Findings {
		keep[f.VulnID] = true
	}
	n := 0
	for id, v := range l.d.Vulns {
		if keep[id] || !v.FirstSeen.Before(before) {
			continue
		}
		for _, k := range v.Keys() {
			delete(l.byKey, k)
		}
		delete(l.d.Vulns, id)
		n++
	}
	return n
}

func (l *Ledger) Feed(id string) model.FeedState       { return l.d.Feeds[id] }
func (l *Ledger) SetFeed(id string, f model.FeedState) { l.d.Feeds[id] = f }
