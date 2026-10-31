// Package ledger holds the monitor's domain state in memory: which
// vulnerabilities are known, which findings exist per project and
// environment, and where each feed left off. It owns identity: deciding that
// two reports are the same issue, and merging what they say.
//
// Persistence is not its concern. A storage adapter loads and saves State.
// A Ledger is not safe for concurrent use.
package ledger

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/b070nd/cvewatch/app/src/model"
)

// State is everything that is persisted.
type State struct {
	// SchemaVersion says which layout the data has; New migrates older data.
	SchemaVersion int `json:"schema_version"`
	// Rev counts saves. Storage adapters use it to refuse a stale write.
	Rev      int64                           `json:"rev"`
	Vulns    map[string]*model.Vulnerability `json:"vulns"`
	Findings map[string]*model.Finding       `json:"findings"`
	Feeds    map[string]model.FeedState      `json:"feeds"`
	// Digests remembers when each channel last got its periodic digest.
	Digests map[string]time.Time `json:"digests,omitempty"`
	// Judged is what the findings were last judged against; see Revalidate.
	Judged *model.Judging `json:"judged,omitempty"`
	// Updated remembers when each project was last refreshed, by a scheduled
	// or a manual run; the next scheduled one is due a period after.
	Updated map[string]time.Time `json:"updated,omitempty"`

	// Health of the tool itself, for the status command, dashboard and TUI.
	Cycles    []model.CycleRecord            `json:"cycles,omitempty"` // newest last, capped
	Sources   map[string]model.SourceHealth  `json:"sources,omitempty"`
	Channels  map[string]model.ChannelHealth `json:"channels,omitempty"`
	Heartbeat *model.Heartbeat               `json:"heartbeat,omitempty"`
}

// SchemaVersion is the current layout of State.
//
//	1  per-channel delivery records (Finding.Alerted) replace Finding.AlertedAt
//	2  health records: cycles, per-source and per-channel outcomes, heartbeat
const SchemaVersion = 2

// maxCycles is how many cycle records are kept.
const maxCycles = 50

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
	if s.Digests == nil {
		s.Digests = map[string]time.Time{}
	}
	if s.Updated == nil {
		s.Updated = map[string]time.Time{}
	}
	if s.Sources == nil {
		s.Sources = map[string]model.SourceHealth{}
	}
	if s.Channels == nil {
		s.Channels = map[string]model.ChannelHealth{}
	}
	migrate(&s)
	l := &Ledger{d: s, byKey: map[string]string{}}
	for _, v := range s.Vulns {
		l.index(v)
	}
	return l
}

// State returns what should be persisted.
func (l *Ledger) State() State { return l.d }

// Clone returns an independent copy, for trying a change without making it.
func (l *Ledger) Clone() (*Ledger, error) {
	raw, err := json.Marshal(l.d)
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	return New(s), nil
}

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
		Severity: it.Severity, CVSS: it.CVSS, CVSSVersion: it.CVSSVersion, CVSSVector: it.CVSSVector, CVSSSource: it.CVSSSource,
		Published: it.Published, FirstSeen: now,
		Refs: []model.Ref{refOf(it)}, Affected: slices.Clone(it.Affected), Fixes: slices.Clone(it.Fixes),
		KEV: it.KEV, Techs: techs,
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
		return model.EnvCompare(a.Env, b.Env)
	})
	return out
}

func (l *Ledger) FindingsOf(vulnID string) []model.Finding {
	return slices.DeleteFunc(l.Findings(), func(f model.Finding) bool { return f.VulnID != vulnID })
}

// RenameProject moves every finding of a project to a new name, re-keying them.
// It changes nothing and fails if a finding of the new name already has the
// same key. It returns how many findings moved.
func (l *Ledger) RenameProject(from, to string) (int, error) {
	var moving []*model.Finding
	for _, f := range l.d.Findings {
		if f.Project == from {
			moving = append(moving, f)
		}
	}
	for _, f := range moving {
		if _, taken := l.d.Findings[f.VulnID+"|"+to+"|"+string(f.Env)]; taken {
			return 0, fmt.Errorf("project %q already has a finding for %s in %s", to, f.VulnID, f.Env)
		}
	}
	for _, f := range moving {
		delete(l.d.Findings, f.Key())
		f.Project = to
		l.d.Findings[f.Key()] = f
	}
	if at, ok := l.d.Updated[from]; ok {
		delete(l.d.Updated, from)
		l.d.Updated[to] = at
	}
	return len(moving), nil
}

// EnvMove is what RenameEnv would move: the findings of a project in one
// environment, or the first finding of the new name that is in the way.
func (l *Ledger) EnvMove(project string, from, to model.Env) (int, error) {
	n := 0
	for _, f := range l.d.Findings {
		if f.Project != project || f.Env != from {
			continue
		}
		if _, taken := l.d.Findings[f.VulnID+"|"+project+"|"+string(to)]; taken {
			return 0, fmt.Errorf("project %q already has a finding for %s in %s", project, f.VulnID, to)
		}
		n++
	}
	return n, nil
}

// RenameEnv moves the findings of a project from one environment name to another, re-keying them.
// It changes nothing and fails if a finding of the new name is in the way.
func (l *Ledger) RenameEnv(project string, from, to model.Env) (int, error) {
	n, err := l.EnvMove(project, from, to)
	if err != nil {
		return 0, err
	}
	var moving []*model.Finding
	for _, f := range l.d.Findings {
		if f.Project == project && f.Env == from {
			moving = append(moving, f)
		}
	}
	for _, f := range moving {
		delete(l.d.Findings, f.Key())
		f.Env = to
		l.d.Findings[f.Key()] = f
	}
	return n, nil
}

// Mutate lets fn adjust one finding in place; it reports whether the finding exists.
func (l *Ledger) Mutate(key string, fn func(*model.Finding)) bool {
	f := l.d.Findings[key]
	if f != nil {
		fn(f)
	}
	return f != nil
}

// UpdateFindings lets fn adjust every finding of one vulnerability in place.
func (l *Ledger) UpdateFindings(vulnID string, fn func(*model.Finding)) {
	for _, f := range l.d.Findings {
		if f.VulnID == vulnID {
			fn(f)
		}
	}
}

// Update describes a change to findings. Nil fields stay as they are.
type Update struct {
	Actor    string
	Status   *model.Status
	Note     *string
	Owner    *string
	Due      *time.Time // a pointer to the zero time clears the due date
	Ticket   *string
	Evidence *model.Evidence
}

// Update applies a change to the findings of one vulnerability in a project;
// an empty env means every environment. Each change is also written to the
// finding's history. It returns how many findings changed.
func (l *Ledger) Update(vulnID, project string, env model.Env, u Update, now time.Time) (int, error) {
	n := 0
	for _, f := range l.d.Findings {
		if f.VulnID != vulnID || f.Project != project || (env != "" && f.Env != env) {
			continue
		}
		n++
		f.Updated = now
		if u.Status != nil {
			f.Status, f.Auto = *u.Status, false
			if u.Note != nil {
				f.Note = *u.Note
			}
			f.History = append(f.History, model.Disposition{Time: now, Actor: u.Actor, Action: "status", Status: *u.Status, Note: f.Note})
		} else if u.Note != nil {
			f.Note = *u.Note
		}
		if u.Owner != nil || u.Due != nil || u.Ticket != nil {
			d := model.Disposition{Time: now, Actor: u.Actor, Action: "assign"}
			if u.Owner != nil {
				f.Owner, d.Owner = *u.Owner, *u.Owner
			}
			if u.Due != nil {
				f.Due, d.Due = *u.Due, *u.Due
			}
			if u.Ticket != nil {
				f.Ticket, d.Ticket = *u.Ticket, *u.Ticket
			}
			f.History = append(f.History, d)
		}
		if u.Evidence != nil {
			e := *u.Evidence
			e.Time, e.Actor = now, u.Actor
			f.Evidence = append(f.Evidence, e)
			f.History = append(f.History, model.Disposition{Time: now, Actor: u.Actor, Action: "evidence", Note: e.Note, URL: e.URL})
		}
	}
	if n == 0 {
		return 0, fmt.Errorf("no finding for %s in project %q env %q", vulnID, project, env)
	}
	return n, nil
}

// SetStatus is Update for the common case of a status and a note.
func (l *Ledger) SetStatus(vulnID, project string, env model.Env, st model.Status, note string, now time.Time) (int, error) {
	return l.Update(vulnID, project, env, Update{Status: &st, Note: &note}, now)
}

// MarkAlerted records that a finding reached one channel.
func (l *Ledger) MarkAlerted(key, channel string, at time.Time) {
	f := l.d.Findings[key]
	if f == nil {
		return
	}
	if f.Alerted == nil {
		f.Alerted = map[string]time.Time{}
	}
	f.Alerted[channel] = at
	if f.AlertedAt.IsZero() {
		f.AlertedAt = at
	}
}

// Digest returns when a channel last got its periodic digest (zero if never).
func (l *Ledger) Digest(channel string) time.Time { return l.d.Digests[channel] }

func (l *Ledger) SetDigest(channel string, at time.Time) { l.d.Digests[channel] = at }

// SetEPSS records the exploit probability for a vulnerability.
func (l *Ledger) SetEPSS(id string, e model.EPSS) bool {
	v := l.d.Vulns[id]
	if v == nil || (v.EPSS != nil && *v.EPSS == e) {
		return false
	}
	v.EPSS = &e
	return true
}

// SetRating records a CVSS rating found by a lookup. It applies the same
// precedence as a repeat sighting (model.Rating) and lifts the severity to the
// band of the score. It reports whether the record changed.
func (l *Ledger) SetRating(id string, r model.Rating) bool {
	v := l.d.Vulns[id]
	if v == nil || !r.Better(v.Rating()) {
		return false
	}
	v.SetRating(r)
	if s := r.Severity(); s.Rank() > v.Severity.Rank() {
		v.Severity = s
	}
	return true
}

// MarkRated notes that the rating of id was looked up at the time, found or not.
func (l *Ledger) MarkRated(id string, at time.Time) {
	if v := l.d.Vulns[id]; v != nil {
		v.CVSSChecked = at
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

// LastUpdate returns when a project was last refreshed (zero if never).
func (l *Ledger) LastUpdate(project string) time.Time { return l.d.Updated[project] }

func (l *Ledger) SetLastUpdate(project string, at time.Time) { l.d.Updated[project] = at }

// Judged returns what the findings were last judged against, nil if never.
func (l *Ledger) Judged() *model.Judging { return l.d.Judged }

func (l *Ledger) SetJudged(j model.Judging) { l.d.Judged = &j }

func (l *Ledger) Feed(id string) model.FeedState       { return l.d.Feeds[id] }
func (l *Ledger) SetFeed(id string, f model.FeedState) { l.d.Feeds[id] = f }

// migrate brings older state up to SchemaVersion. Each step is idempotent.
func migrate(s *State) {
	if s.SchemaVersion < 1 {
		for _, f := range s.Findings {
			if !f.AlertedAt.IsZero() && f.Alerted == nil {
				f.Alerted = map[string]time.Time{"slack": f.AlertedAt} // before channels, Slack was the only one
			}
		}
	}
	s.SchemaVersion = SchemaVersion
}

// ---- health records ----

// RecordCycle appends a cycle record, keeping the most recent ones.
func (l *Ledger) RecordCycle(c model.CycleRecord) {
	l.d.Cycles = append(l.d.Cycles, c)
	if n := len(l.d.Cycles); n > maxCycles {
		l.d.Cycles = slices.Clone(l.d.Cycles[n-maxCycles:])
	}
}

// SourceOutcome records one attempt to read a feed. A success clears the
// failure streak; a failure extends it.
func (l *Ledger) SourceOutcome(id, typ string, now time.Time, items int, err error) {
	h := l.d.Sources[id]
	h.Type, h.LastAttempt = typ, now
	if err == nil {
		h.LastSuccess, h.Failures, h.LastError, h.Items = now, 0, "", items
	} else {
		h.Failures++
		h.LastError = err.Error()
	}
	l.d.Sources[id] = h
}

// ChannelOutcome records one attempt to deliver through a channel.
func (l *Ledger) ChannelOutcome(name string, now time.Time, err error) {
	h := l.d.Channels[name]
	h.LastAttempt = now
	if err == nil {
		h.LastSuccess, h.Failures, h.LastError = now, 0, ""
	} else {
		h.Failures++
		h.LastError = err.Error()
	}
	l.d.Channels[name] = h
}

func (l *Ledger) SetHeartbeat(h model.Heartbeat) { l.d.Heartbeat = &h }

// Health returns the stored health records.
func (l *Ledger) Health() (cycles []model.CycleRecord, sources map[string]model.SourceHealth, channels map[string]model.ChannelHealth, hb *model.Heartbeat) {
	return slices.Clone(l.d.Cycles), maps.Clone(l.d.Sources), maps.Clone(l.d.Channels), l.d.Heartbeat
}
