package ops

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/b070nd/cvewatch/app/src/audit"
	"github.com/b070nd/cvewatch/app/src/ledger"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/query"
	"github.com/b070nd/cvewatch/app/src/report"
	"github.com/b070nd/cvewatch/app/src/store"
)

// StatusChanges are the changes that give every listed issue the status: on
// its open environments, or on the closed ones when reopening. The issues are
// rows of a listing, so each change names exactly what its reader saw.
func StatusChanges(issues []query.Issue, st model.Status, note string) []Change {
	var out []Change
	for _, is := range issues {
		for _, t := range is.Targets {
			if (st == model.StatusOpen) == (t.Status == model.StatusOpen) {
				continue
			}
			out = append(out, Change{ID: is.ID, Project: t.Project, Env: t.Env, Status: st, Note: note})
		}
	}
	return out
}

// BulkResult says what a ResolveAll did.
type BulkResult struct {
	Applied  int      // changes that landed, in the order given
	Findings int      // findings they changed
	Done     []Change // the changes that landed
	// ReportErr is set when everything was saved but a report file could not
	// be rewritten.
	ReportErr error
}

// ResolveAll applies status changes as one operation: each is checked and
// recorded in the audit trail on its own, the reports of the issues are
// rewritten once, and the ledger is saved once. It stops at the first change
// that is refused; what was applied before it is saved, and the error says
// how far it got.
func (s *Session) ResolveAll(cs []Change) (BulkResult, error) {
	res, err := s.resolveAllOnce(cs)
	if errors.Is(err, store.ErrConflict) { // another process saved first (SQLite): reload and redo once
		if rerr := s.reload(); rerr != nil {
			return BulkResult{}, rerr
		}
		return s.resolveAllOnce(cs)
	}
	return res, err
}

func (s *Session) resolveAllOnce(cs []Change) (BulkResult, error) {
	var (
		res     BulkResult
		events  []audit.Event
		changed []string // vulnerability ids, in the order first touched
		refused error
	)
	now := s.Now()
	for _, c := range cs {
		n, id, ev, err := s.resolveInMemory(c)
		if err != nil {
			refused = err
			break
		}
		if err := s.Audit.Append(ev); err != nil { // never change anything without a record: nothing of this run is saved
			for _, done := range events {
				done.Action, done.Note = done.Action+"-failed", "not saved: the audit log could not be written"
				s.Audit.Append(done)
			}
			return BulkResult{}, fmt.Errorf("audit log: %w", err)
		}
		events = append(events, ev)
		res.Applied++
		res.Findings += n
		res.Done = append(res.Done, c)
		if !slices.Contains(changed, id) {
			changed = append(changed, id)
		}
	}
	if res.Applied > 0 {
		for _, id := range changed {
			v := s.Ledger.Vuln(id)
			path, err := report.Write(s.Cfg.AlertsDir, v, s.Ledger.FindingsOf(id), now)
			if err != nil {
				res.ReportErr = err
				continue
			}
			v.ReportPath = path
		}
		if err := s.Commit(); err != nil {
			for _, ev := range events { // the log must not claim what did not land
				ev.Action, ev.Note = ev.Action+"-failed", "not saved: "+err.Error()
				s.Audit.Append(ev)
			}
			return BulkResult{}, err
		}
	}
	if refused != nil {
		if res.Applied > 0 {
			refused = fmt.Errorf("%d of %d changes written, then: %w", res.Applied, len(cs), refused)
		}
		return res, refused
	}
	return res, nil
}

// resolveInMemory checks one status change and makes it in the ledger,
// without recording or saving it. It returns how many findings changed, the
// vulnerability's id and the audit event to record.
func (s *Session) resolveInMemory(c Change) (int, string, audit.Event, error) {
	if err := s.mayWrite(c.Project); err != nil {
		return 0, "", audit.Event{}, err
	}
	if err := c.validate(s.Cfg); err != nil {
		return 0, "", audit.Event{}, err
	}
	v := s.Ledger.Lookup([]string{strings.ToUpper(strings.TrimSpace(c.ID))})
	if v == nil {
		return 0, "", audit.Event{}, fmt.Errorf("unknown vulnerability %q", c.ID)
	}
	now, note := s.Now(), clean(c.Note, 500)
	n, err := s.Ledger.Update(v.ID, c.Project, c.Env, ledger.Update{Status: &c.Status, Note: &note, Actor: s.Actor}, now)
	if err != nil {
		return 0, "", audit.Event{}, err
	}
	return n, v.ID, audit.Event{Time: now, Actor: s.Actor, Action: "status", Vuln: v.ID, Project: c.Project, Env: string(c.Env),
		Status: string(c.Status), Note: note}, nil
}
