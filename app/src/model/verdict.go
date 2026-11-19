package model

import (
	"errors"
	"fmt"
	"time"
)

// A finding's verdict is what it says right now: open and to act on, open
// but outside the affected range, given up on by cvewatch, or closed by a
// person or by cvewatch. It is derived from the finding's fields, and the
// fields change only through the transitions below, which keep them in step.

// Verdict is the state of a finding as one value.
type Verdict string

const (
	VerdictActionable Verdict = "actionable"  // open, and what is installed may be affected
	VerdictUnaffected Verdict = "unaffected"  // open, but what is installed is outside the affected range
	VerdictRetired    Verdict = "retired"     // open, and cvewatch gave up on the match (see Retired)
	VerdictAutoClosed Verdict = "auto_closed" // closed by cvewatch (see AutoReason)
	VerdictClosed     Verdict = "closed"      // closed by a person
)

// AutoReason is why cvewatch closed a finding on its own.
type AutoReason string

const (
	AutoSince      AutoReason = "since"       // published before the project's since date
	AutoEnvRemoved AutoReason = "env_removed" // its environment is no longer declared
)

// EnvRemovedNote is the note of a finding closed because its environment is gone.
const EnvRemovedNote = "environment removed from project"

// Verdict derives the finding's state from its fields.
func (f Finding) Verdict() Verdict {
	switch {
	case f.Status != StatusOpen && f.Auto:
		return VerdictAutoClosed
	case f.Status != StatusOpen:
		return VerdictClosed
	case f.Retired != "":
		return VerdictRetired
	case f.Applies == AppNotAffected:
		return VerdictUnaffected
	}
	return VerdictActionable
}

// Actionable reports whether the finding is open and what is installed may be
// affected: what lists, counts, alerts and policy work on.
func (f Finding) Actionable() bool { return f.Verdict() == VerdictActionable }

// ClosedBy is why cvewatch closed the finding; empty when it did not.
func (f Finding) ClosedBy() AutoReason {
	if !f.Auto || f.Status == StatusOpen {
		return ""
	}
	if f.AutoReason != "" {
		return f.AutoReason
	}
	return legacyAutoReason(f) // written before the reason was stored
}

func legacyAutoReason(f Finding) AutoReason {
	switch {
	case f.Status == StatusNotAffected:
		return AutoSince
	case f.Status == StatusIgnored && f.Note == EnvRemovedNote:
		return AutoEnvRemoved
	}
	return ""
}

// NeedsReason reports whether a person setting this status must say why: a
// not-affected statement is an assertion about the deployment.
func (s Status) NeedsReason() bool { return s == StatusNotAffected }

// NewFinding is a finding that a match made: open, with what matched.
func NewFinding(vulnID, project string, env Env, installed []Installed, applies Applicability, reasons []string, now time.Time) Finding {
	return Finding{VulnID: vulnID, Project: project, Env: env, Status: StatusOpen, Matched: labels(installed),
		Installed: installed, Applies: applies, Reasons: reasons, Updated: now}
}

// Refresh records a new verdict on the range for the same installed entries,
// or only their newer match basis when the verdict stays.
func (f *Finding) Refresh(installed []Installed, applies Applicability, reasons []string, now time.Time) {
	f.Installed = installed
	if applies != f.Applies {
		f.Applies, f.Reasons, f.Updated = applies, reasons, now
	}
}

// Reinventory records what the finding's target has installed now. A match
// that holds again ends a retirement.
func (f *Finding) Reinventory(installed []Installed, applies Applicability, reasons []string, note string, now time.Time) {
	f.set(installed, applies, reasons, "", note, now)
}

// Retire gives up on the match: nothing of it is installed, or the advisory
// no longer matches it. The finding stays open and counts as not affected.
func (f *Finding) Retire(why Retirement, reasons []string, note string, now time.Time) {
	f.set(nil, AppNotAffected, reasons, why, note, now)
}

func (f *Finding) set(installed []Installed, applies Applicability, reasons []string, retired Retirement, note string, now time.Time) {
	f.Installed, f.Matched, f.Applies, f.Reasons, f.Retired, f.Updated = installed, labels(installed), applies, reasons, retired, now
	f.History = append(f.History, Disposition{Time: now, Actor: "cvewatch", Action: "inventory", Note: note})
}

// AutoClose closes an open finding on cvewatch's own account. A note a
// person wrote moves to the history.
func (f *Finding) AutoClose(st Status, why AutoReason, note string, now time.Time) {
	prior := f.Note
	f.Status, f.Auto, f.AutoReason, f.Note, f.Updated = st, true, why, note, now
	f.history(st, note, prior, now)
}

// AutoReopen opens a finding cvewatch closed, once the reason is gone.
func (f *Finding) AutoReopen(note string, now time.Time) {
	f.Status, f.Auto, f.AutoReason, f.Note, f.Updated = StatusOpen, false, "", "", now
	f.history(StatusOpen, note, "", now)
}

func (f *Finding) history(st Status, note, prior string, now time.Time) {
	if prior != "" {
		note += " (previous note: " + prior + ")"
	}
	f.History = append(f.History, Disposition{Time: now, Actor: "cvewatch", Action: "status", Status: st, Note: note})
}

// Resolve is a person's change of status: it is no longer cvewatch's own.
// A nil note keeps the one there is.
func (f *Finding) Resolve(actor string, st Status, note *string, now time.Time) {
	f.Status, f.Auto, f.AutoReason, f.Updated = st, false, "", now
	if note != nil {
		f.Note = *note
	}
	f.History = append(f.History, Disposition{Time: now, Actor: actor, Action: "status", Status: st, Note: f.Note})
}

// Pin puts the finding at the top of the lists, or takes it off (on false).
// Pinning a pinned finding keeps when it was first pinned.
func (f *Finding) Pin(actor string, on bool, now time.Time) {
	switch {
	case on && f.Pinned.IsZero():
		f.Pinned, f.PinnedBy = now, actor
	case !on:
		f.Pinned, f.PinnedBy = time.Time{}, ""
	default:
		return
	}
	action := "pin"
	if !on {
		action = "unpin"
	}
	f.History = append(f.History, Disposition{Time: now, Actor: actor, Action: action})
}

func labels(in []Installed) []string {
	out := make([]string, len(in))
	for i, x := range in {
		out[i] = x.Label()
	}
	return out
}

// ErrIllegalFinding is wrapped by Check for a finding whose fields disagree.
var ErrIllegalFinding = errors.New("illegal finding")

// Check reports the first way the finding's fields disagree with each other,
// so a state that no transition makes is refused before it is stored.
func (f Finding) Check() error {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w %s: %s", ErrIllegalFinding, f.Key(), fmt.Sprintf(format, a...))
	}
	switch f.Status {
	case StatusOpen, StatusFixed, StatusIgnored, StatusNotAffected:
	default:
		return bad("unknown status %q", f.Status)
	}
	switch f.Applies {
	case "", AppAffected, AppUnknown, AppNotAffected:
	default:
		return bad("unknown applicability %q", f.Applies)
	}
	switch f.Retired {
	case "":
	case RetiredUninstalled, RetiredUnmatched:
		if len(f.Installed) > 0 || f.Applies != AppNotAffected {
			return bad("retired (%s) but still has installed entries or is not marked not affected", f.Retired)
		}
	default:
		return bad("unknown retirement %q", f.Retired)
	}
	switch {
	case f.Auto && f.Status == StatusOpen:
		return bad("open but marked as closed by cvewatch")
	case f.AutoReason != "" && !f.Auto:
		return bad("has a reason for an automatic close (%s) but was not closed by cvewatch", f.AutoReason)
	}
	switch f.AutoReason {
	case "", AutoSince, AutoEnvRemoved:
	default:
		return bad("unknown reason for an automatic close %q", f.AutoReason)
	}
	return nil
}
