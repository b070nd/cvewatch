// Package priority decides what comes first and which deadlines are broken.
// Ordering, the alert floor's severity test and the policy report all live
// here, so the list, Slack, exports and the violations report agree.
//
// It uses only facts the sources provide (KEV membership, severity, EPSS,
// age, where it is open). It does not invent a score.
package priority

import (
	"fmt"
	"strings"
	"time"

	"github.com/b070nd/cvewatch/app/src/model"
)

// Facts is what ordering looks at for one issue.
type Facts struct {
	Severity  model.Severity
	KEV       *model.KEV
	EPSS      *model.EPSS
	Published time.Time
	FirstSeen time.Time
	ProdOpen  bool // an open finding exists in prod
}

// Compare orders two issues: a negative result puts a first. The default
// order is KEV first, then severity, then open in prod, then EPSS (higher
// first), then age (older first, it has been exposed longer).
func Compare(a, b Facts) int {
	if x, y := b2i(a.KEV != nil), b2i(b.KEV != nil); x != y {
		return y - x
	}
	if d := b.Severity.Rank() - a.Severity.Rank(); d != 0 {
		return d
	}
	if x, y := b2i(a.ProdOpen), b2i(b.ProdOpen); x != y {
		return y - x
	}
	if x, y := score(a.EPSS), score(b.EPSS); x != y {
		if x > y {
			return -1
		}
		return 1
	}
	switch ta, tb := a.Published, b.Published; {
	case ta.Before(tb):
		return -1
	case tb.Before(ta):
		return 1
	}
	return 0
}

func score(e *model.EPSS) float64 {
	if e == nil {
		return -1
	}
	return e.Score
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Reasons explains the position in plain words, using only our own data.
func Reasons(f Facts, now time.Time) []string {
	var out []string
	if f.KEV != nil {
		r := "known exploited (CISA KEV)"
		if !f.KEV.DueDate.IsZero() {
			r += ", CISA remediation due " + f.KEV.DueDate.Format("2006-01-02")
		}
		out = append(out, r)
	}
	if f.Severity != model.SevUnknown {
		out = append(out, string(f.Severity)+" severity")
	}
	if f.ProdOpen {
		out = append(out, "open in prod")
	}
	if f.EPSS != nil {
		out = append(out, fmt.Sprintf("EPSS %.0f%% chance of exploitation in 30 days", f.EPSS.Score*100))
	}
	return out
}

// Rule is one policy: which findings it covers and what must hold, and by when.
type Rule struct {
	Name        string
	Env         model.Env // empty means every environment
	KEV         bool
	MinSeverity model.Severity
	OwnerWithin time.Duration // an owner is required this long after detection
	FixWithin   time.Duration // the finding must be closed this long after detection
}

// Subject is one open finding with the facts policy needs.
type Subject struct {
	VulnID   string
	Title    string
	Project  string
	Env      model.Env
	Severity model.Severity
	KEV      bool
	Owner    string
	Due      time.Time // the finding's own due date, if set
	Detected time.Time
}

// Violation says which deadline a finding broke and by how long.
type Violation struct {
	Rule    string // rule name, or "due date" for a finding's own deadline
	Subject Subject
	Reason  string
	Late    time.Duration
}

// Violations checks open findings against the rules and against their own
// due dates. Results are ordered by lateness, worst first.
func Violations(rules []Rule, subjects []Subject, now time.Time) []Violation {
	var out []Violation
	for _, s := range subjects {
		if !s.Due.IsZero() && now.After(s.Due) {
			out = append(out, Violation{Rule: "due date", Subject: s, Late: now.Sub(s.Due),
				Reason: "past its due date " + s.Due.Format("2006-01-02")})
		}
		for _, r := range rules {
			if !r.covers(s) {
				continue
			}
			if r.OwnerWithin > 0 && s.Owner == "" && now.Sub(s.Detected) > r.OwnerWithin {
				out = append(out, Violation{Rule: r.Name, Subject: s, Late: now.Sub(s.Detected) - r.OwnerWithin,
					Reason: "no owner within " + short(r.OwnerWithin)})
			}
			if r.FixWithin > 0 && now.Sub(s.Detected) > r.FixWithin {
				out = append(out, Violation{Rule: r.Name, Subject: s, Late: now.Sub(s.Detected) - r.FixWithin,
					Reason: "still open after " + short(r.FixWithin)})
			}
		}
	}
	// worst first; stable keys keep the report deterministic
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && later(out[j], out[j-1]); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

func later(a, b Violation) bool {
	if a.Late != b.Late {
		return a.Late > b.Late
	}
	return strings.Compare(a.Subject.VulnID+a.Subject.Project+string(a.Subject.Env), b.Subject.VulnID+b.Subject.Project+string(b.Subject.Env)) < 0
}

func (r Rule) covers(s Subject) bool {
	return (r.Env == "" || r.Env == s.Env) && (!r.KEV || s.KEV) && s.Severity.AtLeast(r.MinSeverity)
}

// short renders a duration the way people write it: 24h, 3d, 36h.
func short(d time.Duration) string {
	if d >= 48*time.Hour && d%(24*time.Hour) == 0 {
		return fmt.Sprintf("%dd", int(d/(24*time.Hour)))
	}
	return fmt.Sprintf("%dh", int(d.Hours()))
}
