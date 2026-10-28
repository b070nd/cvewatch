package version

import (
	"errors"
	"fmt"
	"strings"

	"github.com/b070nd/cvewatch/app/src/model"
)

// cond is one bound of a range group: op is ">=", ">", "<=" or "<".
type cond struct{ op, v string }

func compareWith(sc *scheme, a, b string) (int, bool) {
	ka, okA := sc.parse(a)
	kb, okB := sc.parse(b)
	if !okA || !okB {
		return 0, false
	}
	return sc.cmp(ka, kb), true
}

func parseRange(sc *scheme, expr string) ([]model.Range, error) {
	if strings.TrimSpace(expr) == "" {
		return nil, nil
	}
	var out []model.Range
	for _, group := range strings.Split(expr, "||") {
		r, err := parseGroup(sc, group)
		if err != nil {
			return nil, fmt.Errorf("version: invalid range %q: %w", clip(expr), err)
		}
		out = append(out, r)
	}
	return out, nil
}

func parseGroup(sc *scheme, g string) (model.Range, error) {
	var r model.Range
	fields := strings.Fields(strings.ReplaceAll(g, ",", " "))
	if len(fields) == 0 {
		return r, errors.New("empty condition")
	}
	for i := 0; i < len(fields); i++ {
		f, op := fields[i], ""
		for _, o := range sc.ops {
			if strings.HasPrefix(f, o) {
				op, f = o, f[len(o):]
				break
			}
		}
		if f == "" {
			if i++; i == len(fields) {
				return r, errors.New("operator without a version")
			}
			f = fields[i]
		}
		var conds []cond
		if sc.expand != nil {
			c, handled, err := sc.expand(op, f)
			if err != nil {
				return r, err
			}
			if handled {
				conds = c
			}
		}
		if conds == nil {
			if _, ok := sc.parse(f); !ok {
				return r, errors.New("unparsable version")
			}
			switch op {
			case ">=", ">", "<=", "<":
				conds = []cond{{op, f}}
			default:
				conds = []cond{{">=", f}, {"<=", f}}
			}
		}
		for _, c := range conds {
			switch c.op {
			case ">=", ">":
				setMin(sc, &r, c.v, c.op == ">")
			default:
				setMax(sc, &r, c.v, c.op == "<")
			}
		}
	}
	return r, nil
}

// setMin keeps the tighter (higher, or exclusive when equal) lower bound.
func setMin(sc *scheme, r *model.Range, v string, excl bool) {
	if c, _ := compareWith(sc, v, r.Min); r.Min == "" || c > 0 || c == 0 && excl {
		r.Min, r.MinExcl = v, excl
	}
}

// setMax keeps the tighter (lower, or exclusive when equal) upper bound.
func setMax(sc *scheme, r *model.Range, v string, excl bool) {
	if c, _ := compareWith(sc, v, r.Max); r.Max == "" || c < 0 || c == 0 && excl {
		r.Max, r.MaxExcl = v, excl
	}
}

func clip(s string) string {
	if r := []rune(s); len(r) > 80 {
		return string(r[:80])
	}
	return s
}

// bound is one end of a span; unset means unbounded.
type bound struct {
	v         any
	set, excl bool
}

// span is a Range with its bounds parsed.
type span struct{ lo, hi bound }

func (sc *scheme) toSpan(r model.Range) (s span, ok bool) {
	if r.Min != "" {
		v, ok := sc.parse(r.Min)
		if !ok {
			return s, false
		}
		s.lo = bound{v, true, r.MinExcl}
	}
	if r.Max != "" {
		v, ok := sc.parse(r.Max)
		if !ok {
			return s, false
		}
		s.hi = bound{v, true, r.MaxExcl}
	}
	return s, true
}

func (sc *scheme) empty(s span) bool {
	if !s.lo.set || !s.hi.set {
		return false
	}
	c := sc.cmp(s.lo.v, s.hi.v)
	return c > 0 || c == 0 && (s.lo.excl || s.hi.excl)
}

func (sc *scheme) contains(s span, v any) bool {
	if s.lo.set {
		if c := sc.cmp(v, s.lo.v); c < 0 || c == 0 && s.lo.excl {
			return false
		}
	}
	if s.hi.set {
		if c := sc.cmp(v, s.hi.v); c > 0 || c == 0 && s.hi.excl {
			return false
		}
	}
	return true
}

// meets reports whether the span shares a version with the half-open [lo, hi).
func (sc *scheme) meets(s span, lo, hi any) bool {
	if s.hi.set {
		if c := sc.cmp(s.hi.v, lo); c < 0 || c == 0 && s.hi.excl {
			return false
		}
	}
	return !s.lo.set || sc.cmp(s.lo.v, hi) < 0
}

// covers reports whether the union of spans contains all of [lo, hi). It
// sweeps upward from lo, always jumping to the span that reaches furthest.
func (sc *scheme) covers(spans []span, lo, hi any) bool {
	cur, done := lo, false // done: cur itself is already covered
	for sc.cmp(cur, hi) < 0 {
		next, nextDone, found := cur, done, false
		for _, s := range spans {
			if s.lo.set {
				if c := sc.cmp(s.lo.v, cur); c > 0 || c == 0 && s.lo.excl && !done {
					continue
				}
			}
			if !s.hi.set {
				return true
			}
			end, endDone := s.hi.v, !s.hi.excl
			if c := sc.cmp(end, next); c > 0 || c == 0 && endDone && !nextDone {
				next, nextDone, found = end, endDone, true
			}
		}
		if !found {
			return false
		}
		cur, done = next, nextDone
	}
	return true
}

func evaluate(sc *scheme, installed string, ranges []model.Range) model.Applicability {
	v, ok := sc.parse(installed)
	if !ok || len(ranges) == 0 {
		return model.AppUnknown
	}
	var spans []span
	unreadable := false
	for _, r := range ranges {
		s, ok := sc.toSpan(r)
		switch {
		case !ok:
			unreadable = true
		case !sc.empty(s):
			spans = append(spans, s)
		}
	}
	miss := model.AppNotAffected
	if unreadable {
		miss = model.AppUnknown
	}

	hi, isSeries := sc.series(v)
	if !isSeries {
		for _, s := range spans {
			if sc.contains(s, v) {
				return model.AppAffected
			}
		}
		return miss
	}
	if sc.covers(spans, v, hi) {
		return model.AppAffected
	}
	for _, s := range spans {
		if sc.meets(s, v, hi) {
			return model.AppUnknown
		}
	}
	return miss
}
