package catalog

import (
	"slices"
	"strings"

	"github.com/b070nd/cvewatch/app/src/model"
)

// Suggest ranks the technologies a typed term most likely means: an exact
// name or alias first, then a name that starts with the term (or the term
// starts with it), then one that contains it, then near misses by edit
// distance (a swapped or missing letter). Nothing unrelated is returned, so
// an empty result means the term is not in the catalog.
func (c *Catalog) Suggest(term string, n int) []model.Tech {
	if n <= 0 {
		n = 5
	}
	q := squash(term)
	if q == "" {
		return nil
	}
	type hit struct {
		tech       model.Tech
		tier, dist int
		size       int // length of the matched name, so closer names come first
	}
	var hits []hit
	for _, t := range c.techs {
		best := hit{tech: t, tier: 99}
		for _, k := range keys(t) {
			tier, dist := rank(q, k)
			if tier < best.tier || tier == best.tier && (dist < best.dist || dist == best.dist && len(k) < best.size) {
				best.tier, best.dist, best.size = tier, dist, len(k)
			}
		}
		if best.tier < 99 {
			hits = append(hits, best)
		}
	}
	slices.SortStableFunc(hits, func(a, b hit) int {
		switch {
		case a.tier != b.tier:
			return a.tier - b.tier
		case a.dist != b.dist:
			return a.dist - b.dist
		}
		return a.size - b.size
	})
	var out []model.Tech
	for _, h := range hits[:min(len(hits), n)] {
		out = append(out, h.tech)
	}
	return out
}

// keys are the squashed spellings a technology answers to.
func keys(t model.Tech) []string {
	var out []string
	for _, s := range append([]string{t.Name, t.Title}, t.Aliases...) {
		if k := squash(s); k != "" && !slices.Contains(out, k) {
			out = append(out, k)
		}
	}
	return out
}

// rank says how well a squashed candidate k fits the squashed term q: tier 0
// is exact, 1 a prefix, 2 a containment, 3 a near miss (dist is the number of
// edits); 99 is no fit.
func rank(q, k string) (tier, dist int) {
	switch {
	case q == k:
		return 0, 0
	case len(q) >= 3 && len(k) >= 3 && (strings.HasPrefix(k, q) || strings.HasPrefix(q, k)):
		return 1, 0
	case len(q) >= 3 && strings.Contains(k, q), len(k) >= 4 && strings.Contains(q, k):
		return 2, 0
	}
	if limit := len(q) / 4; limit > 0 {
		if d := EditDistance(q, k); d <= limit {
			return 3, d
		}
	}
	return 99, 0
}

// squash lowercases and drops everything but letters and digits, so
// "Node.js", "node-js" and "nodejs" are one spelling.
func squash(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'A' && r <= 'Z':
			return r + 'a' - 'A'
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r > 127:
			return r
		}
		return -1
	}, s)
}

// EditDistance counts inserts, deletes, substitutions and swaps of
// neighbours between two strings.
func EditDistance(a, b string) int {
	x, y := []rune(a), []rune(b)
	d := make([][]int, len(x)+1)
	for i := range d {
		d[i] = make([]int, len(y)+1)
		d[i][0] = i
	}
	for j := range d[0] {
		d[0][j] = j
	}
	for i := 1; i <= len(x); i++ {
		for j := 1; j <= len(y); j++ {
			cost := 1
			if x[i-1] == y[j-1] {
				cost = 0
			}
			d[i][j] = min(d[i-1][j]+1, d[i][j-1]+1, d[i-1][j-1]+cost)
			if i > 1 && j > 1 && x[i-1] == y[j-2] && x[i-2] == y[j-1] {
				d[i][j] = min(d[i][j], d[i-2][j-2]+1)
			}
		}
	}
	return d[len(x)][len(y)]
}
