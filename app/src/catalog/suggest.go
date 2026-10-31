package catalog

import (
	"slices"
	"strings"

	"github.com/b070nd/cvewatch/app/src/model"
)

// Suggest ranks the technologies a typed term most likely means: an exact
// name or alias first, then a name that starts with the term (or the term
// starts with it), then one that contains it, then near misses by edit
// distance (a swapped or missing letter), then words in common for terms of
// several words ("ubuntu kernel" shares "kernel" with linux-kernel). Nothing
// unrelated is returned, so an empty result means the term is not in the
// catalog.
func (c *Catalog) Suggest(term string, n int) []model.Tech {
	if n <= 0 {
		n = 5
	}
	var out []model.Tech
	hits := c.ranked(term)
	for _, h := range hits[:min(len(hits), n)] {
		out = append(out, h.tech)
	}
	return out
}

// Closest is the one technology a term clearly means: the best Suggest hit
// when nothing else ranks as high, so it is safe to offer as a rename. A term
// that only starts with or sits inside a name ("linux") is too vague for it.
func (c *Catalog) Closest(term string) (model.Tech, bool) {
	hits := c.ranked(term)
	if len(hits) == 0 || hits[0].tier == 1 || hits[0].tier == 2 ||
		len(hits) > 1 && hits[1].tier == hits[0].tier && hits[1].dist == hits[0].dist {
		return model.Tech{}, false
	}
	return hits[0].tech, true
}

type hit struct {
	tech       model.Tech
	tier, dist int
	size       int // length of the matched name, so closer names come first
}

func (c *Catalog) ranked(term string) []hit {
	q := squash(term)
	if q == "" {
		return nil
	}
	words := words(term)
	var hits []hit
	for _, t := range c.techs {
		best := hit{tech: t, tier: 99}
		better := func(tier, dist, size int) {
			if tier < best.tier || tier == best.tier && (dist < best.dist || dist == best.dist && size < best.size) {
				best.tier, best.dist, best.size = tier, dist, size
			}
		}
		for _, s := range append([]string{t.Name, t.Title}, t.Aliases...) {
			k := squash(s)
			if k == "" {
				continue
			}
			tier, dist := rank(q, k)
			// a name inside a longer phrase says little: "ubuntu kernel" is not about ubuntu alone
			if len(words) > 1 && tier > 0 && tier < 3 && len(k) < len(q) && strings.Contains(q, k) {
				tier = 99
			}
			better(tier, dist, len(k))
			if missed, ok := shared(words, s); ok {
				better(4, missed, len(k))
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
	return hits
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

// filler are words too common to say anything about which technology is meant.
var filler = map[string]bool{
	"server": true, "service": true, "services": true, "app": true, "application": true, "enterprise": true,
	"edition": true, "community": true, "version": true, "the": true, "for": true, "and": true,
	"platform": true, "software": true, "system": true, "cloud": true, "open": true, "source": true,
}

// words splits a term into its lowercase words, dropping short ones, numbers
// and fillers: "Ubuntu 22.04 kernel" is ubuntu, kernel.
func words(s string) []string {
	var out []string
	for _, w := range strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r > 127)
	}) {
		if len([]rune(w)) >= 3 && !filler[w] && strings.Trim(w, "0123456789") != "" && !slices.Contains(out, w) {
			out = append(out, w)
		}
	}
	return out
}

// shared says how many of the term's words a name does not have, when it has
// at least one: a word matches exactly or, from five letters on, with one
// edit per four letters ("kernal" for kernel).
func shared(term []string, name string) (missed int, ok bool) {
	have := words(name)
	n := 0
	for _, w := range term {
		if slices.ContainsFunc(have, func(h string) bool {
			return h == w || len(w) >= 5 && EditDistance(w, h) <= len(w)/4
		}) {
			n++
		}
	}
	return len(term) - n, n > 0
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
