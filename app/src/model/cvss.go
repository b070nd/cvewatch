package model

import (
	"regexp"
	"strings"
)

// CVSS versions a score can come from.
const (
	CVSS20 = "2.0"
	CVSS30 = "3.0"
	CVSS31 = "3.1"
	CVSS40 = "4.0"
)

// Who scored. The label says which metric of a record a rating was read from.
const (
	ScoreNVD          = "nvd"           // NVD's own analysis (type Primary)
	ScoreNVDSecondary = "nvd-secondary" // a CNA's score listed in an NVD record
	ScoreCNA          = "cna"           // the CVE numbering authority that issued the CVE, in a CVE record
	ScoreADP          = "adp"           // an authorized data publisher (CISA-ADP and others) in a CVE record
	ScoreGHSA         = "ghsa"          // GitHub's advisory database
	ScoreCSAF         = "csaf"          // a vendor's own CSAF advisory
	ScoreText         = "text"          // a score quoted in the text of an article
)

// Rating is one CVSS base score with where it came from.
//
// Precedence between ratings of the same issue (Rank, Better, BestRating):
//
//  1. The party that issued or analysed the record comes first: NVD's primary
//     metric, the CNA, GitHub, the vendor's CSAF. Secondary metrics (a CNA
//     score inside an NVD record, ADP containers) come next, a score quoted
//     in an article last. A newer version from a lower group never replaces
//     a score from a higher group.
//  2. Within a group, the newer version wins: 4.0, 3.1, 3.0, 2.0, unknown.
//  3. On equal rank the rating seen first stays, so a score never flips
//     between sightings.
type Rating struct {
	Score   float64
	Version string // CVSS20 .. CVSS40; empty when the source did not say
	Vector  string // the vector string, validated; empty when not given
	Source  string // one of the Score* labels; empty in data from before ratings had a source
}

// Valid reports whether r holds a usable base score.
func (r Rating) Valid() bool { return r.Score > 0 && r.Score <= 10 }

func (r Rating) tier() int {
	switch r.Source {
	case ScoreNVD, ScoreCNA, ScoreGHSA, ScoreCSAF:
		return 2
	case ScoreText:
		return 0
	}
	return 1
}

func versionRank(v string) int {
	switch v {
	case CVSS40:
		return 4
	case CVSS31:
		return 3
	case CVSS30:
		return 2
	case CVSS20:
		return 1
	}
	return 0
}

// Rank orders ratings; an unusable one ranks below every usable one.
func (r Rating) Rank() int {
	if !r.Valid() {
		return -1
	}
	return r.tier()*10 + versionRank(r.Version)
}

// Better reports whether r should replace o: strictly higher rank only.
func (r Rating) Better(o Rating) bool { return r.Rank() > o.Rank() }

// Severity is the band of the score on the scale of its version.
func (r Rating) Severity() Severity { return SeverityOfScore(r.Version, r.Score) }

// BestRating returns the highest ranked rating; on equal rank the higher
// score, then the earlier one. It is the zero Rating when none is usable.
func BestRating(rs ...Rating) Rating {
	var best Rating
	for _, r := range rs {
		if !r.Valid() {
			continue
		}
		if !best.Valid() || r.Rank() > best.Rank() || (r.Rank() == best.Rank() && r.Score > best.Score) {
			best = r
		}
	}
	return best
}

// SeverityOfScore maps a base score to a band. CVSS 2.0 has no critical band
// (0-3.9 low, 4-6.9 medium, 7-10 high); 3.x and 4.0 share their bands.
func SeverityOfScore(version string, score float64) Severity {
	s := SeverityFromCVSS(score)
	if version == CVSS20 && s == SevCritical {
		return SevHigh
	}
	return s
}

// NormVersion returns the CVSS version for what a source wrote ("3.1", "3",
// "CVSS:3.1/AV:N/...", "v4.0"), or "" when it is not a known version.
func NormVersion(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "cvss:")
	s = strings.TrimPrefix(s, "version")
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	switch s {
	case "2", "2.0":
		return CVSS20
	case "3", "3.0":
		return CVSS30
	case "3.1":
		return CVSS31
	case "4", "4.0":
		return CVSS40
	}
	return ""
}

var vectorPattern = regexp.MustCompile(`^(?:CVSS:[234]\.[01]/)?[A-Za-z]{1,10}:[A-Za-z0-9]{1,10}(?:/[A-Za-z]{1,10}:[A-Za-z0-9]{1,10})*$`)

// CleanVector returns v when it looks like a CVSS vector string and "" when
// not, so a vector from a feed can be shown and exported as it is.
func CleanVector(v string) string {
	v = strings.Trim(strings.TrimSpace(v), "()")
	if len(v) > 300 || !vectorPattern.MatchString(v) {
		return ""
	}
	return v
}

// VectorVersion reads the version out of a "CVSS:x.y/..." prefix; a vector
// without one is the 2.0 form when it starts with AV:, else unknown.
func VectorVersion(v string) string {
	switch {
	case strings.HasPrefix(v, "CVSS:"):
		return NormVersion(v)
	case strings.HasPrefix(v, "AV:"):
		return CVSS20
	}
	return ""
}

// Rating is the score the item carries.
func (i Item) Rating() Rating {
	return Rating{Score: i.CVSS, Version: i.CVSSVersion, Vector: i.CVSSVector, Source: i.CVSSSource}
}

// SetRating stores r as the score of the item.
func (i *Item) SetRating(r Rating) {
	i.CVSS, i.CVSSVersion, i.CVSSVector, i.CVSSSource = r.Score, r.Version, r.Vector, r.Source
}

// Rating is the score the record carries.
func (v Vulnerability) Rating() Rating {
	return Rating{Score: v.CVSS, Version: v.CVSSVersion, Vector: v.CVSSVector, Source: v.CVSSSource}
}

// SetRating stores r as the score of the record.
func (v *Vulnerability) SetRating(r Rating) {
	v.CVSS, v.CVSSVersion, v.CVSSVector, v.CVSSSource = r.Score, r.Version, r.Vector, r.Source
}

// Unrated reports whether the record has no score that came from an issuing
// or analysing party; a score quoted from an article counts as unrated.
func (v Vulnerability) Unrated() bool {
	r := v.Rating()
	return !r.Valid() || r.Source == ScoreText
}
