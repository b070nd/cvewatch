package feeds

import (
	"html"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/b070nd/cvewatch/app/src/model"
)

const maxText = 2000 // runes kept in titles and summaries

var (
	scriptRe = regexp.MustCompile(`(?is)<(?:script|style)\b.*?</(?:script|style)\s*>`)
	// tagRe matches comments and real tags only, so "a < b" stays untouched.
	tagRe = regexp.MustCompile(`(?s)<!--.*?-->|</?[a-zA-Z][^>]*>`)
)

// plain removes markup and entities and collapses whitespace.
func plain(s string) string {
	s = tagRe.ReplaceAllString(scriptRe.ReplaceAllString(s, " "), " ")
	s = html.UnescapeString(s)
	s = tagRe.ReplaceAllString(s, " ") // markup that was entity-encoded
	return strings.Join(strings.Fields(strings.Map(visible, s)), " ")
}

// visible drops control characters (terminal escapes) and invisible format
// characters (bidi overrides that make text read differently from how it is
// stored). Ordinary whitespace is kept for Fields to collapse.
func visible(r rune) rune {
	if unicode.IsSpace(r) {
		return r
	}
	if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
		return -1
	}
	return r
}

func truncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n-1]) + "…"
}

// finish cleans an item and sets its ids: explicit ids plus those found in
// the text, CVEs first, no duplicates. ok is false when the title is empty.
func finish(srcID string, it model.Item, explicit ...string) (_ model.Item, ok bool) {
	title, summary := plain(it.Title), plain(it.Summary)
	if title == "" {
		return it, false
	}
	it.SourceID = srcID
	it.IDs = mergeIDs(explicit, model.ExtractIDs(title+"\n"+summary))
	it.Title = truncate(title, maxText)
	it.Summary = truncate(summary, maxText)
	if !it.Rating().Valid() {
		if r, ok := textRating(title+"\n"+summary, it.IDs); ok {
			rate(&it, r, "")
		}
	}
	if it.Severity == "" {
		it.Severity = model.SevUnknown
	}
	return it, true
}

// rate gives the item a rating and the severity the source printed for it,
// or the band of the score when it printed none.
func rate(it *model.Item, r model.Rating, label string) {
	if r.Valid() {
		it.SetRating(r)
	}
	if s := model.ParseSeverity(label); s != model.SevUnknown {
		it.Severity = s
	} else if r.Valid() {
		it.Severity = r.Severity()
	}
}

var cvssText = regexp.MustCompile(`(?i)\bCVSS(?:\s*(?:v(?:ersion)?|:)?\s*([234](?:\.[01])?)\b)?[^0-9\n]{0,40}?\b(10(?:\.0)?|\d\.\d)\b`)

// textRating reads "CVSS 9.8" or "CVSS v4.0 base score 9.3" out of an article.
// It is the weakest rating (see Rating), and it is skipped for roundups that
// name several CVEs, where the score may belong to any of them.
func textRating(text string, ids []string) (model.Rating, bool) {
	cves := 0
	for _, id := range ids {
		if strings.HasPrefix(id, "CVE-") {
			cves++
		}
	}
	if cves > 1 {
		return model.Rating{}, false
	}
	for _, m := range cvssText.FindAllStringSubmatchIndex(text, -1) {
		if prev := text[m[4]-1]; prev == ':' || prev == '/' || (m[5] < len(text) && text[m[5]] == '/') ||
			(m[5]+1 < len(text) && text[m[5]] == '.' && text[m[5]+1] >= '0' && text[m[5]+1] <= '9') {
			continue // part of a vector or a longer number
		}
		score, err := strconv.ParseFloat(text[m[4]:m[5]], 64)
		if err != nil {
			continue
		}
		r := model.Rating{Score: score, Source: model.ScoreText}
		if m[2] >= 0 {
			r.Version = model.NormVersion(text[m[2]:m[3]])
		}
		if r.Valid() {
			return r, true
		}
	}
	return model.Rating{}, false
}

func mergeIDs(explicit, found []string) []string {
	var cves, others []string
	seen := map[string]bool{}
	for _, id := range slices.Concat(explicit, found) {
		id = strings.ToUpper(strings.TrimSpace(id))
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		if strings.HasPrefix(id, "CVE-") {
			cves = append(cves, id)
		} else {
			others = append(others, id)
		}
	}
	return append(cves, others...)
}

var timeLayouts = []string{
	time.RFC1123Z,
	time.RFC1123,
	time.RFC3339, // also accepts fractional seconds
	"Mon, 2 Jan 2006 15:04:05 -0700",
	"Mon, 2 Jan 2006 15:04:05 MST",
	"Mon, 2 Jan 2006 15:04 -0700",
	"2 Jan 2006 15:04:05 -0700",
	"2 Jan 2006 15:04:05 MST",
	time.RFC822Z,
	time.RFC822,
	time.RFC850,
	time.ANSIC,
	"2006-01-02T15:04:05", // NVD, no zone: UTC
	"2006-01-02 15:04:05 -0700",
	"2006-01-02 15:04:05",
	time.DateOnly,
}

// parseTime tries the layouts feeds commonly use. It returns the zero time
// when none fits.
func parseTime(s string) time.Time {
	s = strings.TrimSpace(s)
	for _, l := range timeLayouts {
		if t, err := time.Parse(l, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// addAffected adds a to list, or merges it into the entry with the same
// ecosystem and name: new ranges are appended and repeats dropped, and the
// first fixed version given is kept.
func addAffected(list []model.Affected, a model.Affected) []model.Affected {
	for i := range list {
		if list[i].Ecosystem != a.Ecosystem || list[i].Name != a.Name {
			continue
		}
		for _, r := range a.Ranges {
			if !slices.Contains(list[i].Ranges, r) {
				list[i].Ranges = append(list[i].Ranges, r)
			}
		}
		if list[i].Fixed == "" {
			list[i].Fixed = a.Fixed
		}
		return list
	}
	return append(list, a)
}
