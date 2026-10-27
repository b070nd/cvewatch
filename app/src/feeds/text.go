package feeds

import (
	"html"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"cvewatch/src/model"
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
	if it.Severity == "" {
		it.Severity = model.SevUnknown
	}
	return it, true
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

// severityOf prefers the label the feed gives and falls back to the score.
func severityOf(label string, score float64) model.Severity {
	if s := model.ParseSeverity(label); s != model.SevUnknown {
		return s
	}
	return model.SeverityFromCVSS(score)
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
