package tui

import (
	"regexp"
	"strings"
	"unicode"

	"github.com/charmbracelet/lipgloss"
)

// escapes matches terminal control sequences: CSI, OSC, DCS/SOS/PM/APC and
// two-byte escapes. Text from feeds, repositories and people is untrusted, so
// none of it may reach the terminal with these intact.
var escapes = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?|\x1b[PX^_][^\x1b]*(?:\x1b\\)?|\x1b[ -/]*[0-~]?`)

// clean makes untrusted text safe to draw: escape sequences, control
// characters and invisible format characters (such as bidi overrides) go,
// tabs and line breaks become spaces, invalid UTF-8 becomes U+FFFD.
func clean(s string) string {
	if s == "" {
		return s
	}
	s = strings.ToValidUTF8(s, "�")
	s = escapes.ReplaceAllString(s, "")
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\t' || r == '\n' || r == '\r':
			return ' '
		case unicode.IsControl(r) || unicode.Is(unicode.Cf, r):
			return -1
		}
		return r
	}, s)
}

// oneLine cleans s and collapses whitespace.
func oneLine(s string) string { return strings.Join(strings.Fields(clean(s)), " ") }

func rw(r rune) int {
	if r >= 0x20 && r < 0x7f {
		return 1
	}
	return lipgloss.Width(string(r))
}

// width is the number of terminal cells s takes.
func width(s string) int { return lipgloss.Width(s) }

// trunc cuts plain text to w cells, ending in an ellipsis when it cut.
func trunc(s string, w int) string {
	if w <= 0 {
		return ""
	}
	if width(s) <= w {
		return s
	}
	var b strings.Builder
	n := 0
	for _, r := range s {
		c := rw(r)
		if n+c > w-1 {
			break
		}
		b.WriteRune(r)
		n += c
	}
	return b.String() + "…"
}

// pad cuts or pads plain text to exactly w cells.
func pad(s string, w int) string {
	if w <= 0 {
		return ""
	}
	s = trunc(s, w)
	if n := width(s); n < w {
		s += strings.Repeat(" ", w-n)
	}
	return s
}

// wrap breaks plain text into lines of at most w cells, on spaces where it can.
func wrap(s string, w int) []string {
	if w < 4 {
		w = 4
	}
	var lines []string
	cur := ""
	flush := func() {
		if cur != "" {
			lines = append(lines, cur)
			cur = ""
		}
	}
	for _, word := range strings.Fields(s) {
		for width(word) > w { // a word longer than a line is split
			flush()
			n, cut := 0, 0
			for i, r := range word {
				c := rw(r)
				if n+c > w {
					break
				}
				n += c
				cut = i + len(string(r))
			}
			lines = append(lines, word[:cut])
			word = word[cut:]
		}
		switch {
		case cur == "":
			cur = word
		case width(cur)+1+width(word) <= w:
			cur += " " + word
		default:
			flush()
			cur = word
		}
	}
	flush()
	return lines
}

// indentWrap wraps text under a prefix; continuation lines are indented alike.
func indentWrap(prefix, s string, w int) []string {
	ind := strings.Repeat(" ", width(prefix))
	var out []string
	for i, l := range wrap(s, w-width(prefix)) {
		if i == 0 {
			out = append(out, prefix+l)
		} else {
			out = append(out, ind+l)
		}
	}
	if len(out) == 0 {
		out = append(out, strings.TrimRight(prefix, " "))
	}
	return out
}

// clip keeps the first n lines.
func clip(lines []string, n int) []string {
	if n < 0 {
		n = 0
	}
	if len(lines) > n {
		return lines[:n]
	}
	return lines
}

func clamp(v, lo, hi int) int {
	if hi < lo {
		hi = lo
	}
	return max(lo, min(v, hi))
}
