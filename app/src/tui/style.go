package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/query"
	"github.com/b070nd/cvewatch/app/src/status"
)

// Colours are the terminal's own ANSI palette, so they follow its light or
// dark theme without asking the terminal anything (a background query hangs
// on terminals that do not answer it). They mirror
// the dashboard's palette (critical red, high orange, medium yellow, low blue,
// unrated grey). Colour is never the only signal: severities and levels are
// always printed as words, and the cursor row carries a "> " marker. With
// NO_COLOR set lipgloss drops every escape sequence.
func ac(light, dark string) lipgloss.Color {
	return lipgloss.Color(basic[light])
}

// basic maps the old light-theme codes to the terminal's palette entries.
var basic = map[string]string{"160": "1", "28": "2", "166": "208", "136": "3", "26": "4", "59": "8", "242": "8"}

var (
	stBold  = lipgloss.NewStyle().Bold(true)
	stMuted = lipgloss.NewStyle().Foreground(ac("242", "247"))
	stSel   = lipgloss.NewStyle().Bold(true).Reverse(true)
	stTabOn = lipgloss.NewStyle().Bold(true).Reverse(true)
	stTab   = lipgloss.NewStyle().Foreground(ac("242", "247"))
	stErr   = lipgloss.NewStyle().Bold(true).Foreground(ac("160", "217"))
	stGood  = lipgloss.NewStyle().Bold(true).Foreground(ac("28", "120"))
	stAdd   = lipgloss.NewStyle().Foreground(ac("28", "120"))
	stDel   = lipgloss.NewStyle().Foreground(ac("160", "217"))
	stHead  = lipgloss.NewStyle().Bold(true).Underline(true)
	stFlag  = lipgloss.NewStyle().Bold(true).Foreground(ac("160", "217"))

	sevStyles = map[int]lipgloss.Style{
		4: lipgloss.NewStyle().Bold(true).Foreground(ac("160", "217")), // critical
		3: lipgloss.NewStyle().Bold(true).Foreground(ac("166", "215")), // high
		2: lipgloss.NewStyle().Foreground(ac("136", "227")),            // medium
		1: lipgloss.NewStyle().Foreground(ac("26", "117")),             // low
		0: lipgloss.NewStyle().Foreground(ac("59", "252")),             // unrated
	}
	lvlStyles = map[status.Level]lipgloss.Style{
		status.Green:  stGood,
		status.Yellow: sevStyles[2].Bold(true),
		status.Red:    stErr,
	}
)

// severities lists the severities from most to least urgent; unrated is last.
var severities = []model.Severity{model.SevCritical, model.SevHigh, model.SevMedium, model.SevLow, model.SevUnknown}

// sevWord is the severity as a word, the dashboard's wording.
func sevWord(s model.Severity) string {
	if s.Rank() == 0 {
		return "unrated"
	}
	return string(s)
}

func sevText(s model.Severity, w int) string {
	return sevStyles[s.Rank()].Render(pad(sevWord(s), w))
}

// levelText is a health level as glyph and word (never colour alone).
func levelText(l status.Level) string {
	var t string
	switch l {
	case status.Green:
		t = "● GREEN"
	case status.Red:
		t = "✖ RED"
	default:
		t = "▲ YELLOW"
		l = status.Yellow
	}
	return lvlStyles[l].Render(t)
}

// when renders a time as UTC plus how long ago, or "never".
func when(t, now time.Time) string {
	if t.IsZero() {
		return "never"
	}
	s := t.UTC().Format("2006-01-02 15:04") + " UTC"
	if a := query.Age(t, now); a != "" {
		s += " (" + a + " ago)"
	}
	return s
}

func day(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format("2006-01-02")
}

// section is a heading line.
func section(s string) string { return stHead.Render(s) }

func spaces(n int) string {
	if n <= 0 {
		return ""
	}
	return strings.Repeat(" ", n)
}

// bar draws n out of max as blocks at most w cells long, at least one if n > 0.
func bar(n, max, w int) string {
	if n <= 0 || max <= 0 || w <= 0 {
		return ""
	}
	k := n * w / max
	if k < 1 {
		k = 1
	}
	return strings.Repeat("█", k)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}
