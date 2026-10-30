package tui

import (
	"strings"

	"github.com/b070nd/cvewatch/app/src/confdoc"
	"github.com/b070nd/cvewatch/app/src/config"
)

// windowLabels name the horizon windows the way Google's time filter does.
var windowLabels = map[string]string{
	config.WindowUnlimited: "Any time",
	config.WindowHour:      "Past hour",
	config.WindowDay:       "Past 24 hours",
	config.WindowWeek:      "Past week",
	config.WindowMonth:     "Past month",
	config.WindowYear:      "Past year",
	config.WindowCustom:    "Custom range",
}

const (
	horizonWindow = "horizon.window"
	horizonNote   = "applies from the next fetch or cycle"
)

func isHorizon(path string) bool { return strings.HasPrefix(path, "horizon.") }

// enumLabel is how a value of an enum setting is shown; most show as they are.
func enumLabel(path, v string) string {
	if l, ok := windowLabels[v]; ok && path == horizonWindow {
		return l
	}
	return v
}

// enumNote adds the value itself to the note of a choice that is shown under another name.
func enumNote(path, v, note string) string {
	if path != horizonWindow {
		return note
	}
	if note == "" {
		return v
	}
	return v + ", " + note
}

// enumHint is what the choice of a setting adds to the line under the list.
func enumHint(path string) string {
	if isHorizon(path) {
		return "; " + horizonNote
	}
	return ""
}

// shownValue is the value of a row as the table shows it.
func shownValue(r setRow) string {
	switch {
	case r.f.Path == horizonWindow && r.value != "-":
		return enumLabel(r.f.Path, r.value)
	case r.inactive && r.value == "-":
		return "- (custom range only)"
	case r.inactive:
		return r.value + " (custom range only)"
	}
	return r.value
}

// horizonHint says what the dates of a custom horizon may look like.
func horizonHint(path string) string {
	switch path {
	case "horizon.from":
		return "a day YYYY-MM-DD or a time like 2026-03-01T12:00:00Z; empty for no start; " + horizonNote
	case "horizon.to":
		return "a day YYYY-MM-DD (that whole day) or a time like 2026-03-01T12:00:00Z; empty for now; " + horizonNote
	}
	return ""
}

// horizonFacts are the short facts under the help of a horizon setting.
func horizonFacts(r setRow) []string {
	if !isHorizon(r.f.Path) {
		return nil
	}
	out := []string{horizonNote}
	if r.inactive {
		out = append(out, "used only when the window is a custom range")
	}
	return out
}

// horizonIssue gives the warning that the window reaches further back than the
// lookback, which the loader words without a field, the window as its field.
func horizonIssue(is confdoc.Issue) confdoc.Issue {
	if is.Field == "" && is.Doc == "" && strings.HasPrefix(is.Message, "horizon reaches back") {
		is.Doc, is.Field = confdoc.IDSettings, horizonWindow
	}
	return is
}

// horizonRow marks the dates of a horizon whose window is not custom as unused.
func (m *setModel) horizonRow(r *setRow) {
	if r.f.Path != "horizon.from" && r.f.Path != "horizon.to" {
		return
	}
	if v, ok := m.get(confdoc.KindSettings, []string{"horizon", "window"}); !ok || v.value != config.WindowCustom {
		r.inactive, r.dflt = true, true
	}
}

// helpRoom is how many lines of help the detail of a row has: a horizon
// setting with a problem gives one to the problem, which is a long sentence.
func helpRoom(r setRow) int {
	if isHorizon(r.f.Path) && r.issue != nil {
		return 1
	}
	return 2
}

// rowProblemLines are the lines that say the problem of a row, cut to the detail.
func rowProblemLines(r setRow, w int) []string {
	if isHorizon(r.f.Path) {
		return clip(indentWrap("", issueLine(r.issue), w), 2)
	}
	return []string{trunc(issueLine(r.issue), w)}
}
