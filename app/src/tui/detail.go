package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/b070nd/cvewatch/app/src/model"
)

func sevTag(s model.Severity) string { return sevStyles[s.Rank()].Render(sevWord(s)) }

// statusStyle makes closed states recede and a fixed one stand out as good.
func statusStyle(st model.Status) lipgloss.Style {
	switch st {
	case model.StatusFixed:
		return stGood
	case model.StatusIgnored, model.StatusNotAffected:
		return stMuted
	}
	return lipgloss.NewStyle()
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// lines lays the issue out as text and returns the line of the selected
// environment, so the caller can keep it in view. Everything that came from
// a feed, a repository or a person goes through clean first.
func (d *detail) lines(_ time.Time, w int) ([]string, int) {
	switch {
	case d.loading:
		return []string{stMuted.Render("Loading " + oneLine(d.id) + "...")}, 0
	case d.err != nil:
		return []string{stErr.Render("error: ") + oneLine(d.err.Error()), "", stMuted.Render("esc goes back")}, 0
	}
	is := d.is
	var out []string
	add := func(l ...string) { out = append(out, l...) }

	head := []string{stBold.Render(oneLine(is.ID)), sevTag(is.Severity)}
	if is.CVSS > 0 {
		head = append(head, fmt.Sprintf("CVSS %.1f", is.CVSS))
	}
	if is.KEV != nil {
		head = append(head, stFlag.Render("KEV"))
	}
	if is.EPSS != nil {
		head = append(head, fmt.Sprintf("EPSS %.0f%%", is.EPSS.Score*100))
	}
	if is.Age != "" {
		head = append(head, "age "+is.Age)
	}
	if is.ProdOpen {
		head = append(head, stFlag.Render("open in prod"))
	}
	add(strings.Join(head, "  "))
	add(indentWrap("", orDash(oneLine(is.Untrusted.Title)), w)...)
	meta := "published " + day(is.Published) + "  first seen " + day(is.FirstSeen)
	if len(is.Techs) > 0 {
		meta += "  techs " + oneLine(strings.Join(is.Techs, ", "))
	}
	if len(is.Aliases) > 0 {
		meta += "  aliases " + oneLine(strings.Join(is.Aliases, ", "))
	}
	add(stMuted.Render(trunc(meta, w)))
	if len(is.Priority) > 0 {
		add(indentWrap("priority: ", oneLine(strings.Join(is.Priority, "; ")), w)...)
	}
	add("")

	if desc := oneLine(is.Untrusted.Description); desc != "" {
		add(section("Description"))
		add(indentWrap("  ", desc, w)...)
		add("")
	}

	add(section("Environments") + stMuted.Render("  up/down select; f i n o act on the selected row, F I N O on the whole project"))
	selLine := 0
	if len(is.Targets) == 0 {
		add("  (no environment is tracked for this issue)")
	}
	for i, t := range is.Targets {
		if i == d.sel {
			selLine = len(out)
		}
		due := "-"
		if !t.Due.IsZero() {
			due = day(t.Due)
			if t.Overdue {
				due += " OVERDUE"
			}
		}
		core := pad(oneLine(t.Project), 14) + " " + pad(string(t.Env), 8) + " " + pad(strings.ReplaceAll(string(t.Status), "_", " "), 12) + " " + pad(string(t.Applies), 12)
		rest := "owner " + orDash(oneLine(t.Owner)) + "  due " + due
		if t.Ticket != "" {
			rest += "  ticket " + oneLine(t.Ticket)
		}
		if t.Evidence > 0 {
			rest += "  " + plural(t.Evidence, "evidence note", "evidence notes")
		}
		if i == d.sel {
			add(stSel.Render(pad("> "+core+" "+rest, w)))
		} else {
			add("  " + statusStyle(t.Status).Render(core) + " " + trunc(rest, max(w-width(core)-3, 1)))
		}
		if t.Note != "" {
			add(indentWrap("      note: ", oneLine(t.Note), w)...)
		}
	}
	add("")

	add(section("Fix evidence"))
	if len(is.Untrusted.Fixes) == 0 {
		add("  none recorded")
	}
	for _, f := range is.Untrusted.Fixes {
		s := string(f.Kind)
		if f.Detail != "" {
			s += " " + oneLine(f.Detail)
		}
		if f.Official {
			s += " (official)"
		}
		if f.Source != "" {
			s += " via " + oneLine(f.Source)
		}
		if f.URL != "" {
			s += " " + oneLine(f.URL)
		}
		add(indentWrap("  - ", s, w)...)
	}
	if is.Untrusted.KEVAction != "" {
		add(indentWrap("  KEV action: ", oneLine(is.Untrusted.KEVAction), w)...)
	}
	if n := len(is.Untrusted.Articles); n > 0 {
		add("", section(plural(n, "report", "reports")))
		for i, a := range is.Untrusted.Articles {
			if i == 5 {
				add(fmt.Sprintf("  ... and %d more", n-5))
				break
			}
			add(indentWrap("  - ", oneLine(a.Title)+" ("+orDash(oneLine(a.Source))+")", w)...)
		}
	}
	add("")

	add(section("Why it matched"))
	for _, t := range is.Targets {
		if len(t.Reasons) == 0 && len(t.Matched) == 0 {
			continue
		}
		s := oneLine(strings.Join(t.Reasons, "; "))
		if len(t.Matched) > 0 {
			s += " [matched " + oneLine(strings.Join(t.Matched, ", ")) + "]"
		}
		add(indentWrap("  "+oneLine(t.Project)+"/"+string(t.Env)+": ", s, w)...)
	}
	switch {
	case d.exErr != "":
		add("  could not re-check today: " + oneLine(d.exErr))
	case d.ex != nil:
		for _, l := range d.ex.Today {
			add(indentWrap("  today: ", oneLine(l), w)...)
		}
		for _, l := range d.ex.Notes {
			add(indentWrap("  note: ", oneLine(l), w)...)
		}
		if d.ex.Relevant {
			add("  relevant under the current configuration: yes")
		} else {
			add("  relevant under the current configuration: no")
		}
	}
	return out, selLine
}
