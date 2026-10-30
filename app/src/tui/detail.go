package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/query"
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

// detailLayout is the issue laid out as text for one width. Each environment
// row and each link is there in two forms, plain and selected, and at says on
// which line it starts.
type detailLayout struct {
	w     int
	lines []string
	rows  []detailRow // the environments
	links []detailRow // the links of the References section
}

// detailRow is one or more lines; plain and hl have as many.
type detailRow struct {
	at        int
	plain, hl []string
}

// layout is the cached page when it fits the width, else a fresh one (kept
// by the caller's Update, not here).
func (d *detail) layout(w int) *detailLayout {
	if d.lay != nil && d.lay.w == w {
		return d.lay
	}
	return d.build(w)
}

// build lays the issue out as text. Everything that came from a feed, a
// repository or a person goes through clean first.
func (d *detail) build(w int) *detailLayout {
	switch {
	case d.loading:
		return &detailLayout{w: w, lines: []string{stMuted.Render("Loading " + oneLine(d.id) + "...")}}
	case d.err != nil:
		return &detailLayout{w: w, lines: []string{stErr.Render("error: ") + oneLine(d.err.Error()), "", stMuted.Render("esc goes back")}}
	}
	is := d.is
	var out []string
	var rows []detailRow
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
	if facts := exploitFacts(is); facts != "" {
		add(indentWrap("exploitation: ", facts, w)...)
	}
	why := is.Priority
	if d.det != nil {
		why = d.det.Why
	}
	if len(why) > 0 {
		add(indentWrap("priority: ", oneLine(strings.Join(why, "; ")), w)...)
	}
	add("")

	if desc := oneLine(is.Untrusted.Description); desc != "" {
		add(section("Description"))
		add(indentWrap("  ", desc, w)...)
		add("")
	}

	add(section("Environments") + stMuted.Render("  up/down select; f i n o act on the selected row, F I N O on the whole project"))
	if len(is.Targets) == 0 {
		add("  (no environment is tracked for this issue)")
	}
	for _, t := range is.Targets {
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
		rows = append(rows, detailRow{
			at:    len(out),
			plain: []string{"  " + statusStyle(t.Status).Render(core) + " " + trunc(rest, max(w-width(core)-3, 1))},
			hl:    []string{stSel.Render(pad("> "+core+" "+rest, w))},
		})
		add(rows[len(rows)-1].plain...)
		if t.Note != "" {
			add(indentWrap("      note: ", oneLine(t.Note), w)...)
		}
		if d.det != nil {
			if inst := installedText(d.det.TargetOf(t.Project, t.Env)); inst != "" {
				add(indentWrap("      installed: ", inst, w)...)
			}
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

	if d.det != nil && len(d.det.Affected) > 0 {
		add(section("Affected versions"))
		for _, a := range d.det.Affected {
			s := oneLine(a.Ecosystem+" "+a.Name) + ": " + oneLine(query.RangeText(a.Ranges))
			if a.Fixed != "" {
				s += " (first fixed " + oneLine(a.Fixed) + ")"
			}
			add(indentWrap("  ", s, w)...)
		}
		add("")
	}

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
	var links []detailRow
	if d.det != nil {
		add("")
		links = d.buildReferences(w, &out)
		d.buildEvidence(w, &out)
		d.buildHistory(w, &out)
	}
	return &detailLayout{w: w, lines: out, rows: rows, links: links}
}

// exploitFacts is the line about known exploitation: the KEV listing with its
// dates and the EPSS score with its percentile.
func exploitFacts(is query.Issue) string {
	var parts []string
	if k := is.KEV; k != nil {
		s := "on the CISA KEV list since " + day(k.DateAdded)
		if !k.DueDate.IsZero() {
			s += ", CISA remediation due " + day(k.DueDate)
		}
		if k.Ransomware {
			s += ", known ransomware use"
		}
		parts = append(parts, s)
	}
	if e := is.EPSS; e != nil {
		parts = append(parts, fmt.Sprintf("EPSS %.0f%% (percentile %.0f)", e.Score*100, e.Percentile*100))
	}
	return strings.Join(parts, "; ")
}

func installedText(t query.TargetDetail) string {
	labels := make([]string, len(t.Installed))
	for i, in := range t.Installed {
		labels[i] = in.Label()
	}
	return oneLine(strings.Join(labels, ", "))
}

// buildReferences lists the links, numbered, each selectable. The report file
// is named last.
func (d *detail) buildReferences(w int, out *[]string) []detailRow {
	add := func(l ...string) { *out = append(*out, l...) }
	add(section("References") + stMuted.Render("  l/L select a link; enter opens it, c copies it"))
	var rows []detailRow
	for i, l := range d.det.Links {
		head := fmt.Sprintf("  %2d. %s  %s", i+1, pad(l.Kind, 8), oneLine(l.Source))
		if t := oneLine(l.Title); t != "" {
			head += "  " + t
		}
		plain := []string{trunc(head, w)}
		hl := []string{stSel.Render(pad(">"+head[1:], w))}
		for _, u := range indentWrap("      ", oneLine(l.URL), w) {
			plain = append(plain, stMuted.Render(u))
			hl = append(hl, stSel.Render(pad(u, w)))
		}
		rows = append(rows, detailRow{at: len(*out), plain: plain, hl: hl})
		add(plain...)
	}
	if len(rows) == 0 {
		add("  no link is recorded for this issue")
	}
	if d.is.Report != "" {
		add(indentWrap("  report file: ", oneLine(d.is.Report), w)...)
	}
	add(stMuted.Render("  R shows the report here, v the evidence pack"))
	add("")
	return rows
}

// buildEvidence lists the notes and links people attached, per environment.
func (d *detail) buildEvidence(w int, out *[]string) {
	add := func(l ...string) { *out = append(*out, l...) }
	add(section("Evidence") + stMuted.Render("  + adds a note or a link to the selected environment"))
	n := 0
	for _, t := range d.det.Targets {
		for _, e := range t.Evidence {
			n++
			s := day(e.Time) + " " + orDash(oneLine(e.Actor))
			if e.Note != "" {
				s += ": " + oneLine(e.Note)
			}
			add(indentWrap("  "+oneLine(t.Project)+"/"+string(t.Env)+" ", s, w)...)
			if e.URL != "" {
				add(indentWrap("      ", oneLine(e.URL), w)...)
			}
		}
	}
	if n == 0 {
		add("  none attached")
	}
	add("")
}

// buildHistory lists what happened to the findings, oldest first.
func (d *detail) buildHistory(w int, out *[]string) {
	add := func(l ...string) { *out = append(*out, l...) }
	add(section("History"))
	for _, h := range d.det.History {
		s := h.Time.UTC().Format("2006-01-02 15:04") + " " + oneLine(h.Detail)
		if h.Actor != "" {
			s += " (by " + oneLine(h.Actor) + ")"
		}
		if h.URL != "" {
			s += " " + oneLine(h.URL)
		}
		add(indentWrap("  ", s, w)...)
	}
	if len(d.det.History) == 0 {
		add("  nothing recorded")
	}
}
