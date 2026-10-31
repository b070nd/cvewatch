package tui

import (
	"fmt"
	"time"

	"github.com/b070nd/cvewatch/app/src/status"
)

// renderStatus lists the health of the tool itself: the daemon, each feed and
// channel, and the recent cycles.
func renderStatus(rep status.Report, now time.Time, w int, projects []string, horizon string) *textPage {
	var out []string
	var rows []pageRow
	add := func(l ...string) { out = append(out, l...) }
	// failing is a row that can be selected: Enter goes to the project the
	// error names, or shows the error in full.
	failing := func(key, title, errText string, lines int) {
		r := pageRow{at: len(out) - lines, n: lines, key: key, title: title, info: errText}
		if p := projectIn(errText, projects); p != "" {
			r.tgt = projectTarget(p, "")
		}
		rows = append(rows, r)
	}

	add(section("Overall")+"  "+levelText(rep.Level)+reasonText(rep), "")
	add("  daemon  " + levelText(rep.Daemon.Level) + "  " + orDash(oneLine(rep.Daemon.Mode)))
	add(indentWrap("          ", orDash(oneLine(rep.Daemon.Message)), w)...)
	if !rep.Daemon.LastCycle.IsZero() {
		add("          last cycle " + when(rep.Daemon.LastCycle, now))
	}
	if !rep.Daemon.NextRun.IsZero() {
		add("          next run   " + rep.Daemon.NextRun.UTC().Format("2006-01-02 15:04") + " UTC")
	}
	if horizon != "" {
		add("          alert horizon: " + horizon + " (only vulnerabilities published then are judged and alerted)")
	}
	add("")

	add(section(fmt.Sprintf("Feeds (%d)", len(rep.Sources))))
	if len(rep.Sources) == 0 {
		add("  none configured")
	}
	idW := 6
	for _, s := range rep.Sources {
		idW = max(idW, min(width(oneLine(s.ID)), 24))
	}
	if len(rep.Sources) > 0 {
		add(stMuted.Render("  " + pad("FEED", idW) + " " + pad("TYPE", 10) + " " + pad("LEVEL", 9) + " " + pad("LAST SUCCESS", 20) + " " + pad("FAILS", 5) + " ITEMS"))
	}
	for _, s := range rep.Sources {
		line := "  " + pad(oneLine(s.ID), idW) + " " + pad(oneLine(s.Type), 10) + " " + levelCell(s.Level, 9) + " " +
			pad(agoText(s.LastSuccess), 20) + " " + pad(fmt.Sprint(s.Failures), 5) + " " + fmt.Sprint(s.Items)
		add(line)
		if s.LastError != "" {
			ls := indentWrap("      error: ", oneLine(s.LastError), w)
			add(ls...)
			failing("feed "+s.ID, "Feed "+oneLine(s.ID)+": error", s.LastError, 1+len(ls))
		}
	}
	add("")

	add(section(fmt.Sprintf("Channels (%d)", len(rep.Channels))))
	if len(rep.Channels) == 0 {
		add("  none active")
	}
	nameW := 8
	for _, c := range rep.Channels {
		nameW = max(nameW, min(width(oneLine(c.Name)), 24))
	}
	if len(rep.Channels) > 0 {
		add(stMuted.Render("  " + pad("CHANNEL", nameW) + " " + pad("LEVEL", 9) + " " + pad("LAST SUCCESS", 20) + " FAILS"))
	}
	for _, c := range rep.Channels {
		add("  " + pad(oneLine(c.Name), nameW) + " " + levelCell(c.Level, 9) + " " + pad(agoText(c.LastSuccess), 20) + " " + fmt.Sprint(c.Failures))
		if c.LastError != "" {
			ls := indentWrap("      error: ", oneLine(c.LastError), w)
			add(ls...)
			failing("channel "+c.Name, "Channel "+oneLine(c.Name)+": error", c.LastError, 1+len(ls))
		}
	}
	add("")

	add(section(fmt.Sprintf("Projects (%d)", len(rep.Projects))))
	if !rep.Scheduled {
		add(indentWrap("  ", "scheduled updates are off (update.auto in config.yaml): only update and the F key refresh", w)...)
	}
	if len(rep.Projects) == 0 {
		add("  none")
	}
	prjW := 7
	for _, p := range rep.Projects {
		prjW = max(prjW, min(width(oneLine(p.Name)), 24))
	}
	if len(rep.Projects) > 0 {
		add(stMuted.Render("  " + pad("PROJECT", prjW) + " " + pad("UPDATES", 10) + " " + pad("LAST UPDATE", 18) + " NEXT"))
	}
	for _, p := range rep.Projects {
		every, _ := rep.Schedule(p)
		next := "-"
		switch {
		case !p.Next.IsZero() && !p.Next.After(rep.GeneratedAt):
			next = "due now"
		case !p.Next.IsZero():
			next = p.Next.UTC().Format("2006-01-02 15:04") + "Z"
		}
		add("  " + pad(oneLine(p.Name), prjW) + " " + pad(every, 10) + " " + pad(agoText(p.LastUpdate), 18) + " " + next)
	}
	add("")

	add(section(fmt.Sprintf("Recent cycles (%d)", len(rep.Cycles))))
	if len(rep.Cycles) == 0 {
		add("  no cycle has run yet")
	} else {
		add(stMuted.Render("  " + pad("STARTED (UTC)", 17) + " " + pad("TOOK", 6) + " " + pad("ITEMS", 5) + " " + pad("NEW", 4) + " " + pad("FINDINGS", 8) + " " + pad("ALERTED", 7) + " FAILED"))
	}
	for _, c := range rep.Cycles {
		took := "-"
		if !c.Finished.IsZero() && !c.Started.IsZero() {
			took = c.Finished.Sub(c.Started).Round(time.Second).String()
		}
		add("  " + pad(c.Started.UTC().Format("2006-01-02 15:04"), 17) + " " + pad(took, 6) + " " + pad(fmt.Sprint(c.Items), 5) + " " +
			pad(fmt.Sprint(c.New), 4) + " " + pad(fmt.Sprint(c.Findings), 8) + " " + pad(fmt.Sprint(c.Alerted), 7) + " " + fmt.Sprint(c.Failed))
		if c.Err != "" {
			ls := indentWrap("      error: ", oneLine(c.Err), w)
			add(ls...)
			failing("cycle "+c.Started.UTC().Format("2006-01-02T15:04:05"), "Cycle of "+c.Started.UTC().Format("2006-01-02 15:04")+": error", c.Err, 1+len(ls))
		}
	}

	if len(rep.Warnings) > 0 {
		add("", section("Warnings"))
		for _, wn := range rep.Warnings {
			add(indentWrap("  ! ", oneLine(wn), w)...)
		}
	}
	return &textPage{lines: out, rows: rows}
}

// levelCell is a level word padded to w cells, styled after padding.
func levelCell(l status.Level, w int) string {
	txt := levelText(l)
	if n := width(txt); n < w {
		txt += spaces(w - n)
	}
	return txt
}

func agoText(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.UTC().Format("2006-01-02 15:04") + "Z"
}

// reasonText is the muted note after an overall level that needs one.
func reasonText(rep status.Report) string {
	if why := rep.Reason(); why != "" {
		return stMuted.Render("  " + why)
	}
	return ""
}
