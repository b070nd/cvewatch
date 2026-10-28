package tui

import (
	"fmt"
	"time"

	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/priority"
)

// renderOverview is the first screen: is the tool healthy, how much is open,
// where, and what broke a policy. Wording follows the HTML dashboard.
func renderOverview(sn *snapshot, w int) []string {
	c := countsOf(sn.Issues)
	rep := sn.Status
	var out []string
	add := func(l ...string) { out = append(out, l...) }

	add(section("Status") + "  " + levelText(rep.Level))
	add(indentWrap("  daemon: ", orDash(oneLine(rep.Daemon.Message)), w)...)
	if len(rep.Cycles) == 0 {
		add("  last cycle: none yet")
	} else {
		cy := rep.Cycles[0]
		add("  last cycle: " + when(cy.Finished, sn.At))
		add(fmt.Sprintf("              items %d  new %d  merged %d  findings %d  alerted %d  digests %d  failed feeds %d",
			cy.Items, cy.New, cy.Merged, cy.Findings, cy.Alerted, cy.Digests, cy.Failed))
		if cy.Err != "" {
			add(indentWrap("              error: ", oneLine(cy.Err), w)...)
		}
	}
	add("")
	add(fmt.Sprintf("  %-34s %d", "open issues", c.Issues),
		fmt.Sprintf("  %-34s %d", "open findings", c.Findings),
		fmt.Sprintf("  %-34s %d", "critical + high open", c.BySev[4]+c.BySev[3]),
		fmt.Sprintf("  %-34s %d", "known exploited (KEV) open", c.KEV),
		fmt.Sprintf("  %-34s %d", "open in prod", c.ProdOpen),
		fmt.Sprintf("  %-34s %d", "overdue findings", c.Overdue),
		fmt.Sprintf("  %-34s %d", "policy violations", len(sn.Violations)))
	add("")

	barW := max(min(w-24, 40), 0)
	add(section("Open issues by severity"))
	most := 0
	for _, n := range c.BySev {
		most = max(most, n)
	}
	for _, s := range severities {
		n := c.BySev[s.Rank()]
		add("  " + sevText(s, 9) + fmt.Sprintf("%5d  ", n) + sevStyles[s.Rank()].Render(bar(n, most, barW)))
	}
	add("")

	add(section("Open findings by environment"))
	most = 0
	for _, n := range c.ByEnv {
		most = max(most, n)
	}
	for _, e := range model.AllEnvs {
		n := c.ByEnv[e]
		add("  " + pad(string(e), 9) + fmt.Sprintf("%5d  ", n) + bar(n, most, barW))
	}
	add("")

	add(section("Policy violations"))
	if len(sn.Violations) == 0 {
		add("  none")
	}
	for i, v := range sn.Violations {
		if i == 5 {
			add(fmt.Sprintf("  ... and %d more (see the dashboard or `cvewatch report`)", len(sn.Violations)-5))
			break
		}
		add(violationLines(v, w)...)
	}
	add("")

	var warns []string
	warns = append(warns, rep.Warnings...)
	warns = append(warns, sn.Warnings...)
	if len(warns) > 0 {
		add("", section("Warnings"))
		for _, wn := range warns {
			add(indentWrap("  ! ", oneLine(wn), w)...)
		}
	}
	return out
}

func violationLines(v priority.Violation, w int) []string {
	s := v.Subject
	text := fmt.Sprintf("%s: %s %s/%s %s", oneLine(v.Rule), oneLine(s.VulnID), oneLine(s.Project), s.Env, oneLine(v.Reason))
	if v.Late >= time.Hour {
		text += fmt.Sprintf(" (%dh late)", int(v.Late.Hours()))
	}
	return indentWrap("  - ", text, w)
}
