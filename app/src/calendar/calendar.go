// Package calendar renders a one-month overview of vulnerabilities, as a
// self-contained HTML page and as terminal text. Weeks start on Monday.
package calendar

import (
	"cmp"
	"fmt"
	"hash/fnv"
	"html"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/b070nd/cvewatch/app/src/model"
)

// Entry is one vulnerability to show on its date.
type Entry struct {
	Date     time.Time
	ID       string
	Title    string
	Severity model.Severity
	Techs    []string
	Articles int
	Fix      bool
}

// maxChips is how many entries one day cell shows before "+N more".
const maxChips = 4

// sevs lists severities from most to least urgent, so sevs[sevIndex(s)]
// describes s. Anything unrated or unrecognised lands on the last one.
var sevs = [...]struct {
	sev    model.Severity
	letter string
	label  string
}{
	{model.SevCritical, "C", "critical"},
	{model.SevHigh, "H", "high"},
	{model.SevMedium, "M", "medium"},
	{model.SevLow, "L", "low"},
	{model.SevUnknown, "?", "unrated"},
}

func sevIndex(s model.Severity) int { return len(sevs) - 1 - s.Rank() }

// monthDays groups the entries that fall in month by day of month (index 0 is
// day 1), each day sorted by severity, then ID.
func monthDays(entries []Entry, month time.Time) [][]Entry {
	y, m, _ := month.Date()
	loc := month.Location()
	days := make([][]Entry, time.Date(y, m+1, 0, 0, 0, 0, 0, loc).Day())
	for _, e := range entries {
		if ey, em, ed := e.Date.In(loc).Date(); ey == y && em == m {
			days[ed-1] = append(days[ed-1], e)
		}
	}
	for _, d := range days {
		slices.SortFunc(d, func(a, b Entry) int {
			return cmp.Or(
				cmp.Compare(b.Severity.Rank(), a.Severity.Rank()),
				cmp.Compare(a.ID, b.ID),
				cmp.Compare(a.Title, b.Title))
		})
	}
	return days
}

// lead is how many cells precede the 1st in a Monday-first week.
func lead(month time.Time) int {
	y, m, _ := month.Date()
	return (int(time.Date(y, m, 1, 0, 0, 0, 0, month.Location()).Weekday()) + 6) % 7
}

// techs returns the entry's tech names, trimmed, sorted, without blanks or repeats.
func techs(e Entry) []string {
	var out []string
	for _, t := range e.Techs {
		if t = strings.TrimSpace(t); t != "" {
			out = append(out, t)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// plural formats n with a singular noun or its "-ies"/"-s" plural.
func plural(n int, word string) string {
	switch {
	case n == 1:
		return "1 " + word
	case strings.HasSuffix(word, "y"):
		return fmt.Sprintf("%d %sies", n, strings.TrimSuffix(word, "y"))
	}
	return fmt.Sprintf("%d %ss", n, word)
}

// ---- text ----

// Text renders the month as a Monday-first grid of day numbers with entry
// counts, followed by the entries listed by day.
func Text(entries []Entry, month time.Time) string {
	days := monthDays(entries, month)
	y, m, _ := month.Date()
	var b strings.Builder
	fmt.Fprintf(&b, "%s %d\n\n", m, y)
	for _, wd := range []string{"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"} {
		fmt.Fprintf(&b, " %-7s", wd)
	}
	b.WriteString("\n")
	cells := make([]string, 0, 42)
	for range lead(month) {
		cells = append(cells, strings.Repeat(" ", 8))
	}
	for i, d := range days {
		count := ""
		if len(d) > 0 {
			count = fmt.Sprintf(" (%d)", len(d))
		}
		cells = append(cells, fmt.Sprintf("%2d%-6s", i+1, count))
	}
	for i := 0; i < len(cells); i += 7 {
		b.WriteString(strings.TrimRight(strings.Join(cells[i:min(i+7, len(cells))], " "), " "))
		b.WriteString("\n")
	}
	b.WriteString("\n")
	n := 0
	for i, d := range days {
		for _, e := range d {
			n++
			parts := []string{
				fmt.Sprintf("%04d-%02d-%02d", y, int(m), i+1),
				fmt.Sprintf("%-8s", strings.ToUpper(sevs[sevIndex(e.Severity)].label)),
				clean(e.ID),
			}
			if t := techs(e); len(t) > 0 {
				parts = append(parts, "["+clean(strings.Join(t, ","))+"]")
			}
			parts = append(parts, clip(clean(e.Title), 70))
			line := strings.Join(parts, "  ")
			if e.Articles > 0 {
				line += "  · " + plural(e.Articles, "article")
			}
			if e.Fix {
				line += " · fix"
			}
			b.WriteString(strings.TrimRight(line, " "))
			b.WriteString("\n")
		}
	}
	if n == 0 {
		b.WriteString("No entries.\n")
	}
	return b.String()
}

// clean drops control characters (so feed text cannot drive the terminal)
// and folds whitespace runs into single spaces.
func clean(s string) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\t' || r == '\r':
			return ' '
		case unicode.In(r, unicode.Cc, unicode.Cf):
			return -1
		}
		return r
	}, s)
	return strings.Join(strings.Fields(s), " ")
}

// clip shortens s to at most n runes, ending in an ellipsis when cut.
func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// ---- html ----

// techColors is how many tech colors the stylesheet defines (--t0 ... --t9).
const techColors = 10

// techClass picks a stable palette slot from the tech's name.
func techClass(name string) string {
	h := fnv.New32a()
	h.Write([]byte(name))
	return fmt.Sprintf("t%d", h.Sum32()%techColors)
}

// HTML renders the month as one self-contained page: no scripts and no
// external resources. Everything taken from entries is escaped; colors come
// only from the fixed palette in the stylesheet. now marks today when it
// falls inside the month.
func HTML(entries []Entry, month, now time.Time) string {
	days := monthDays(entries, month)
	y, m, _ := month.Date()
	today := 0
	if ny, nm, nd := now.In(month.Location()).Date(); ny == y && nm == m {
		today = nd
	}
	label := fmt.Sprintf("%s %d", m, y)
	esc := html.EscapeString

	var b strings.Builder
	p := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }

	p("<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n")
	p("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n")
	p("<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">\n")
	p("<title>Vulnerability calendar - %s</title>\n<style>%s</style>\n</head>\n<body>\n", label, css)
	p("<h1>%s</h1>\n<div class=\"scroll\"><div class=\"grid\">\n", label)
	for _, wd := range []string{"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"} {
		p("<div class=\"wd\">%s</div>\n", wd)
	}
	blank := func() { p("<div class=\"cell blank\" aria-hidden=\"true\"></div>\n") }
	for range lead(month) {
		blank()
	}

	var counts [len(sevs)]int
	techCount := map[string]int{}
	total := 0
	for i, d := range days {
		if i+1 == today {
			p("<div class=\"cell today\" aria-current=\"date\"><div class=\"dn\">%d <span class=\"now\">today</span></div>\n", i+1)
		} else {
			p("<div class=\"cell\"><div class=\"dn\">%d</div>\n", i+1)
		}
		for j, e := range d {
			si := sevIndex(e.Severity)
			counts[si]++
			total++
			ts := techs(e)
			for _, t := range ts {
				techCount[t]++
			}
			if j >= maxChips {
				continue
			}
			tip := e.Title
			if e.Articles > 0 {
				tip += " · " + plural(e.Articles, "article")
			}
			if e.Fix {
				tip += " · fix available"
			}
			p("<div class=\"chip s%d\" title=\"%s\"><span class=\"badge\">%s</span><span class=\"id\">%s</span>",
				si, esc(tip), sevs[si].letter, esc(e.ID))
			for _, t := range ts {
				p("<span class=\"tag %s\">%s</span>", techClass(t), esc(t))
			}
			p("</div>\n")
		}
		if len(d) > maxChips {
			p("<div class=\"more\">+%d more</div>\n", len(d)-maxChips)
		}
		p("</div>\n")
	}
	for range (7 - (lead(month)+len(days))%7) % 7 {
		blank()
	}
	p("</div></div>\n")

	p("<section><h2>Summary</h2>\n<p>%s in %s.</p>\n<ul class=\"row\">\n", plural(total, "vulnerability"), label)
	for i, s := range sevs {
		p("<li class=\"s%d\"><span class=\"badge\">%s</span> %s %d</li>\n", i, s.letter, s.label, counts[i])
	}
	p("</ul></section>\n")

	p("<section class=\"legend\"><h2>Legend</h2>\n<h3>Severity</h3>\n<ul class=\"row\">\n")
	for i, s := range sevs {
		p("<li class=\"s%d\"><span class=\"badge\">%s</span> %s</li>\n", i, s.letter, s.label)
	}
	p("</ul>\n<h3>Technologies</h3>\n")
	if len(techCount) == 0 {
		p("<p class=\"muted\">None this month.</p>\n")
	} else {
		names := make([]string, 0, len(techCount))
		for t := range techCount {
			names = append(names, t)
		}
		slices.Sort(names)
		p("<ul class=\"row\">\n")
		for _, t := range names {
			p("<li><span class=\"tag %s\">%s</span> %d</li>\n", techClass(t), esc(t), techCount[t])
		}
		p("</ul>\n")
	}
	p("<h3>Advisories</h3>\n")
	if total == 0 {
		p("<p class=\"muted\">None this month.</p>\n")
	} else {
		p("<ol class=\"ids\">\n")
		for i, d := range days {
			for _, e := range d {
				si := sevIndex(e.Severity)
				p("<li class=\"s%d\"><span class=\"date\">%04d-%02d-%02d</span> <span class=\"badge\">%s</span> <span class=\"id\">%s</span></li>\n",
					si, y, int(m), i+1, sevs[si].letter, esc(e.ID))
			}
		}
		p("</ol>\n")
	}
	p("</section>\n</body>\n</html>\n")
	return b.String()
}

// css holds the whole stylesheet. Colors are variables so dark mode only
// swaps values; badge and tag text switch with --on to keep contrast.
const css = `
:root{color-scheme:light dark;--bg:#fff;--fg:#1f2328;--muted:#57606a;--line:#d0d7de;--cell:#f6f8fa;--blank:#eceff3;--today:#0969da;--on:#fff;
--s0:#b91c1c;--s1:#c2410c;--s2:#a16207;--s3:#1d4ed8;--s4:#4b5563;
--t0:#0f766e;--t1:#7e22ce;--t2:#be185d;--t3:#15803d;--t4:#4338ca;--t5:#0e7490;--t6:#92400e;--t7:#0369a1;--t8:#a21caf;--t9:#4d7c0f}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--fg:#e6edf3;--muted:#9da7b3;--line:#30363d;--cell:#161b22;--blank:#0d1117;--today:#58a6ff;--on:#111;
--s0:#fca5a5;--s1:#fdba74;--s2:#fde047;--s3:#93c5fd;--s4:#d1d5db;
--t0:#5eead4;--t1:#d8b4fe;--t2:#f9a8d4;--t3:#86efac;--t4:#a5b4fc;--t5:#67e8f9;--t6:#fcd34d;--t7:#7dd3fc;--t8:#f0abfc;--t9:#bef264}}
*{box-sizing:border-box}
body{margin:0 auto;max-width:72rem;padding:1rem;background:var(--bg);color:var(--fg);font:14px/1.4 system-ui,sans-serif}
h1{margin:.2em 0 .6em;font-size:1.6rem}h2{font-size:1.2rem;margin:1.5em 0 .4em}h3{font-size:1rem;margin:1em 0 .3em}
.scroll{overflow-x:auto}
.grid{display:grid;grid-template-columns:repeat(7,minmax(8.5rem,1fr));gap:2px;min-width:60rem}
.wd{padding:.3rem;font-weight:600;color:var(--muted)}
.cell{min-height:6rem;padding:.3rem;background:var(--cell);border:1px solid var(--line);border-radius:4px;display:flex;flex-direction:column;gap:.2rem}
.blank{background:var(--blank);border-style:dashed}
.today{outline:3px solid var(--today)}
.dn{font-weight:600}.now{margin-left:.3rem;color:var(--today);font-size:.75rem}
.chip{display:flex;flex-wrap:wrap;gap:.2rem;align-items:center;padding:.1rem .3rem;background:var(--bg);border:1px solid var(--line);border-left:4px solid var(--sc);border-radius:4px;font-size:.75rem}
.more{color:var(--muted);font-size:.75rem}
.s0{--sc:var(--s0)}.s1{--sc:var(--s1)}.s2{--sc:var(--s2)}.s3{--sc:var(--s3)}.s4{--sc:var(--s4)}
.t0{--tc:var(--t0)}.t1{--tc:var(--t1)}.t2{--tc:var(--t2)}.t3{--tc:var(--t3)}.t4{--tc:var(--t4)}.t5{--tc:var(--t5)}.t6{--tc:var(--t6)}.t7{--tc:var(--t7)}.t8{--tc:var(--t8)}.t9{--tc:var(--t9)}
.badge{display:inline-block;min-width:1.3em;padding:0 .25em;border-radius:3px;background:var(--sc);color:var(--on);font-weight:700;text-align:center}
.tag{display:inline-block;padding:0 .35em;border-radius:3px;background:var(--tc);color:var(--on);font-size:.7rem}
.id{font-family:ui-monospace,monospace;overflow-wrap:anywhere}
.row{display:flex;flex-wrap:wrap;gap:.4rem 1.2rem;margin:0;padding:0;list-style:none}
.ids{margin:0;padding-left:1.5rem}.ids li{margin:.15rem 0}.date{color:var(--muted)}
.muted{color:var(--muted)}
`
