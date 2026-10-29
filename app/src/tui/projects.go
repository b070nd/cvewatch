package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/b070nd/cvewatch/app/src/projectfile"
)

type projectsState struct {
	cursor int
	issue  int // the selected problem of the selected project
	fix    *fixState
}

func (m *app) projectsKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	n := 0
	if m.data != nil {
		n = len(m.data.Projects)
	}
	if m.data == nil {
		return m, nil // nothing loaded yet; r retries, q quits
	}
	before := m.prj.cursor
	defer func() {
		if m.prj.cursor != before {
			m.prj.issue = 0
		}
	}()
	switch k.String() {
	case "up", "k":
		m.prj.cursor = clamp(m.prj.cursor-1, 0, n-1)
	case "down", "j":
		m.prj.cursor = clamp(m.prj.cursor+1, 0, n-1)
	case "home", "g":
		m.prj.cursor = 0
	case "end", "G":
		m.prj.cursor = max(n-1, 0)
	case "p", "P":
		if p, ok := m.selectedProject(); ok && len(p.Problems) > 0 {
			d := 1
			if k.String() == "P" {
				d = len(p.Problems) - 1
			}
			m.prj.issue = (clamp(m.prj.issue, 0, len(p.Problems)-1) + d) % len(p.Problems)
		}
	case "f":
		return m, m.startFix()
	case "o":
		return m, m.openEditor()
	case "e", "enter":
		if n == 0 {
			return m, nil
		}
		p := m.data.Projects[clamp(m.prj.cursor, 0, n-1)]
		if p.Broken != "" {
			m.fail("the file of " + p.Name + " does not load; press o to edit it")
			return m, nil
		}
		m.busy = "opening " + oneLine(p.Name) + "..."
		return m, startFlowCmd(m.b, p.Name, "")
	case "n":
		m.busy = "opening..."
		return m, startFlowCmd(m.b, "", "")
	case "d":
		m.startPath()
	}
	return m, nil
}

// techList is "php 8.2, nginx", as much as fits.
func techList(p projectRow) string {
	var parts []string
	for _, t := range p.Techs {
		parts = append(parts, strings.TrimSpace(oneLine(t.Name)+" "+oneLine(t.Version)))
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, ", ")
}

// renderProjects lists the projects with their declared technologies and the
// number of lockfiles, and below the list the selected project in full.
func renderProjects(rows []projectRow, cursor, issue, w, h int) []string {
	if len(rows) == 0 {
		return []string{stMuted.Render("No projects yet."), "", "Press n to create one, or d to scan a folder and propose one."}
	}
	nameW := 8
	for _, p := range rows {
		nameW = max(nameW, min(width(oneLine(p.Name)), 24))
	}
	const envW, lockW, probW = 22, 9, 13
	techW := max(w-2-nameW-1-envW-1-lockW-1-probW-1, 10)
	lines := []string{stHead.Render(trunc("  "+pad("PROJECT", nameW)+" "+pad("ENVIRONMENTS", envW)+" "+pad("LOCKFILES", lockW)+" "+pad("PROBLEMS", probW)+" TECHNOLOGIES", w))}

	detailH := 0
	sel := rows[clamp(cursor, 0, len(rows)-1)]
	detail := projectDetail(sel, issue, w)
	if h > 14 {
		detailH = len(detail) + 1
	}
	room := max(h-len(lines)-detailH, 1)
	start := clamp(cursor-room/2, 0, len(rows)-room)
	end := min(start+room, len(rows))
	for i := start; i < end; i++ {
		p := rows[i]
		envs := "all"
		if len(p.Envs) > 0 && len(p.Envs) < 4 {
			envs = strings.Join(p.Envs, ",")
		}
		techs := techList(p)
		if p.Broken != "" {
			envs, techs = "-", oneLine(p.Broken)
		}
		cells := pad(oneLine(p.Name), nameW) + " " + pad(envs, envW) + " " + pad(fmt.Sprint(len(p.Lockfiles)), lockW) + " " + pad(problemBadge(p), probW) + " " + trunc(techs, techW)
		if i == cursor {
			lines = append(lines, stSel.Render(pad("> "+cells, w)))
		} else {
			lines = append(lines, "  "+cells)
		}
	}
	if detailH > 0 {
		lines = append(lines, "")
		lines = append(lines, detail...)
	}
	return lines
}

// problemBadge is the count of what is wrong with the project file, in words.
func problemBadge(p projectRow) string {
	errs, warns := p.counts()
	switch {
	case p.Broken != "":
		return "BROKEN"
	case errs+warns == 0:
		return "-"
	case warns == 0:
		return fmt.Sprintf("%d err", errs)
	case errs == 0:
		return fmt.Sprintf("%d warn", warns)
	}
	return fmt.Sprintf("%d err %d warn", errs, warns)
}

func projectDetail(p projectRow, issue, w int) []string {
	out := []string{section(oneLine(p.Name))}
	if !p.HasFile {
		out[0] += stMuted.Render("  defined in the main config, not editable here")
	}
	if p.Broken != "" {
		out = append(out, clip(indentWrap("  "+stErr.Render("broken: "), oneLine(p.Broken), w), 3)...)
		out = append(out, "  file: "+trunc(oneLine(p.File), w-8))
	} else {
		out = append(out, indentWrap("  technologies: ", techList(p), w)...)
	}
	out = append(out, problemLines(p.Problems, issue, w)...)
	if p.Broken != "" {
		return out
	}
	if len(p.Lockfiles) == 0 {
		return append(out, "  lockfiles: none")
	}
	for i, l := range p.Lockfiles {
		if i == 4 {
			out = append(out, fmt.Sprintf("  ... and %d more lockfiles", len(p.Lockfiles)-4))
			break
		}
		s := oneLine(l.Type) + " " + oneLine(l.Path)
		if l.Env != "" {
			s += " (" + oneLine(l.Env) + ")"
		}
		out = append(out, indentWrap("  lockfile: ", s, w)...)
	}
	return out
}

// problemLines lists the problems, the selected one marked, with the label of
// its fix underneath. At most five are shown, around the selected one.
func problemLines(issues []projectfile.Issue, sel, w int) []string {
	if len(issues) == 0 {
		return nil
	}
	sel = clamp(sel, 0, len(issues)-1)
	const room = 5
	start := clamp(sel-room/2, 0, len(issues)-room)
	end := min(start+room, len(issues))
	out := []string{stMuted.Render("  problems (p next, f fix):")}
	for i := start; i < end; i++ {
		is := issues[i]
		mark := "    "
		if i == sel {
			mark = "  > "
		}
		out = append(out, trunc(mark+pad(oneLine(is.Level), 7)+" "+oneLine(is.Field)+": "+oneLine(is.Message), w))
		if i == sel && len(is.Fixes) > 0 {
			out = append(out, stMuted.Render(trunc("        fix: "+oneLine(is.Fixes[0].Label), w)))
		}
	}
	if start > 0 || end < len(issues) {
		out = append(out, stMuted.Render(fmt.Sprintf("    (%d of %d)", sel+1, len(issues))))
	}
	return out
}
