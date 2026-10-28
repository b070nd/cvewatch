package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

type projectsState struct {
	cursor int
}

func (m *app) projectsKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	n := 0
	if m.data != nil {
		n = len(m.data.Projects)
	}
	switch k.String() {
	case "up", "k":
		m.prj.cursor = clamp(m.prj.cursor-1, 0, n-1)
	case "down", "j":
		m.prj.cursor = clamp(m.prj.cursor+1, 0, n-1)
	case "home", "g":
		m.prj.cursor = 0
	case "end", "G":
		m.prj.cursor = max(n-1, 0)
	case "e", "enter":
		if n == 0 {
			return m, nil
		}
		p := m.data.Projects[clamp(m.prj.cursor, 0, n-1)]
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
func renderProjects(rows []projectRow, cursor, w, h int) []string {
	if len(rows) == 0 {
		return []string{stMuted.Render("No projects yet."), "", "Press n to create one, or d to scan a folder and propose one."}
	}
	nameW := 8
	for _, p := range rows {
		nameW = max(nameW, min(width(oneLine(p.Name)), 24))
	}
	const envW, lockW = 22, 9
	techW := max(w-2-nameW-1-envW-1-lockW-1, 10)
	lines := []string{stHead.Render(trunc("  "+pad("PROJECT", nameW)+" "+pad("ENVIRONMENTS", envW)+" "+pad("LOCKFILES", lockW)+" TECHNOLOGIES", w))}

	detailH := 0
	sel := rows[clamp(cursor, 0, len(rows)-1)]
	detail := projectDetail(sel, w)
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
		cells := pad(oneLine(p.Name), nameW) + " " + pad(envs, envW) + " " + pad(fmt.Sprint(len(p.Lockfiles)), lockW) + " " + trunc(techList(p), techW)
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

func projectDetail(p projectRow, w int) []string {
	out := []string{section(oneLine(p.Name))}
	if !p.HasFile {
		out[0] += stMuted.Render("  defined in the main config, not editable here")
	}
	out = append(out, indentWrap("  technologies: ", techList(p), w)...)
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
