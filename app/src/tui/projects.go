package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/b070nd/cvewatch/app/src/projectfile"
)

type projectsState struct {
	proj viewport // the project rows, followed by name
	prob viewport // the problems of the selected project, followed by field and message
	fix  *fixState
}

// problemRoom is how many problems the project panel shows at once.
const problemRoom = 5

func problemID(i projectfile.Issue) string { return i.Field + "\x00" + i.Message }

// refitProjects takes the rows of a new snapshot, or a move to another project:
// the problem cursor starts over when the project under the cursor changed.
func (m *app) refitProjects(before string) {
	rows := m.data.Projects
	m.prj.proj.refit(len(rows), func(i int) string { return rows[i].Name })
	var probs []projectfile.Issue
	if p, ok := m.selectedProject(); ok {
		probs = p.Problems
	}
	if m.prj.proj.id() != before {
		m.prj.prob.reset(len(probs))
	}
	m.prj.prob.refit(len(probs), func(i int) string { return problemID(probs[i]) })
}

func (m *app) projectsKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.data == nil {
		return m, nil // nothing loaded yet; r retries, q quits
	}
	n := len(m.data.Projects)
	before := m.prj.proj.id()
	if m.prj.proj.handle(k.String()) {
		m.refitProjects(before)
		return m, nil
	}
	switch k.String() {
	case "p", "P":
		if p, ok := m.selectedProject(); ok && len(p.Problems) > 0 {
			d := 1
			if k.String() == "P" {
				d = len(p.Problems) - 1
			}
			m.prj.prob.to((m.prj.prob.at() + d) % len(p.Problems))
		}
	case "f":
		return m, m.startFix()
	case "o":
		return m, m.openEditor()
	case "e", "enter":
		if n == 0 {
			return m, nil
		}
		p := m.data.Projects[m.prj.proj.at()]
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

// projectsPanel lays the selected project out under the list and says how
// many project rows that leaves room for.
func projectsPanel(rows []projectRow, st *projectsState, w, h int) (detail []string, room int) {
	if len(rows) == 0 {
		return nil, 1
	}
	detail = projectDetail(rows[st.proj.at()], &st.prob, w)
	detailH := 0
	if h > 14 {
		detailH = len(detail) + 1
	}
	return detail, max(h-1-detailH, 1)
}

// renderProjects lists the projects with their declared technologies and the
// number of lockfiles, and below the list the selected project in full.
func renderProjects(rows []projectRow, st *projectsState, w, h int) []string {
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

	detail, room := projectsPanel(rows, st, w, h)
	start, end := st.proj.window(room)
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
		if i == st.proj.at() {
			lines = append(lines, stSel.Render(pad("> "+cells, w)))
		} else {
			lines = append(lines, "  "+cells)
		}
	}
	if h > 14 {
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

func projectDetail(p projectRow, prob *viewport, w int) []string {
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
	out = append(out, problemLines(p.Problems, prob, w)...)
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
// its fix underneath. At most problemRoom are shown, the selected one among them.
func problemLines(issues []projectfile.Issue, prob *viewport, w int) []string {
	if len(issues) == 0 {
		return nil
	}
	sel := prob.at()
	start, end := prob.window(problemRoom)
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
