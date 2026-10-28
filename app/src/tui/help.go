package tui

// helpView lists the keys. The current screen's keys come first.
func helpView(scr screen, inForm bool) []string {
	out := []string{section("Keys"), ""}
	add := func(k, what string) { out = append(out, "  "+pad(k, 14)+what) }

	switch {
	case inForm:
		out[0] = section("Keys in the project form")
		add("enter", "accept the answer and go on")
		add("esc", "go back one step; on the first step leave without saving")
		add("up/down", "move in a list")
		add("space", "tick or untick in a checklist (a: all or none)")
		add("y / n", "answer a yes/no question; y on the last step saves the file")
		add("d, ctrl+d", "scan a folder and merge what it finds (ctrl+d also while typing)")
	case scr == scrFindings:
		out[0] = section("Keys on the findings screen")
		add("up/down", "move (pgup/pgdn, g/G for the ends)")
		add("enter", "open the selected issue")
		add("s", "cycle the minimum severity: all, low+, medium+, high+, critical+")
		add("/", "filter by words or fields such as severity:high; esc clears")
		add("in an issue", "up/down pick an environment; f fixed, i ignore, n not-affected,")
		add("", "o reopen, a assign owner, due date and ticket; capitals (F I N O A)")
		add("", "act on every environment of the project; esc goes back")
		add("", "not-affected needs a reason; ops checks everything and says why it refuses")
	case scr == scrProjects:
		out[0] = section("Keys on the projects screen")
		add("up/down", "move")
		add("e, enter", "edit the selected project (technologies, versions, lockfiles, environments)")
		add("n", "new project")
		add("d", "new project from a folder: it is scanned and proposals are offered")
	}
	out = append(out, "", section("Everywhere"))
	add("1 2 3 4", "Overview, Findings, Projects, Status (tab and shift+tab cycle)")
	add("r", "refresh now (it also refreshes by itself)")
	add("?", "show or hide this help")
	add("q, ctrl+c", "quit")
	out = append(out, "", "  Severities and health levels are always written out as words,",
		"  so nothing depends on colour. Set NO_COLOR to turn colour off.")
	return out
}
