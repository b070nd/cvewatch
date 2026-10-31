package ops

import (
	"fmt"
	"slices"
	"strings"

	"github.com/b070nd/cvewatch/app/src/status"
)

// healthProblems are the problems of Status that only the session can see:
// project files that cannot be used, an unreadable inventory, a damaged audit
// log. A project becomes one problem, whatever number of messages it has.
func (s *Session) healthProblems(visible []string) []status.Problem {
	var out []status.Problem
	messages := map[string][]string{}
	var order []string
	add := func(project, msg string) {
		if len(visible) > 0 && !slices.Contains(visible, project) {
			return
		}
		if _, ok := messages[project]; !ok {
			order = append(order, project)
		}
		if !slices.Contains(messages[project], msg) {
			messages[project] = append(messages[project], msg)
		}
	}
	for _, b := range s.Cfg.Broken {
		add(b.Name, strings.TrimPrefix(b.Err, b.File+": "))
	}
	issues, err := s.ProjectProblems("")
	if err != nil {
		out = append(out, status.Problem{Key: "projects", Level: status.Yellow, Title: "the project files cannot be checked", Detail: err.Error(),
			Hint: "check that the config/projects folder is readable"})
	}
	for _, i := range issues {
		if i.Level == "error" {
			add(i.Project, i.Message)
		}
	}
	for _, name := range order {
		msgs := messages[name]
		detail := strings.Join(msgs[:min(3, len(msgs))], "; ")
		if len(msgs) > 3 {
			detail += fmt.Sprintf("; and %d more", len(msgs)-3)
		}
		out = append(out, status.Problem{Key: "project:" + name, Level: status.Yellow, Title: "project " + name + " cannot be used fully",
			Detail: detail, Hint: "the Projects screen of the TUI and the check_projects tool list the problems and the fixes; cvewatch inventory -project " + name + " shows what was read"})
	}
	if _, err := s.Audit.Verify(); err != nil {
		out = append(out, status.Problem{Key: "audit", Level: status.Red, Title: "the audit log is damaged", Detail: err.Error(),
			Hint: "restore audit.log from a backup, or move it aside to start a new chain; cvewatch audit shows where it breaks"})
	}
	return out
}
