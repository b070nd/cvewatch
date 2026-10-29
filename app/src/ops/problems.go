package ops

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strings"

	"github.com/b070nd/cvewatch/app/src/inventory"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/projectfile"
)

// ProjectProblems lists what is wrong with project files, each with the edits
// that would fix it. An empty project means every file the actor may see.
func (s *Session) ProjectProblems(project string) ([]projectfile.Issue, error) {
	names := []string{project}
	if project == "" {
		var err error
		if names, err = s.ProjectNames(); err != nil {
			return nil, err
		}
	} else if err := s.mayRead(project); err != nil {
		return nil, err
	}
	var problems []inventory.Problem
	if len(names) > 0 {
		problems = inventory.Load(s.Cfg).Problems()
	}
	var out []projectfile.Issue
	seen := map[[3]string]bool{}
	for _, name := range names {
		issues, err := s.fileProblems(name, problems)
		if err != nil {
			return nil, err
		}
		for _, i := range issues {
			i.Project = name
			if key := [3]string{name, i.Field, i.Message}; !seen[key] {
				seen[key] = true
				out = append(out, i)
			}
		}
	}
	slices.SortStableFunc(out, func(a, b projectfile.Issue) int {
		return strings.Compare(levelRank(a.Level)+a.Project+"\x00"+a.Field, levelRank(b.Level)+b.Project+"\x00"+b.Field)
	})
	return out, nil
}

func levelRank(level string) string {
	if level == "error" {
		return "0"
	}
	return "1"
}

func (s *Session) fileProblems(name string, problems []inventory.Problem) ([]projectfile.Issue, error) {
	path, err := projectfile.Path(s.projectsDir(), name)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("no project file for %q", name)
	}
	if err != nil {
		return []projectfile.Issue{{Level: "error", Field: "file", Message: err.Error()}}, nil
	}
	f, err := projectfile.Parse(data)
	if err != nil {
		return []projectfile.Issue{{Level: "error", Field: "file", Message: err.Error()}}, nil
	}
	p := f.Project()
	issues := f.ValidateCatalog(s.Cfg.Catalog)
	missing := map[string]bool{}
	for _, i := range projectfile.CheckFiles(p, s.Cfg.Root) {
		missing[i.Field] = true
		issues = append(issues, i)
	}
	for _, pr := range problems {
		if pr.Project != p.Name {
			continue
		}
		issue := projectfile.Issue{Level: "warning", Field: "lockfiles",
			Message: fmt.Sprintf("%d entries of lockfile %s were skipped", len(pr.Skipped), pr.Path)}
		var lock model.Lockfile
		for i, l := range p.Lockfiles {
			if l.Type == pr.Type && projectfile.ResolvePath(s.Cfg.Root, l.Path) == pr.Path {
				issue.Field, lock = fmt.Sprintf("lockfiles[%d]", i), l
				issue.Message = fmt.Sprintf("%d entries of lockfile %s were skipped", len(pr.Skipped), l.Path)
				break
			}
		}
		if pr.Err != "" {
			if missing[issue.Field+".path"] {
				continue
			}
			issue.Level = "error"
			issue.Message = fmt.Sprintf("lockfile %s could not be read: %s", pr.Path, pr.Err)
			if lock.Path != "" {
				issue.Fixes = []projectfile.Fix{projectfile.RemoveLockfileFix(lock)}
			}
		}
		issues = append(issues, issue)
	}
	return issues, nil
}
