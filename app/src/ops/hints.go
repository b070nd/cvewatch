package ops

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/b070nd/cvewatch/app/src/projectfile"
)

// ProjectHint is a hint about one project file.
type ProjectHint struct {
	Project string `json:"project"`
	projectfile.Hint
}

// ProjectHints says what may not be covered or cause trouble in project
// files: unknown technologies, missing versions or lockfiles, environments,
// a missing start date. An empty project means every file the actor may see.
// A file that cannot be read has no hints; ProjectProblems reports it.
func (s *Session) ProjectHints(project string) ([]ProjectHint, error) {
	names := []string{project}
	if project == "" {
		var err error
		if names, err = s.ProjectNames(); err != nil {
			return nil, err
		}
	} else if err := s.mayRead(project); err != nil {
		return nil, err
	}
	var own []string
	if mine, err := s.UserTechs(); err == nil {
		for _, t := range mine {
			own = append(own, t.Name)
		}
	}
	out := []ProjectHint{}
	for _, name := range names {
		path, err := s.ProjectFile(name)
		if err != nil {
			return nil, err
		}
		data, err := os.ReadFile(path)
		if errors.Is(err, fs.ErrNotExist) {
			if project != "" {
				return nil, fmt.Errorf("no project file for %q", name)
			}
			continue
		}
		if err != nil {
			return nil, err
		}
		f, err := projectfile.Parse(data)
		if err != nil {
			continue
		}
		for _, h := range f.Hints(projectfile.HintOptions{Catalog: s.Cfg.Catalog, Root: s.Cfg.Root, Own: own}) {
			out = append(out, ProjectHint{Project: name, Hint: h})
		}
	}
	return out, nil
}
