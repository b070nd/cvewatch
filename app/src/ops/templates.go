package ops

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/projectfile"
)

// ProjectTemplates lists the project templates: the projects/<name>.yaml.dist
// files, which are never loaded as projects. A new project can start from one
// (ProjectChange.Template).
func (s *Session) ProjectTemplates() ([]string, error) {
	files, err := filepath.Glob(filepath.Join(config.ProjectsDir(s.Cfg.Root), "*.yaml"+config.Dist))
	if err != nil {
		return nil, err
	}
	var out []string
	for _, f := range files {
		out = append(out, strings.TrimSuffix(filepath.Base(f), ".yaml"+config.Dist))
	}
	slices.Sort(out)
	return out, nil
}

// fromTemplate reads a template and gives it the project's name.
func (s *Session) fromTemplate(template, name string) (*projectfile.File, error) {
	names, err := s.ProjectTemplates()
	if err != nil {
		return nil, err
	}
	if !slices.Contains(names, template) {
		return nil, fmt.Errorf("no project template %q (the templates are %s)", template, strings.Join(names, ", "))
	}
	data, err := os.ReadFile(filepath.Join(config.ProjectsDir(s.Cfg.Root), template+".yaml"+config.Dist))
	if err != nil {
		return nil, err
	}
	f, err := projectfile.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("template %s: %w", template, err)
	}
	if err := f.SetName(name); err != nil {
		return nil, err
	}
	return f, nil
}
