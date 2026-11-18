package tui

import (
	"errors"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/b070nd/cvewatch/app/src/ops"
	"github.com/b070nd/cvewatch/app/src/projectfile"
	"github.com/b070nd/cvewatch/app/src/projectflow"
)

// fieldScan asks for a folder or file whose stack is merged into the project.
func (m *app) fieldScan() tea.Cmd {
	p, _, ok := m.fieldCtx()
	if !ok {
		return nil
	}
	m.prm = &prompt{kind: pkMerge, project: p.Name, title: "Add inputs to " + oneLine(p.Name),
		hint: "a repository or monorepo folder, or a Dockerfile, compose file, manifest or lockfile; what it names is merged into the project, nothing in it is executed",
		box:  newFolderBox()}
	return nil
}

// previewMerge scans the path and shows what merging it would change in the
// project file.
func (m *app) previewMerge(prm *prompt, path string) tea.Cmd {
	p, _, ok := m.fieldCtx()
	if !ok {
		prm.problem = "the project is not open any more"
		return nil
	}
	fx := &fixState{project: p.Name, fix: projectfile.Fix{Label: "add the inputs found in " + oneLine(path)}, seq: 1, vp: scrolling(), edit: true}
	seen := map[string]bool{}
	for _, i := range p.Problems {
		seen[problemID(i)] = true
	}
	return m.start("scanning...", "merge "+p.Name, 0, prm, mergeCheckCmd(m.b, fx, p.Name, path, seen))
}

func mergeCheckCmd(b Backend, fx *fixState, project, path string, seen map[string]bool) tea.Cmd {
	return func() tea.Msg {
		var prev ops.ProjectPreview
		err := b.Read(func(s *ops.Session) error {
			o, err := projectflow.Open(s, projectflow.Request{Project: project, Folder: path})
			if err != nil {
				return err
			}
			edits := projectflow.Edits(s, o.Flow)
			if len(edits) == 0 {
				return errors.New("nothing new: what " + oneLine(path) + " names is already in the project")
			}
			fx.fix.Ops, fx.techs = edits, o.Flow.Custom()
			prev, err = s.EditProject(ops.ProjectChange{Project: project, Ops: edits, NewTechs: fx.techs})
			return err
		})
		return editCheckedMsg{fx: fx, prev: prev, seen: seen, err: err}
	}
}
