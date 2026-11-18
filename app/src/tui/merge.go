package tui

import (
	"errors"
	"path/filepath"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/b070nd/cvewatch/app/src/model"
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
		var differs *mergeDiffersMsg
		err := b.Read(func(s *ops.Session) error {
			o, err := projectflow.Open(s, projectflow.Request{Project: project, Folder: path, IncludeIgnored: namesAFile(path)})
			if err != nil {
				return err
			}
			edits := projectflow.Edits(s, o.Flow)
			if len(edits) == 0 {
				if d := projectflow.VersionDiffs(s, project, path); len(d) > 0 {
					differs = &mergeDiffersMsg{project: project, path: path, diffs: d}
					return nil
				}
				return errors.New("nothing new: what " + oneLine(path) + " names is already in the project")
			}
			fx.fix.Ops, fx.techs = edits, o.Flow.Custom()
			prev, err = s.EditProject(ops.ProjectChange{Project: project, Ops: edits, NewTechs: fx.techs})
			return err
		})
		if differs != nil {
			return *differs
		}
		return editCheckedMsg{fx: fx, prev: prev, seen: seen, err: err}
	}
}

type mergeDiffersMsg struct {
	project, path string
	diffs         []projectflow.VersionDiff
}

// mergeDiffers asks where a version the scan found should apply, when it is not the one the project declares.
func (m *app) mergeDiffers(msg mergeDiffersMsg) outcome {
	p, _, ok := m.fieldCtx()
	if !ok || len(msg.diffs) == 0 {
		return outcome{}
	}
	d := msg.diffs[0]
	pk := &picker{title: oneLine(d.Tech) + ": " + oneLine(filepath.Base(msg.path)) + " says " + d.Found + ", the project says " + d.Have, crumb: "version",
		hint: "enter chooses; nothing is written before you have seen the change"}
	for _, e := range d.Envs {
		pk.items = append(pk.items, pickItem{value: "env:" + string(e), label: "Only in " + string(e), detail: d.Tech + " " + d.Found + " there; the other environments keep " + d.Have})
	}
	pk.items = append(pk.items,
		pickItem{value: "all", label: "Everywhere", detail: "replace " + d.Have + " by " + d.Found + " in every environment"},
		pickItem{value: "keep", label: "Keep the project as it is"})
	pk.done = func(m *app, vals []string) tea.Cmd {
		m.chs = nil
		var op projectfile.Op
		var label string
		switch v := vals[0]; {
		case v == "keep":
			return nil
		case v == "all":
			op, label = projectfile.Op{Kind: projectfile.KindSetTech, Tech: d.Tech, Version: d.Found}, "set "+d.Tech+" to "+d.Found
		default:
			e := model.Env(strings.TrimPrefix(v, "env:"))
			op, label = projectfile.Op{Kind: projectfile.KindSetEnvTech, Env: e, Tech: d.Tech, Version: d.Found}, "set "+d.Tech+" to "+d.Found+" in "+string(e)
		}
		return m.previewEdit(msg.project, p.Problems, label, []projectfile.Op{op}, "", nil)
	}
	m.choose(pk)
	return outcome{}
}

// namesAFile is true when the typed path is one file: the person named it, so
// .gitignore has no say in whether it is read.
func namesAFile(path string) bool {
	src, err := projectflow.ResolveSource(path)
	return err == nil && src.IsFile()
}
