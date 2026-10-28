// Package inventory answers "what runs in this project and environment". It
// merges declared techs (with per-environment versions), lockfiles and SBOMs
// into one relevance.Target per project environment, and keeps the problems it
// met so doctor can show them. Lockfiles are read once per load.
package inventory

import (
	"fmt"
	"slices"
	"strings"

	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/matrix"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/relevance"
)

// Problem is something that kept an inventory source from being used fully.
type Problem struct {
	Project string
	Path    string
	Type    string
	Err     string   // the source could not be read at all
	Skipped []string // entries that were read but could not be used
}

func (p Problem) String() string {
	if p.Err != "" {
		return fmt.Sprintf("%s: %s %s: %s", p.Project, p.Type, p.Path, p.Err)
	}
	return fmt.Sprintf("%s: %s %s: %d entries skipped", p.Project, p.Type, p.Path, len(p.Skipped))
}

// Source is one lockfile or SBOM and what it contributed.
type Source struct {
	Project  string
	Type     string
	Path     string
	Env      model.Env
	Packages int
}

// Inventory holds one target per project environment.
type Inventory struct {
	targets  []relevance.Target
	problems []Problem
	sources  []Source
}

// devEnvs are the environments where development-only packages count by default.
var devEnvs = []model.Env{model.EnvDev, model.EnvInt}

// Load builds the inventory from the configuration, reading every lockfile once.
func Load(cfg *config.Bundle) *Inventory {
	inv := &Inventory{}
	for _, p := range cfg.Projects {
		type loaded struct {
			lf  model.Lockfile
			pkg []model.Package
		}
		var files []loaded
		for _, lf := range p.Lockfiles {
			res, err := matrix.LoadResult(lf)
			switch {
			case err != nil:
				inv.problems = append(inv.problems, Problem{Project: p.Name, Path: lf.Path, Type: lf.Type, Err: err.Error()})
				continue
			case len(res.Skipped) > 0:
				inv.problems = append(inv.problems, Problem{Project: p.Name, Path: lf.Path, Type: lf.Type, Skipped: res.Skipped})
			}
			files = append(files, loaded{lf, res.Packages})
			inv.sources = append(inv.sources, Source{Project: p.Name, Type: lf.Type, Path: lf.Path, Env: lf.Env, Packages: len(res.Packages)})
		}

		for _, env := range p.EffectiveEnvs() {
			tg := relevance.Target{Project: p.Name, Env: env, Techs: techsFor(p, env), Image: p.Environments[env].Image}
			seen := map[string]bool{}
			for _, f := range files {
				if f.lf.Env != "" && f.lf.Env != env {
					continue
				}
				for _, pkg := range f.pkg {
					if pkg.Dev && !f.lf.Dev && !slices.Contains(devEnvs, env) {
						continue
					}
					if k := pkg.Ecosystem + "|" + pkg.Name + "|" + pkg.Version; !seen[k] {
						seen[k] = true
						tg.Packages = append(tg.Packages, pkg)
					}
				}
			}
			inv.targets = append(inv.targets, tg)
		}
	}
	return inv
}

// techsFor applies the environment's deployed versions over the project's declared techs.
func techsFor(p model.Project, env model.Env) []model.ProjectTech {
	out := slices.Clone(p.Techs)
	for name, ver := range p.Environments[env].Techs {
		i := slices.IndexFunc(out, func(t model.ProjectTech) bool { return strings.EqualFold(t.Name, name) })
		if i >= 0 {
			out[i].Version = ver
		} else {
			out = append(out, model.ProjectTech{Name: name, Version: ver})
		}
	}
	return out
}

// Targets lists every project environment.
func (i *Inventory) Targets() []relevance.Target { return i.targets }

// Target returns one project environment.
func (i *Inventory) Target(project string, env model.Env) (relevance.Target, bool) {
	for _, t := range i.targets {
		if t.Project == project && t.Env == env {
			return t, true
		}
	}
	return relevance.Target{}, false
}

// Problems lists sources that failed or were only partly usable.
func (i *Inventory) Problems() []Problem { return i.problems }

// Sources lists what was read and how many packages each gave.
func (i *Inventory) Sources() []Source { return i.sources }
