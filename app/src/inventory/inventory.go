// Package inventory answers "what runs in this project and environment". It
// merges declared techs (generic, with the differences of each environment), lockfiles and SBOMs
// into one relevance.Target per project environment, and keeps the problems it
// met so doctor can show them. Lockfiles are read once per load.
package inventory

import (
	"fmt"
	"time"

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
	Env     model.Env // the environment the source is for; empty for all
	Err     string    // the source could not be read at all
	Skipped []string  // entries that were read but could not be used
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
				inv.problems = append(inv.problems, Problem{Project: p.Name, Path: lf.Path, Type: lf.Type, Env: lf.Env, Err: err.Error()})
				continue
			case len(res.Skipped) > 0:
				inv.problems = append(inv.problems, Problem{Project: p.Name, Path: lf.Path, Type: lf.Type, Env: lf.Env, Skipped: res.Skipped})
			}
			files = append(files, loaded{lf, res.Packages})
			inv.sources = append(inv.sources, Source{Project: p.Name, Type: lf.Type, Path: lf.Path, Env: lf.Env, Packages: len(res.Packages)})
		}

		for _, env := range p.EffectiveEnvs() {
			tg := relevance.Target{Project: p.Name, Env: env, Techs: p.TechsIn(env), Image: p.Environments[env].Image, Since: p.Since}
			seen := map[string]bool{}
			for _, f := range files {
				if f.lf.Env != "" && f.lf.Env != env {
					continue
				}
				for _, pkg := range f.pkg {
					if pkg.Dev && !f.lf.Dev && !model.IsDevLike(env) {
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

// Targets lists every project environment.
func (i *Inventory) Targets() []relevance.Target { return i.targets }

// Within applies the alert horizon at now: items published outside it are not
// judged for any target. It returns the inventory for chaining.
func (i *Inventory) Within(h config.Horizon, now time.Time) *Inventory {
	from, to := h.Range(now)
	for k := range i.targets {
		i.targets[k].Horizon = relevance.Window{From: from, To: to}
	}
	return i
}

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

// Unreadable lists the paths of the lockfiles and SBOMs of a project
// environment that could not be read at all. What they hold is then unknown,
// which is not the same as absent.
func (i *Inventory) Unreadable(project string, env model.Env) []string {
	var out []string
	for _, p := range i.problems {
		if p.Project == project && p.Err != "" && (p.Env == "" || p.Env == env) {
			out = append(out, p.Path)
		}
	}
	return out
}

// Sources lists what was read and how many packages each gave.
func (i *Inventory) Sources() []Source { return i.sources }
