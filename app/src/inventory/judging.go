package inventory

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/model"
)

// Judging fingerprints every input of the judgement: per project its
// environments, start date, techs with versions per environment, lockfile
// packages and the catalog terms of the techs it uses, plus the alert horizon.
// Comments, key order and anything else in the files do not count. at is when
// the findings are judged against it.
func (i *Inventory) Judging(cfg *config.Bundle, at time.Time) model.Judging {
	j := model.Judging{At: at, Horizon: horizonKey(cfg.Horizon), Projects: map[string]model.JudgedProject{}}
	defs := map[string]model.Tech{}
	for _, t := range cfg.Techs {
		defs[strings.ToLower(t.Name)] = t
	}
	for _, p := range cfg.Projects {
		h := sha256.New()
		since := p.Since.UTC()
		fmt.Fprintf(h, "project %s\nsince %s\n", p.Name, sinceKey(since))
		envs := slices.Clone(p.EffectiveEnvs())
		model.SortEnvs(envs)
		names := map[string]bool{}
		for _, env := range envs {
			tg, ok := i.Target(p.Name, env)
			if !ok {
				continue
			}
			var techs, pkgs []string
			for _, t := range tg.Techs {
				n := strings.ToLower(t.Name)
				names[n] = true
				techs = append(techs, n+"@"+t.Version)
			}
			for _, pk := range tg.Packages {
				pkgs = append(pkgs, pk.Ecosystem+"|"+pk.Name+"|"+pk.Version)
			}
			slices.Sort(techs)
			slices.Sort(pkgs)
			fmt.Fprintf(h, "env %s\ntechs %s\npackages %s\n", env, strings.Join(techs, ","), strings.Join(pkgs, ","))
		}
		used := make([]string, 0, len(names))
		for n := range names {
			used = append(used, n)
		}
		slices.Sort(used)
		for _, n := range used {
			t, ok := defs[n]
			fmt.Fprintf(h, "tech %s known=%v scheme=%s terms=%s excludes=%s cpe=%s\n", n, ok, t.Scheme,
				strings.Join(sorted(t.Terms()), ","), strings.Join(sorted(t.Excludes), ","), strings.Join(sorted(t.CPE), ","))
		}
		j.Projects[p.Name] = model.JudgedProject{Hash: hex.EncodeToString(h.Sum(nil)[:12]), Since: since, Techs: used}
	}
	all := sha256.New()
	fmt.Fprintf(all, "horizon %s\n", j.Horizon)
	for _, name := range sortedKeys(j.Projects) {
		fmt.Fprintf(all, "%s %s\n", name, j.Projects[name].Hash)
	}
	j.Hash = hex.EncodeToString(all.Sum(nil)[:12])
	return j
}

func sorted(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.ToLower(strings.TrimSpace(s))
	}
	slices.Sort(out)
	return out
}

func sortedKeys(m map[string]model.JudgedProject) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func sinceKey(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Format(time.RFC3339)
}

func horizonKey(h config.Horizon) string {
	w := h.Window
	if w == "" {
		w = config.WindowUnlimited
	}
	if w != config.WindowCustom {
		return w // from and to are ignored by every other window
	}
	return w + " " + h.From + " " + h.To
}

// Delta says how the current judging inputs differ from the recorded ones.
type Delta struct {
	Never    bool      // nothing was recorded yet
	Changed  []string  // projects added, removed or with different inputs, sorted
	Horizon  bool      // the alert horizon differs
	Backfill time.Time // the earliest start of the history the change needs; zero when none
}

// Stale reports whether the findings were judged against something else.
func (d Delta) Stale() bool { return d.Never || d.Horizon || len(d.Changed) > 0 }

// Compare tells what changed between the recorded judging and the current one.
// A nil prev means nothing was recorded, which counts as everything changed.
func Compare(prev *model.Judging, cur model.Judging, h config.Horizon, now time.Time) Delta {
	var d Delta
	d.Never = prev == nil
	if prev != nil {
		d.Horizon = prev.Horizon != cur.Horizon
		for name, p := range cur.Projects {
			if old, ok := prev.Projects[name]; !ok || old.Hash != p.Hash {
				d.Changed = append(d.Changed, name)
			}
		}
		for name := range prev.Projects {
			if _, ok := cur.Projects[name]; !ok {
				d.Changed = append(d.Changed, name)
			}
		}
	} else {
		for name := range cur.Projects {
			d.Changed = append(d.Changed, name)
		}
	}
	slices.Sort(d.Changed)
	for name, p := range cur.Projects {
		if !d.Horizon && !slices.Contains(d.Changed, name) {
			continue
		}
		if s := Start(p.Since, h, now); !s.IsZero() && (d.Backfill.IsZero() || s.Before(d.Backfill)) {
			d.Backfill = s
		}
	}
	return d
}

// Start is the earliest publication date a project judges: the later of its
// since date and the start of the alert horizon. Zero means no start, so no
// history beyond what the sources deliver anyway is wanted.
func Start(since time.Time, h config.Horizon, now time.Time) time.Time {
	from, _ := h.Range(now)
	if since.After(from) {
		return since
	}
	return from
}
