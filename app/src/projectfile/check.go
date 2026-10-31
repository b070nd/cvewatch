package projectfile

import (
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/b070nd/cvewatch/app/src/catalog"
	"github.com/b070nd/cvewatch/app/src/matrix"
	"github.com/b070nd/cvewatch/app/src/model"
)

// CheckFiles looks at the files a project points to. Relative lockfile paths
// follow root, like the configuration loader does.
func CheckFiles(p model.Project, root string) []Issue {
	var issues []Issue
	types := matrix.Types()
	for i, l := range p.Lockfiles {
		if strings.TrimSpace(l.Path) == "" {
			continue
		}
		field := fmt.Sprintf("lockfiles[%d]", i)
		if _, err := os.Stat(ResolvePath(root, l.Path)); errors.Is(err, fs.ErrNotExist) {
			issues = append(issues, Issue{Level: "error", Field: field + ".path",
				Message: fmt.Sprintf("lockfile %s does not exist", l.Path), Fixes: []Fix{RemoveLockfileFix(l)}})
		}
		if to, ok := matrix.DetectType(filepath.Base(l.Path)); ok && to != l.Type && slices.Contains(types, l.Type) {
			var fixes []Fix
			if fix, ok := retypeLockfile(p, l); ok {
				fixes = []Fix{fix}
			}
			issues = append(issues, Issue{Level: "warning", Field: field + ".type",
				Message: fmt.Sprintf("lockfile %s is declared as %q but its file name looks like %q", l.Path, l.Type, to), Fixes: fixes})
		}
	}
	return issues
}

// ResolvePath makes a lockfile path absolute against root, as the configuration loader does.
func ResolvePath(root, p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Clean(filepath.Join(root, p))
}

// Suggest returns the one known name closest to name, if it is a near miss
// (a couple of typing errors, ignoring case) and no other name is as close.
func Suggest(name string, known []string) (string, bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	limit := 2
	if len([]rune(name)) <= 3 {
		limit = 1
	}
	best, bestDist, tied := "", limit+1, false
	for _, k := range known {
		d := catalog.EditDistance(name, strings.ToLower(k))
		switch {
		case d == 0:
			return "", false
		case d < bestDist:
			best, bestDist, tied = k, d, false
		case d == bestDist && k != best:
			tied = true
		}
	}
	return best, bestDist <= limit && !tied
}

// RemoveLockfileFix drops the lockfile entry l.
func RemoveLockfileFix(l model.Lockfile) Fix {
	label := "remove lockfile " + l.Path
	if l.Env.Valid() {
		label += " for " + string(l.Env)
	}
	return Fix{Label: label, Ops: []Op{removeOp(l)}}
}

func removeOp(l model.Lockfile) Op {
	op := Op{Kind: "remove_lockfile", Lockfile: model.Lockfile{Path: l.Path}}
	if l.Env.Valid() {
		op.Lockfile.Env = l.Env
	}
	return op
}

func sharedPath(p model.Project, l model.Lockfile) bool {
	n := 0
	for _, o := range p.Lockfiles {
		if o.Path == l.Path {
			n++
		}
	}
	return n > 1
}

// retypeLockfile replaces the type of l with the one its file name stands for.
func retypeLockfile(p model.Project, l model.Lockfile) (Fix, bool) {
	to, ok := matrix.DetectType(filepath.Base(l.Path))
	if !ok || !slices.Contains(matrix.Types(), to) || to == l.Type || l.Env != "" && !l.Env.Valid() || l.Env == "" && sharedPath(p, l) {
		return Fix{}, false
	}
	add := l
	add.Type = to
	return Fix{
		Label: fmt.Sprintf("use lockfile type %q for %s instead of %q", to, l.Path, l.Type),
		Ops:   []Op{removeOp(l), {Kind: "add_lockfile", Lockfile: add}},
	}, true
}

func enableEnvFix(p model.Project, e model.Env) Fix {
	envs := append(slices.Clone(p.EffectiveEnvs()), e)
	return Fix{Label: "monitor environment " + string(e), Ops: []Op{{Kind: "set_envs", Envs: envs}}}
}

func renameTech(p model.Project, t model.ProjectTech, to string) []Fix {
	label := fmt.Sprintf("use technology name %q instead of %q", to, t.Name)
	ops := []Op{{Kind: "remove_tech", Tech: t.Name}}
	if slices.ContainsFunc(p.Techs, func(o model.ProjectTech) bool { return strings.EqualFold(o.Name, to) }) {
		label = fmt.Sprintf("remove technology %q, %q is already listed", t.Name, to)
	} else {
		ops = append(ops, Op{Kind: "set_tech", Tech: to, Version: t.Version})
	}
	return []Fix{{Label: label, Ops: ops}}
}

func renameEnvTech(p model.Project, e model.Env, name, to string) []Fix {
	version := p.Environments[e].Techs[name]
	if !e.Valid() || version == "" {
		return nil
	}
	label := fmt.Sprintf("use technology name %q instead of %q in %s", to, name, e)
	ops := []Op{{Kind: "remove_env_tech", Env: e, Tech: name}}
	if slices.ContainsFunc(slices.Collect(maps.Keys(p.Environments[e].Techs)), func(o string) bool { return strings.EqualFold(o, to) }) {
		label = fmt.Sprintf("remove technology %q from %s, %q is already set there", name, e, to)
	} else {
		ops = append(ops, Op{Kind: "set_env_tech", Env: e, Tech: to, Version: version})
	}
	return []Fix{{Label: label, Ops: ops}}
}
