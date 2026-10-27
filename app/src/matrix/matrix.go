// Package matrix reads lockfiles into the package list used for tech matching.
package matrix

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/b070nd/cvewatch/app/src/model"
)

// maxLockfile bounds what we parse; real lockfiles are a few MiB.
const maxLockfile = 64 << 20

// Load reads a lockfile and returns its packages, deduplicated and sorted by name, then version.
func Load(l model.Lockfile) ([]model.Package, error) {
	var parse func([]byte) ([]model.Package, error)
	switch l.Type {
	case "composer":
		parse = parseComposer
	case "npm":
		parse = parseNPM
	default:
		return nil, fmt.Errorf("matrix: %s: unknown lockfile type %q", l.Path, l.Type)
	}

	if fi, err := os.Stat(l.Path); err == nil && fi.Size() > maxLockfile {
		return nil, fmt.Errorf("matrix: %s is larger than %d MiB", l.Path, maxLockfile>>20)
	}
	data, err := os.ReadFile(l.Path)
	if err != nil {
		return nil, fmt.Errorf("matrix: read %s: %w", l.Path, err)
	}
	pkgs, err := parse(data)
	if err != nil {
		return nil, fmt.Errorf("matrix: parse %s: %w", l.Path, err)
	}
	return normalize(pkgs), nil
}

type composerLock struct {
	Packages    []composerPkg `json:"packages"`
	PackagesDev []composerPkg `json:"packages-dev"`
}

type composerPkg struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func parseComposer(data []byte) ([]model.Package, error) {
	var lock composerLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}
	var out []model.Package
	for _, p := range slices.Concat(lock.Packages, lock.PackagesDev) {
		out = append(out, model.Package{Name: p.Name, Version: strings.TrimPrefix(p.Version, "v"), Ecosystem: "composer"})
	}
	return out, nil
}

type npmLock struct {
	LockfileVersion int                 `json:"lockfileVersion"`
	Packages        map[string]npmPkg   `json:"packages"`
	Dependencies    map[string]npmDepV1 `json:"dependencies"`
}

type npmPkg struct {
	Version string `json:"version"`
}

type npmDepV1 struct {
	Version      string              `json:"version"`
	Dependencies map[string]npmDepV1 `json:"dependencies"`
}

func parseNPM(data []byte) ([]model.Package, error) {
	var lock npmLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}
	if lock.LockfileVersion < 2 {
		return walkV1(lock.Dependencies, nil), nil
	}
	var out []model.Package
	for key, p := range lock.Packages {
		// The name is whatever follows the last node_modules/; the root "" key has none.
		i := strings.LastIndex(key, "node_modules/")
		if i < 0 || p.Version == "" {
			continue
		}
		out = append(out, model.Package{Name: key[i+len("node_modules/"):], Version: p.Version, Ecosystem: "npm"})
	}
	return out, nil
}

func walkV1(deps map[string]npmDepV1, out []model.Package) []model.Package {
	for name, d := range deps {
		if d.Version != "" {
			out = append(out, model.Package{Name: name, Version: d.Version, Ecosystem: "npm"})
		}
		out = walkV1(d.Dependencies, out)
	}
	return out
}

// normalize lowercases names, drops duplicate name+version pairs and sorts the rest.
func normalize(pkgs []model.Package) []model.Package {
	type key struct{ name, version string }
	seen := make(map[key]bool, len(pkgs))
	out := pkgs[:0]
	for _, p := range pkgs {
		p.Name = strings.ToLower(p.Name)
		k := key{p.Name, p.Version}
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, p)
	}
	slices.SortFunc(out, func(a, b model.Package) int {
		if c := strings.Compare(a.Name, b.Name); c != 0 {
			return c
		}
		return strings.Compare(a.Version, b.Version)
	})
	return out
}
