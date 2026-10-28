// Package matrix reads lockfiles into the package list used for tech matching.
package matrix

import (
	"cmp"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"

	"github.com/b070nd/cvewatch/app/src/ecosystem"
	"github.com/b070nd/cvewatch/app/src/model"
)

// maxLockfile bounds what we parse; real lockfiles are a few MiB.
const maxLockfile = 64 << 20

// maxSkipped caps how many Skipped lines a Result keeps.
const maxSkipped = 50

// Result is what one lockfile yields: the usable packages and a short
// plain-English line for every entry that was ignored because it cannot be used.
type Result struct {
	Packages []model.Package
	Skipped  []string
}

type parser func(data []byte) (Result, error)

// parsers maps a lockfile type (the `type:` value in a project file) to its parser.
var parsers = map[string]parser{
	"composer":  parseComposer,
	"npm":       parseNPM,
	"go":        parseGoMod,
	"pip":       parseRequirements,
	"poetry":    parsePoetry,
	"pipfile":   parsePipfileLock,
	"gradle":    parseGradleLock,
	"maven":     parsePOM,
	"cyclonedx": parseCycloneDX,
	"spdx":      parseSPDX,
}

// Types lists the supported lockfile types, sorted.
func Types() []string { return slices.Sorted(maps.Keys(parsers)) }

// Load reads a lockfile and returns its packages, deduplicated and sorted by name, then version.
func Load(l model.Lockfile) ([]model.Package, error) {
	res, err := LoadResult(l)
	return res.Packages, err
}

// LoadResult is Load plus the entries that were ignored and why.
func LoadResult(l model.Lockfile) (Result, error) {
	parse, ok := parsers[l.Type]
	if !ok {
		return Result{}, fmt.Errorf("matrix: %s: unknown lockfile type %q (valid types: %s)", l.Path, l.Type, strings.Join(Types(), ", "))
	}

	if fi, err := os.Stat(l.Path); err == nil && fi.Size() > maxLockfile {
		return Result{}, fmt.Errorf("matrix: %s is larger than %d MiB", l.Path, maxLockfile>>20)
	}
	data, err := os.ReadFile(l.Path)
	if err != nil {
		return Result{}, fmt.Errorf("matrix: read %s: %w", l.Path, err)
	}
	res, err := parse(data)
	if err != nil {
		return Result{}, fmt.Errorf("matrix: parse %s: %w", l.Path, err)
	}
	res.Packages = normalize(res.Packages)
	res.Skipped = capSkipped(res.Skipped)
	return res, nil
}

func capSkipped(s []string) []string {
	if len(s) <= maxSkipped {
		return s
	}
	out := slices.Clone(s[:maxSkipped])
	return append(out, fmt.Sprintf("... and %d more", len(s)-maxSkipped))
}

// short trims a quoted fragment so one odd line cannot flood a report.
func short(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 80 {
		return s[:77] + "..."
	}
	return s
}

type composerLock struct {
	Packages    []composerPkg `json:"packages"`
	PackagesDev []composerPkg `json:"packages-dev"`
}

type composerPkg struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func parseComposer(data []byte) (Result, error) {
	var lock composerLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return Result{}, err
	}
	var res Result
	add := func(pkgs []composerPkg, dev bool) {
		for _, p := range pkgs {
			res.Packages = append(res.Packages, model.Package{
				Name: p.Name, Version: strings.TrimPrefix(p.Version, "v"), Ecosystem: model.EcoComposer, Dev: dev,
			})
		}
	}
	add(lock.Packages, false)
	add(lock.PackagesDev, true)
	return res, nil
}

type npmLock struct {
	LockfileVersion int                 `json:"lockfileVersion"`
	Packages        map[string]npmPkg   `json:"packages"`
	Dependencies    map[string]npmDepV1 `json:"dependencies"`
}

type npmPkg struct {
	Version string `json:"version"`
	Dev     bool   `json:"dev"`
}

type npmDepV1 struct {
	Version      string              `json:"version"`
	Dev          bool                `json:"dev"`
	Dependencies map[string]npmDepV1 `json:"dependencies"`
}

func parseNPM(data []byte) (Result, error) {
	var lock npmLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return Result{}, err
	}
	if lock.LockfileVersion < 2 {
		return Result{Packages: walkV1(lock.Dependencies, nil)}, nil
	}
	var res Result
	for key, p := range lock.Packages {
		// The name is whatever follows the last node_modules/; the root "" key has none.
		i := strings.LastIndex(key, "node_modules/")
		if i < 0 || p.Version == "" {
			continue
		}
		res.Packages = append(res.Packages, model.Package{Name: key[i+len("node_modules/"):], Version: p.Version, Ecosystem: model.EcoNPM, Dev: p.Dev})
	}
	return res, nil
}

func walkV1(deps map[string]npmDepV1, out []model.Package) []model.Package {
	for name, d := range deps {
		if d.Version != "" {
			out = append(out, model.Package{Name: name, Version: d.Version, Ecosystem: model.EcoNPM, Dev: d.Dev})
		}
		out = walkV1(d.Dependencies, out)
	}
	return out
}

// normalize canonicalizes names, merges duplicate ecosystem+name+version
// entries (the result is Dev only if every copy was) and sorts the rest by
// name, then version.
func normalize(pkgs []model.Package) []model.Package {
	type key struct{ eco, name, version string }
	index := make(map[key]int, len(pkgs))
	var out []model.Package
	for _, p := range pkgs {
		p.Name = ecosystem.NormalizeName(p.Ecosystem, p.Name)
		k := key{p.Ecosystem, p.Name, p.Version}
		if i, ok := index[k]; ok {
			out[i].Dev = out[i].Dev && p.Dev
			continue
		}
		index[k] = len(out)
		out = append(out, p)
	}
	slices.SortFunc(out, func(a, b model.Package) int {
		return cmp.Or(strings.Compare(a.Name, b.Name), strings.Compare(a.Version, b.Version), strings.Compare(a.Ecosystem, b.Ecosystem))
	})
	return out
}
