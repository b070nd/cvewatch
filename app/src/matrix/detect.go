package matrix

import (
	"slices"
	"strings"
)

// fileTypes maps well-known file names to the lockfile type that reads them.
// Discovery uses it so the list of recognised files lives next to the parsers.
var fileTypes = map[string]string{
	"composer.lock":     "composer",
	"package-lock.json": "npm",
	"go.mod":            "go",
	"requirements.txt":  "pip",
	"poetry.lock":       "poetry",
	"pipfile.lock":      "pipfile",
	"gradle.lockfile":   "gradle",
	"pom.xml":           "maven",
	"bom.json":          "cyclonedx",
	"sbom.json":         "cyclonedx",
}

// DetectType returns the lockfile type for a file name (not a path), or false
// if cvewatch has no reader for it. Matching ignores case.
func DetectType(base string) (string, bool) {
	b := strings.ToLower(base)
	if t, ok := fileTypes[b]; ok {
		return t, true
	}
	switch {
	case strings.HasSuffix(b, ".cdx.json"):
		return "cyclonedx", true
	case strings.HasSuffix(b, ".spdx.json"):
		return "spdx", true
	}
	return "", false
}

// FileNames lists the fixed file names DetectType knows, sorted, for help text.
func FileNames() []string {
	out := make([]string, 0, len(fileTypes))
	for n := range fileTypes {
		out = append(out, n)
	}
	slices.Sort(out)
	return out
}
