// Package ecosystem is the one place that knows how package managers name
// things: which spellings mean the same ecosystem, and how a package name is
// normalized so the same package matches across lockfiles, SBOMs and advisories.
package ecosystem

import (
	"regexp"
	"strings"

	"github.com/b070nd/cvewatch/app/src/model"
)

var aliases = map[string]string{
	"composer": model.EcoComposer, "packagist": model.EcoComposer,
	"npm": model.EcoNPM,
	"go":  model.EcoGo, "golang": model.EcoGo,
	"pypi": model.EcoPyPI, "pip": model.EcoPyPI, "python": model.EcoPyPI,
	"maven": model.EcoMaven, "gradle": model.EcoMaven,
	"cpe": model.EcoCPE,
}

// Canonical maps any known spelling (GitHub's "pip", a purl's "golang", a
// lockfile's "packagist") to the one name used inside cvewatch. Unknown
// ecosystems come back lowercased, so they still compare equal to themselves.
func Canonical(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	if c, ok := aliases[n]; ok {
		return c
	}
	return n
}

// Known reports whether cvewatch can compare versions and names for the ecosystem.
func Known(name string) bool {
	_, ok := aliases[strings.ToLower(strings.TrimSpace(name))]
	return ok
}

var pypiSeparators = regexp.MustCompile(`[-_.]+`)

// NormalizeName gives a package name its canonical form for matching:
// lowercase everywhere, PEP 503 normalization for PyPI (runs of - _ . become
// one -), and group:artifact for Maven. Go module paths are lowercased too,
// because advisories are not consistent about case.
func NormalizeName(eco, name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	switch Canonical(eco) {
	case model.EcoPyPI:
		return pypiSeparators.ReplaceAllString(n, "-")
	case model.EcoMaven:
		return strings.ReplaceAll(n, "/", ":") // some sources write group/artifact
	}
	return n
}

// FromPURL maps a package URL type ("pkg:pypi/requests@2.31.0") to an ecosystem.
// The second result is false for types cvewatch does not handle (deb, rpm, ...).
func FromPURL(purlType string) (string, bool) {
	switch strings.ToLower(purlType) {
	case "composer":
		return model.EcoComposer, true
	case "npm":
		return model.EcoNPM, true
	case "golang":
		return model.EcoGo, true
	case "pypi":
		return model.EcoPyPI, true
	case "maven":
		return model.EcoMaven, true
	}
	return "", false
}
