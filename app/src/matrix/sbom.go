package matrix

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/b070nd/cvewatch/app/src/ecosystem"
	"github.com/b070nd/cvewatch/app/src/model"
)

// parsePURL turns a package URL into a package. The error text is a Skipped line.
// fallbackVersion is used when the purl itself has no version.
func parsePURL(purl, fallbackVersion string) (model.Package, error) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(purl), "pkg:")
	if !ok {
		return model.Package{}, fmt.Errorf("%q is not a package URL", short(purl))
	}
	rest = strings.TrimLeft(rest, "/")
	rest, _, _ = strings.Cut(rest, "#") // subpath
	rest, _, _ = strings.Cut(rest, "?") // qualifiers
	typ, path, ok := strings.Cut(rest, "/")
	if !ok {
		return model.Package{}, fmt.Errorf("%q is not a valid package URL", short(purl))
	}
	version := ""
	if i := strings.LastIndex(path, "@"); i > strings.LastIndex(path, "/") {
		path, version = path[:i], path[i+1:]
	}
	var segs []string
	for s := range strings.SplitSeq(path, "/") {
		u, err := url.PathUnescape(s)
		if err != nil {
			return model.Package{}, fmt.Errorf("%q is not a valid package URL", short(purl))
		}
		segs = append(segs, u)
	}
	if version, ok = unescape(version); !ok {
		return model.Package{}, fmt.Errorf("%q is not a valid package URL", short(purl))
	}
	eco, ok := ecosystem.FromPURL(typ)
	if !ok {
		return model.Package{}, fmt.Errorf("%q has an unsupported package type %q", short(purl), typ)
	}
	if version == "" {
		version = strings.TrimSpace(fallbackVersion)
	}
	if version == "" {
		return model.Package{}, fmt.Errorf("%q has no version", short(purl))
	}
	name := segs[len(segs)-1]
	namespace := strings.Join(segs[:len(segs)-1], "/")
	switch {
	case name == "":
		return model.Package{}, fmt.Errorf("%q has no name", short(purl))
	case eco == model.EcoMaven && namespace != "":
		name = namespace + ":" + name
	case eco == model.EcoMaven:
		return model.Package{}, fmt.Errorf("%q has no group", short(purl))
	case namespace != "":
		name = namespace + "/" + name
	}
	if eco == model.EcoComposer {
		version = strings.TrimPrefix(version, "v")
	}
	return model.Package{Name: name, Version: version, Ecosystem: eco}, nil
}

func unescape(s string) (string, bool) {
	u, err := url.PathUnescape(s)
	return u, err == nil
}

type cdxBOM struct {
	Components []cdxComponent `json:"components"`
}

type cdxComponent struct {
	Name       string         `json:"name"`
	Version    string         `json:"version"`
	PURL       string         `json:"purl"`
	Scope      string         `json:"scope"`
	Components []cdxComponent `json:"components"`
}

// parseCycloneDX reads a CycloneDX JSON BOM, including nested components.
func parseCycloneDX(data []byte) (Result, error) {
	var bom cdxBOM
	if err := json.Unmarshal(data, &bom); err != nil {
		return Result{}, err
	}
	var res Result
	var walk func([]cdxComponent)
	walk = func(comps []cdxComponent) {
		for _, c := range comps {
			if c.PURL == "" {
				res.Skipped = append(res.Skipped, fmt.Sprintf("component %q has no purl", short(c.Name)))
			} else if p, err := parsePURL(c.PURL, c.Version); err != nil {
				res.Skipped = append(res.Skipped, "component "+err.Error())
			} else {
				p.Dev = strings.EqualFold(c.Scope, "excluded")
				res.Packages = append(res.Packages, p)
			}
			walk(c.Components)
		}
	}
	walk(bom.Components)
	return res, nil
}

type spdxDoc struct {
	Packages []struct {
		Name         string `json:"name"`
		VersionInfo  string `json:"versionInfo"`
		ExternalRefs []struct {
			ReferenceType    string `json:"referenceType"`
			ReferenceLocator string `json:"referenceLocator"`
		} `json:"externalRefs"`
	} `json:"packages"`
}

// parseSPDX reads an SPDX JSON document; packages are identified by their purl external reference.
func parseSPDX(data []byte) (Result, error) {
	var doc spdxDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return Result{}, err
	}
	var res Result
	for _, sp := range doc.Packages {
		purl := ""
		for _, r := range sp.ExternalRefs {
			if strings.EqualFold(r.ReferenceType, "purl") && r.ReferenceLocator != "" {
				purl = r.ReferenceLocator
				break
			}
		}
		if purl == "" {
			res.Skipped = append(res.Skipped, fmt.Sprintf("package %q has no purl", short(sp.Name)))
			continue
		}
		p, err := parsePURL(purl, sp.VersionInfo)
		if err != nil {
			res.Skipped = append(res.Skipped, "package "+err.Error())
			continue
		}
		res.Packages = append(res.Packages, p)
	}
	return res, nil
}
