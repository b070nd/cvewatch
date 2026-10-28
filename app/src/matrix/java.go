package matrix

import (
	"encoding/xml"
	"fmt"
	"regexp"
	"strings"

	"github.com/b070nd/cvewatch/app/src/model"
)

// parseGradleLock reads gradle.lockfile: "group:artifact:version=conf1,conf2" lines.
func parseGradleLock(data []byte) (Result, error) {
	var res Result
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "empty=") {
			continue
		}
		coords, confs, _ := strings.Cut(line, "=")
		parts := strings.Split(coords, ":")
		if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
			res.Skipped = append(res.Skipped, fmt.Sprintf("unreadable gradle lock line %q", short(line)))
			continue
		}
		dev := confs != ""
		for c := range strings.SplitSeq(confs, ",") {
			if !strings.Contains(strings.ToLower(c), "test") {
				dev = false
			}
		}
		res.Packages = append(res.Packages, model.Package{Name: parts[0] + ":" + parts[1], Version: parts[2], Ecosystem: model.EcoMaven, Dev: dev})
	}
	return res, nil
}

type pom struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Parent     struct {
		GroupID string `xml:"groupId"`
		Version string `xml:"version"`
	} `xml:"parent"`
	Properties           pomProperties `xml:"properties"`
	DependencyManagement struct {
		Dependencies []pomDep `xml:"dependencies>dependency"`
	} `xml:"dependencyManagement"`
	Dependencies []pomDep `xml:"dependencies>dependency"`
}

type pomDep struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
}

// pomProperties collects <properties> children, whatever their names.
type pomProperties map[string]string

func (p *pomProperties) UnmarshalXML(d *xml.Decoder, _ xml.StartElement) error {
	*p = pomProperties{}
	for {
		tok, err := d.Token()
		if err != nil {
			return err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			var v string
			if err := d.DecodeElement(&v, &t); err != nil {
				return err
			}
			(*p)[t.Name.Local] = strings.TrimSpace(v)
		case xml.EndElement:
			return nil
		}
	}
}

var (
	propRef   = regexp.MustCompile(`\$\{([^}]+)\}`)
	exactPin  = regexp.MustCompile(`^\[([^,\[\]()]+)\]$`)
	pomLatest = map[string]bool{"LATEST": true, "RELEASE": true}
)

// parsePOM reads the direct dependencies of a pom.xml. Versions come from the
// pom itself, its properties or its dependencyManagement; a parent POM is not read.
func parsePOM(data []byte) (Result, error) {
	var p pom
	if err := xml.Unmarshal(data, &p); err != nil {
		return Result{}, err
	}
	groupID := strings.TrimSpace(p.GroupID)
	if groupID == "" {
		groupID = strings.TrimSpace(p.Parent.GroupID)
	}
	version := strings.TrimSpace(p.Version)
	if version == "" {
		version = strings.TrimSpace(p.Parent.Version)
	}
	props := map[string]string{
		"project.version": version, "pom.version": version, "version": version,
		"project.groupId": groupID, "pom.groupId": groupID, "groupId": groupID,
		"project.artifactId": strings.TrimSpace(p.ArtifactID), "project.parent.version": strings.TrimSpace(p.Parent.Version),
		"project.parent.groupId": strings.TrimSpace(p.Parent.GroupID),
	}
	for k, v := range p.Properties {
		props[k] = v
	}
	resolve := func(s string) string {
		s = strings.TrimSpace(s)
		for range 10 { // properties may refer to other properties
			next := propRef.ReplaceAllStringFunc(s, func(ref string) string {
				if v, ok := props[ref[2:len(ref)-1]]; ok && v != "" {
					return v
				}
				return ref
			})
			if next == s {
				break
			}
			s = next
		}
		return s
	}

	managed := map[string]string{}
	for _, d := range p.DependencyManagement.Dependencies {
		if v := resolve(d.Version); v != "" {
			managed[resolve(d.GroupID)+":"+resolve(d.ArtifactID)] = v
		}
	}

	var res Result
	for _, d := range p.Dependencies {
		name := resolve(d.GroupID) + ":" + resolve(d.ArtifactID)
		v := resolve(d.Version)
		if v == "" {
			v = managed[name]
		}
		switch {
		case strings.Contains(name, "${"):
			res.Skipped = append(res.Skipped, fmt.Sprintf("maven dependency %q has an unresolved property in its name", short(name)))
			continue
		case v == "":
			res.Skipped = append(res.Skipped, fmt.Sprintf("maven dependency %s has no version (managed outside this pom)", name))
			continue
		case strings.Contains(v, "${"):
			res.Skipped = append(res.Skipped, fmt.Sprintf("maven dependency %s has an unresolved version %q", name, short(v)))
			continue
		}
		if m := exactPin.FindStringSubmatch(v); m != nil {
			v = strings.TrimSpace(m[1])
		}
		if strings.ContainsAny(v, "[](),") || pomLatest[v] {
			res.Skipped = append(res.Skipped, fmt.Sprintf("maven dependency %s has a version range %q", name, short(v)))
			continue
		}
		res.Packages = append(res.Packages, model.Package{Name: name, Version: v, Ecosystem: model.EcoMaven, Dev: strings.TrimSpace(d.Scope) == "test"})
	}
	return res, nil
}
