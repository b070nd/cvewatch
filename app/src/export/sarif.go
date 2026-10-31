package export

import (
	"encoding/json"
	"io"
	"slices"

	"github.com/b070nd/cvewatch/app/src/model"
)

// WriteSARIF writes the document as SARIF 2.1.0, for code-scanning screens and
// CI systems that read it. Each issue is a rule, each project and environment
// it is open in is a result. Results point at the project's config file, since
// that is where the exposure is declared, and carry the environment as a
// logical location.
func (d Document) WriteSARIF(w io.Writer) error {
	type obj = map[string]any
	rules, results := []obj{}, []obj{}
	for _, is := range d.Issues {
		level := sarifLevel(is.Severity)
		rules = append(rules, obj{
			"id": is.ID, "shortDescription": obj{"text": is.Untrusted.Title},
			"defaultConfiguration": obj{"level": level},
			"properties":           obj{"severity": string(is.Severity), "kev": is.KEV != nil, "aliases": nonNil(is.Aliases)},
		})
		for _, t := range is.Targets {
			props := obj{"project": t.Project, "env": string(t.Env), "status": string(t.Status), "owner": t.Owner}
			if t.Vendor != "" {
				props["vendor"] = t.Vendor
			}
			results = append(results, obj{
				"ruleId": is.ID, "level": level,
				"message": obj{"text": is.Untrusted.Title + " (" + t.Project + "/" + string(t.Env) + ", " + string(t.Status) + ")"},
				"locations": []obj{{
					"physicalLocation": obj{"artifactLocation": obj{"uri": "config/projects/" + t.Project + ".yaml"}, "region": obj{"startLine": 1}},
					"logicalLocations": []obj{{"name": string(t.Env), "kind": "namespace"}},
				}},
				"properties": props,
			})
		}
	}
	doc := obj{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
		"runs": []obj{{"tool": obj{"driver": obj{"name": "cvewatch", "rules": rules}}, "results": results}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// sarifLevel maps severity to the three levels SARIF knows.
func sarifLevel(s model.Severity) string {
	switch {
	case s.AtLeast(model.SevHigh):
		return "error"
	case s == model.SevMedium:
		return "warning"
	}
	return "note"
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return slices.Clone(s)
}
