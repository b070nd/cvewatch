package discovery

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// compose (8): every services.<name>.image of a compose file.
func (s *scanner) compose(f *file, data []byte) {
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		s.note("%s is not valid YAML", f.rel)
		return
	}
	services := asMap(doc["services"])
	names := make([]string, 0, len(services))
	for n := range services {
		names = append(names, n)
	}
	slices.Sort(names) // a stable order keeps ties deterministic
	for _, n := range names {
		if img, ok := asMap(services[n])["image"].(string); ok {
			s.image(f, expandVars(img, nil))
		}
	}
}

// kubernetes (9): every image: scalar at any depth, in plain (non-Helm) manifests.
func (s *scanner) kubernetes(f *file, data []byte) {
	var doc []string
	flush := func() {
		text := strings.Join(doc, "\n")
		doc = doc[:0]
		if strings.Contains(text, "{{") {
			return // a Helm template, not YAML
		}
		var n yaml.Node
		if yaml.Unmarshal([]byte(text), &n) == nil {
			s.walkImages(f, &n)
		}
	}
	for _, line := range strings.Split(string(data), "\n") {
		if t := strings.TrimRight(line, " \t\r"); t == "---" || strings.HasPrefix(t, "--- ") {
			flush()
			continue
		}
		doc = append(doc, line)
	}
	flush()
}

// walkImages finds image scalars without following aliases.
func (s *scanner) walkImages(f *file, n *yaml.Node) {
	switch n.Kind {
	case yaml.DocumentNode, yaml.SequenceNode:
		for _, c := range n.Content {
			s.walkImages(f, c)
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			if k.Value == "image" && v.Kind == yaml.ScalarNode {
				s.image(f, v.Value)
				continue
			}
			s.walkImages(f, v)
		}
	}
}

var (
	tfImage   = regexp.MustCompile(`image\s*=\s*"([^"]+)"`)
	tfEngine  = regexp.MustCompile(`engine\s*=\s*"([^"]+)"`)
	tfVersion = regexp.MustCompile(`engine_version\s*=\s*"([^"]+)"`)
)

// terraform (10): image = "..." and engine/engine_version pairs in one block.
func (s *scanner) terraform(f *file) {
	if !strings.HasSuffix(f.low, ".tf") {
		return
	}
	lines := strings.Split(string(f.bytes()), "\n")
	for i, line := range lines {
		if t := strings.TrimSpace(line); strings.HasPrefix(t, "#") || strings.HasPrefix(t, "//") {
			continue
		}
		if m := tfImage.FindStringSubmatch(line); m != nil {
			s.image(f, m[1])
		}
		m := tfEngine.FindStringSubmatch(line)
		if m == nil || strings.Contains(line, "engine_version") {
			continue
		}
		t, ok := s.cat.ForTerm(m[1])
		if !ok {
			continue
		}
		for _, next := range lines[i+1 : min(i+16, len(lines))] {
			if strings.HasPrefix(next, "}") || strings.HasPrefix(next, "resource ") {
				break // the block ended
			}
			if v := tfVersion.FindStringSubmatch(next); v != nil {
				ver := tagVersion("x:" + v[1])
				c := Medium
				if ver == "" {
					c = Low
				}
				s.add(f, t, ver, c, fmt.Sprintf("engine %s %s", m[1], v[1]))
				break
			}
		}
	}
}

// ---- merging ----

// better says whether a beats b: higher confidence, then the more specific version.
func better(a, b hit) bool {
	if a.conf != b.conf {
		return a.conf.rank() > b.conf.rank()
	}
	return strings.Count(a.version, ".") > strings.Count(b.version, ".")
}

// compatible is true when one version is the other or a series of it (8.2 and 8.2.1).
func compatible(a, b string) bool {
	return a == b || strings.HasPrefix(a, b+".") || strings.HasPrefix(b, a+".")
}

func (h hit) says() string {
	if h.claim != "" {
		return h.claim
	}
	return "says " + h.version
}

// result merges the hits into one proposal per technology and orders everything.
func (s *scanner) result(root string) Result {
	var names []string
	byTech := map[string][]hit{}
	for _, h := range s.hits {
		if _, ok := byTech[h.tech.Name]; !ok {
			names = append(names, h.tech.Name)
		}
		byTech[h.tech.Name] = append(byTech[h.tech.Name], h)
	}

	res := Result{Root: root, Lockfiles: s.locks, Truncated: s.trunc}
	for _, name := range names {
		hits := byTech[name]
		win := -1
		for i, h := range hits {
			if h.version != "" && (win < 0 || better(h, hits[win])) {
				win = i
			}
		}
		p := TechProposal{Tech: name, Title: hits[0].tech.Title, Confidence: Low}
		if p.Infra = !slices.ContainsFunc(hits, func(h hit) bool { return !h.infra }); p.Infra {
			p.Category = hits[0].tech.Category
		}
		if p.Title == "" {
			p.Title = name
		}
		order := hits
		if win >= 0 {
			w := hits[win]
			p.Version, p.Confidence = w.version, w.conf
			order = append([]hit{w}, slices.Delete(slices.Clone(hits), win, win+1)...)
			for _, h := range hits {
				if h.version != "" && !h.quiet && !compatible(h.version, w.version) {
					s.note("%s: %s %s but %s %s", name, w.file, w.says(), h.file, h.says())
				}
			}
		} else {
			for _, h := range hits {
				if h.conf.rank() > p.Confidence.rank() {
					p.Confidence = h.conf
				}
			}
		}
		for _, h := range order {
			e := Evidence{File: h.file, Detail: h.detail}
			if len(p.Evidence) < maxEvidence && !slices.Contains(p.Evidence, e) {
				p.Evidence = append(p.Evidence, e)
			}
		}
		res.Techs = append(res.Techs, p)
	}

	slices.SortFunc(res.Techs, func(a, b TechProposal) int {
		if a.Confidence != b.Confidence {
			return b.Confidence.rank() - a.Confidence.rank()
		}
		return strings.Compare(a.Tech, b.Tech)
	})
	slices.SortFunc(res.Lockfiles, func(a, b LockProposal) int { return strings.Compare(a.Path, b.Path) })
	for n := range s.notes {
		res.Notes = append(res.Notes, n)
	}
	slices.Sort(res.Notes)
	return res
}
