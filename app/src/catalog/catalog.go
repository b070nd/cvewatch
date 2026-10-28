// Package catalog is the one place that knows what a technology is: how to
// match it in advisories, how to recognise it in a repository, how to order
// its versions and which vendor feed belongs to it. The shipped catalog and
// the user's own entries are layered by name.
package catalog

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/b070nd/cvewatch/app/src/ecosystem"
	"github.com/b070nd/cvewatch/app/src/model"
)

// Categories a technology may belong to.
var Categories = []string{
	"language", "runtime", "framework", "database", "cache", "search", "messaging",
	"web-server", "proxy", "cms", "ecommerce", "os", "hypervisor", "container",
	"devops", "ci-cd", "monitoring", "identity", "collaboration", "storage",
	"network", "firewall", "vpn", "mail", "erp", "security", "other",
}

// Sources of a technology's code.
var Sources = []string{"open", "closed", "mixed"}

// Catalog is an immutable, indexed set of technologies.
type Catalog struct {
	techs  []model.Tech
	byName map[string]int
}

// Merge layers user entries over shipped ones by lowercase name: a user entry
// replaces the shipped entry of the same name (keeping its position), a new
// name is appended, and an entry with Disabled set removes the shipped one.
func Merge(shipped, user []model.Tech) []model.Tech {
	out := slices.Clone(shipped)
	for _, u := range user {
		i := slices.IndexFunc(out, func(t model.Tech) bool { return strings.EqualFold(t.Name, u.Name) })
		switch {
		case u.Disabled && i >= 0:
			out = slices.Delete(out, i, i+1)
		case u.Disabled:
		case i >= 0:
			out[i] = u
		default:
			out = append(out, u)
		}
	}
	return out
}

// New indexes a list of technologies.
func New(techs []model.Tech) *Catalog {
	c := &Catalog{techs: slices.Clone(techs), byName: map[string]int{}}
	for i, t := range c.techs {
		c.byName[strings.ToLower(t.Name)] = i
	}
	return c
}

func (c *Catalog) All() []model.Tech { return slices.Clone(c.techs) }

func (c *Catalog) Get(name string) (model.Tech, bool) {
	i, ok := c.byName[strings.ToLower(strings.TrimSpace(name))]
	if !ok {
		return model.Tech{}, false
	}
	return c.techs[i], true
}

func (c *Catalog) Has(name string) bool { _, ok := c.Get(name); return ok }

// Search finds technologies whose name, title, alias or vendor contains the
// query, case-insensitively. An empty query returns everything.
func (c *Catalog) Search(q string) []model.Tech {
	q = strings.ToLower(strings.TrimSpace(q))
	var out []model.Tech
	for _, t := range c.techs {
		if q == "" || strings.Contains(strings.ToLower(t.Name), q) || strings.Contains(strings.ToLower(t.Title), q) ||
			strings.Contains(strings.ToLower(t.Vendor), q) || slices.ContainsFunc(t.Aliases, func(a string) bool { return strings.Contains(strings.ToLower(a), q) }) {
			out = append(out, t)
		}
	}
	return out
}

// ByCategory lists the technologies of one category.
func (c *Catalog) ByCategory(cat string) []model.Tech {
	var out []model.Tech
	for _, t := range c.techs {
		if t.Category == cat {
			out = append(out, t)
		}
	}
	return out
}

// UsedCategories lists the categories that have entries, in catalog order.
func (c *Catalog) UsedCategories() []string {
	var out []string
	for _, cat := range Categories {
		if len(c.ByCategory(cat)) > 0 {
			out = append(out, cat)
		}
	}
	return out
}

// ForImage finds the technology for a container image reference such as
// "docker.io/library/nginx:1.25.3-alpine" or "postgres@sha256:...". The
// registry, namespace "library", tag and digest are ignored.
func (c *Catalog) ForImage(ref string) (model.Tech, bool) {
	name := ImageName(ref)
	for _, t := range c.techs {
		for _, img := range t.Detect.Images {
			if strings.EqualFold(img, name) {
				return t, true
			}
		}
	}
	return model.Tech{}, false
}

// ImageName reduces an image reference to its repository name without
// registry, tag or digest: "docker.elastic.co/elasticsearch/elasticsearch:8.11.1"
// becomes "elasticsearch/elasticsearch", "library/nginx:1" becomes "nginx".
func ImageName(ref string) string {
	ref = strings.ToLower(strings.TrimSpace(ref))
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	if i := strings.LastIndex(ref, ":"); i >= 0 && !strings.Contains(ref[i:], "/") {
		ref = ref[:i]
	}
	if parts := strings.Split(ref, "/"); len(parts) > 1 && (strings.Contains(parts[0], ".") || strings.Contains(parts[0], ":") || parts[0] == "localhost") {
		ref = strings.Join(parts[1:], "/") // drop the registry host
	}
	return strings.TrimPrefix(ref, "library/")
}

// ForPackage finds the technology a lockfile package implies, if any.
func (c *Catalog) ForPackage(eco, name string) (model.Tech, bool) {
	want := ecosystem.Canonical(eco) + "|" + ecosystem.NormalizeName(eco, name)
	for _, t := range c.techs {
		for _, p := range t.Detect.Packages {
			if ecosystem.Canonical(p.Ecosystem)+"|"+ecosystem.NormalizeName(p.Ecosystem, p.Name) == want {
				return t, true
			}
		}
	}
	return model.Tech{}, false
}

// ForFile lists technologies whose marker files include the base name.
func (c *Catalog) ForFile(base string) []model.Tech {
	var out []model.Tech
	for _, t := range c.techs {
		if slices.ContainsFunc(t.Detect.Files, func(f string) bool { return strings.EqualFold(f, base) }) {
			out = append(out, t)
		}
	}
	return out
}

// ForTerm finds a technology by key, alias or a tool-name such as an asdf
// plugin ("golang" for go, "nodejs" for nodejs).
func (c *Catalog) ForTerm(term string) (model.Tech, bool) {
	term = strings.ToLower(strings.TrimSpace(term))
	if t, ok := c.Get(term); ok {
		return t, true
	}
	for _, t := range c.techs {
		if slices.ContainsFunc(t.Aliases, func(a string) bool { return strings.EqualFold(a, term) }) {
			return t, true
		}
	}
	return model.Tech{}, false
}

var cpeRe = regexp.MustCompile(`^[a-z0-9._+~\-]+:[a-z0-9._+~\-]+$`)

// Validate checks the catalog for mistakes that would silently hide or
// mis-assign advisories. It never touches the network.
func (c *Catalog) Validate() []error {
	var errs []error
	fail := func(f string, a ...any) { errs = append(errs, fmt.Errorf(f, a...)) }
	seen := map[string]bool{}
	for _, t := range c.techs {
		key := strings.ToLower(t.Name)
		switch {
		case t.Name == "":
			fail("a technology has no name")
			continue
		case seen[key]:
			fail("duplicate technology %q", t.Name)
		}
		seen[key] = true
		if t.Category != "" && !slices.Contains(Categories, t.Category) {
			fail("%s: unknown category %q", t.Name, t.Category)
		}
		if t.Source != "" && !slices.Contains(Sources, t.Source) {
			fail("%s: source must be open, closed or mixed, not %q", t.Name, t.Source)
		}
		if !slices.Contains([]string{"", "pypi", "maven", "go"}, t.Scheme) {
			fail("%s: unknown version scheme %q", t.Name, t.Scheme)
		}
		for _, cpe := range t.CPE {
			if !cpeRe.MatchString(cpe) {
				fail("%s: CPE %q must look like vendor:product in lowercase", t.Name, cpe)
			}
		}
		for _, v := range t.Detect.Versions {
			if re, err := regexp.Compile(v.Pattern); err != nil {
				fail("%s: version pattern %q: %v", t.Name, v.Pattern, err)
			} else if re.NumSubexp() != 1 {
				fail("%s: version pattern %q needs exactly one capture group", t.Name, v.Pattern)
			}
		}
	}
	return errs
}
