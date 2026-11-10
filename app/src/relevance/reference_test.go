package relevance

import (
	"fmt"
	"math/rand"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/b070nd/cvewatch/app/src/ecosystem"
	"github.com/b070nd/cvewatch/app/src/model"
)

// refJudge is the judge as it was before the compiled matcher: every tech and
// every package of every target is tried against the item. It is slow and
// obviously right, and exists only to hold the matcher to the same verdicts.
func refJudge(j *Judge, it model.Item, targets []Target) Verdict {
	return refJudgeWith(j, it, targets, nil)
}

// refJudgeWith takes the prepared words of package names, which is how the
// loop ran once it cached them; nil prepares them on every use.
func refJudgeWith(j *Judge, it model.Item, targets []Target, cache map[string]words) Verdict {
	type refHit struct {
		ranges []model.Range
		known  bool
		why    string
	}
	var v Verdict
	declared := map[string]bool{}
	for _, tg := range targets {
		for _, pt := range tg.Techs {
			declared[strings.ToLower(pt.Name)] = true
		}
	}
	schemes := map[string]string{}
	hits := map[string]refHit{}
	text := newSubject(it.TechText())
	plain := text
	if it.TitleOnly {
		plain = newSubject(it.Text())
	}
	for _, t := range j.techs {
		if !declared[t.name] {
			continue
		}
		schemes[t.name] = t.scheme
		h, note, ok := t.judge(it, text)
		if note != "" {
			v.Notes = append(v.Notes, note)
		}
		if ok && !h.waiting {
			hits[t.name] = refHit{h.ranges, h.known, basisWords(model.Installed{Basis: []model.Basis{h.basis}})}
			v.Techs = append(v.Techs, t.name)
		}
	}
	noted := map[string]bool{}
	var packages map[string][]model.Range
	if len(it.Affected) > 0 || len(it.Products) > 0 {
		packages = map[string][]model.Range{}
	}
	for _, a := range it.Affected {
		if a.Ecosystem == model.EcoCPE {
			continue
		}
		key := pkgKey(a.Ecosystem, a.Name)
		packages[key] = append(packages[key], a.Ranges...)
	}
	add := func(m *Match, in model.Installed, a model.Applicability, why string) {
		m.Installed = append(m.Installed, in)
		if len(m.Installed) == 1 {
			m.Applies = a
		} else {
			m.Applies = m.Applies.Worse(a)
		}
		m.Reasons = append(m.Reasons, fmt.Sprintf("%s: %s, %s", in.Label(), why, verdictWords(a)))
	}
	for _, tg := range targets {
		m := Match{Project: tg.Project, Env: tg.Env, Applies: model.AppNotAffected}
		for _, pt := range tg.Techs {
			h, ok := hits[strings.ToLower(pt.Name)]
			if !ok {
				continue
			}
			in := model.Installed{Name: pt.Name, Version: pt.Version, Via: "tech", Ecosystem: schemes[strings.ToLower(pt.Name)]}
			add(&m, in, applies(in, h.ranges, h.known), h.why)
		}
		for _, pkg := range tg.Packages {
			in := model.Installed{Name: pkg.Name, Version: pkg.Version, Ecosystem: pkg.Ecosystem, Via: "package"}
			rs, structured, ok := refPackageHit(packages, it.Products, plain, pkg, cache)
			if !ok {
				continue
			}
			why := "named in the advisory's package list"
			if packages == nil {
				why = "named in the text"
			} else if len(packages) == 0 {
				why = "named in the advisory's product data"
			}
			add(&m, in, applies(in, rs, structured), why)
		}
		if len(m.Installed) == 0 {
			continue
		}
		if !tg.Since.IsZero() && !it.Published.IsZero() && it.Published.Before(tg.Since) {
			if !noted[tg.Project] {
				noted[tg.Project] = true
				v.Notes = append(v.Notes, fmt.Sprintf("%s: published %s, before the project's start date %s",
					tg.Project, it.Published.UTC().Format("2006-01-02"), tg.Since.UTC().Format("2006-01-02")))
			}
			continue
		}
		if tg.Horizon.Outside(it.Published) {
			if !noted[tg.Project] {
				noted[tg.Project] = true
				v.Notes = append(v.Notes, fmt.Sprintf("%s: published %s, outside the alert horizon",
					tg.Project, it.Published.UTC().Format("2006-01-02")))
			}
			continue
		}
		v.Matches = append(v.Matches, m)
	}
	if len(v.Matches) == 0 && len(noted) > 0 {
		v.Techs = nil
	}
	return v
}

func refPackageHit(packages map[string][]model.Range, products []model.Product, plain subject, pkg model.Package, cache map[string]words) (ranges []model.Range, structured, ok bool) {
	if packages != nil {
		ranges, ok = packages[pkgKey(pkg.Ecosystem, pkg.Name)]
		if !ok && len(packages) == 0 && strings.ContainsAny(pkg.Name, "/:") {
			for _, p := range products {
				if ecosystem.NormalizeName(pkg.Ecosystem, p.Name) == ecosystem.NormalizeName(pkg.Ecosystem, pkg.Name) {
					return nil, false, true
				}
			}
		}
		return ranges, len(ranges) > 0, ok
	}
	if strings.ContainsAny(pkg.Name, "/:") {
		w, ok := cache[pkg.Name]
		if !ok {
			w = newWords([]string{pkg.Name})
		}
		if w.match(plain) {
			return nil, false, true
		}
	}
	return nil, false, false
}

// plainVerdict drops what the reference never had: the basis of each match
// and the held matches.
func plainVerdict(v Verdict) Verdict {
	v.Held = nil
	for i := range v.Matches {
		for k := range v.Matches[i].Installed {
			v.Matches[i].Installed[k].Basis = nil
		}
	}
	return v
}

// TestMatcherGivesTheReferenceVerdicts judges a seeded random corpus with the
// compiled matcher and with the reference. Balanced profile, which is what
// the reference implements.
func TestMatcherGivesTheReferenceVerdicts(t *testing.T) {
	rng := rand.New(rand.NewSource(20261110))
	pick := func(xs []string) string { return xs[rng.Intn(len(xs))] }
	techNames := []string{"php", "nginx", "redis", "magento", "go", "nodejs", "craft"}
	techs := []model.Tech{
		{Name: "php", CPE: []string{"php:php"}, Excludes: []string{"plugin for", "written in php"}},
		{Name: "nginx", CPE: []string{"f5:nginx", "nginx:nginx"}},
		{Name: "redis", Aliases: []string{"redis", "redis server"}},
		{Name: "magento", Aliases: []string{"magento", "adobe commerce"}, CPE: []string{"adobe:commerce", "magento:magento"}},
		{Name: "go", Aliases: []string{"golang"}, Scheme: "go"},
		{Name: "nodejs", Aliases: []string{"nodejs", "node.js"}, CPE: []string{"nodejs:node.js"}},
		{Name: "craft", Aliases: []string{"craft cms"}},
		{Name: "unused", CPE: []string{"x:unused"}},
	}
	pkgNames := []string{"symfony/http-kernel", "monolog/monolog", "magento/framework", "golang.org/x/net", "org.apache.logging.log4j:log4j-core",
		"lodash", "django-rest-framework", "@babel/core", "guzzlehttp/guzzle", "github.com/gin-gonic/gin", "müller/paket", "a/b"}
	ecos := []string{"composer", "npm", "go", "maven", "pypi", "pip", "Packagist"}
	versions := []string{"1.0.0", "2.4.7", "6.4.1", "8.2.10", "v0.17.0", "2.17.0", ""}
	var targets []Target
	for p := 0; p < 5; p++ {
		for _, env := range []model.Env{model.EnvDev, model.EnvProd} {
			tg := Target{Project: fmt.Sprintf("p%d", p), Env: env}
			for i, n := 0, rng.Intn(4); i < n; i++ {
				tg.Techs = append(tg.Techs, model.ProjectTech{Name: strings.ToUpper(pick(techNames)[:1]) + pick(techNames)[1:], Version: pick(versions)})
			}
			for i, n := 0, rng.Intn(9); i < n; i++ {
				tg.Packages = append(tg.Packages, model.Package{Ecosystem: pick(ecos), Name: pick(pkgNames), Version: pick(versions)})
			}
			if rng.Intn(4) == 0 {
				tg.Since = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
			}
			if rng.Intn(5) == 0 {
				tg.Horizon = Window{From: time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)}
			}
			targets = append(targets, tg)
		}
	}
	// Techs must be real names for the catalog to know them.
	for i := range targets {
		for k := range targets[i].Techs {
			targets[i].Techs[k].Name = pick(append(techNames, "PHP", "Nginx"))
		}
	}
	wordsPool := []string{"A flaw in", "PHP", "php-fpm", "nginx", "Redis server", "Adobe Commerce", "Magento", "golang", "node.js", "Craft CMS",
		"plugin for WordPress", "written in PHP", "symfony/http-kernel", "(monolog/monolog)", "golang.org/x/net/http2", "see https://example.test/a/b",
		"org.apache.logging.log4j:log4j-core", "lodash", "@babel/core.", "Müller/Paket", "KELVIN K", "phpunit", "a/b", "x:a/b:y", "remote code execution", "ſymfony/http-kernel"}
	text := func(n int) string {
		var parts []string
		for i := 0; i < n; i++ {
			parts = append(parts, pick(wordsPool))
		}
		return strings.Join(parts, " ")
	}
	cpes := []string{"php:php", "f5:nginx", "adobe:commerce", "moodle:moodle", "nodejs:node.js", "x:unused"}
	ranges := [][]model.Range{nil, {{Max: "8.2.30", MaxExcl: true}}, {{Min: "2.0.0", Max: "2.4.9"}}, {{}}}
	products := []model.Product{{Vendor: "Adobe", Name: "Commerce"}, {Name: "Magento"}, {Vendor: "PHP Group", Name: "PHP"}, {Name: "symfony/http-kernel"},
		{Vendor: "Craft", Name: "CMS"}, {Name: "Roundcube"}, {Name: "golang.org/x/net"}, {Name: "Log4j"}}

	j := New(techs)
	m := j.Compile(targets)
	matched, held, noted := 0, 0, 0
	for n := 0; n < 20000; n++ {
		it := model.Item{Title: text(1 + rng.Intn(4)), Summary: text(rng.Intn(6)), TitleOnly: rng.Intn(3) == 0, StructuredOnly: rng.Intn(3) == 0}
		if rng.Intn(3) > 0 {
			it.Published = time.Date(2026, time.Month(1+rng.Intn(11)), 1+rng.Intn(27), 0, 0, 0, 0, time.UTC)
		}
		for i, k := 0, rng.Intn(3); i < k && rng.Intn(2) == 0; i++ {
			it.Affected = append(it.Affected, model.Affected{Ecosystem: model.EcoCPE, Name: pick(cpes), Ranges: ranges[rng.Intn(len(ranges))]})
		}
		for i, k := 0, rng.Intn(3); i < k && rng.Intn(3) == 0; i++ {
			it.Affected = append(it.Affected, model.Affected{Ecosystem: pick(ecos), Name: pick(pkgNames), Ranges: ranges[rng.Intn(len(ranges))]})
		}
		for i, k := 0, rng.Intn(3); i < k && rng.Intn(3) == 0; i++ {
			it.Products = append(it.Products, products[rng.Intn(len(products))])
		}
		want := refJudge(j, it, targets)
		full := m.Judge(it)
		held += len(full.Held)
		got := plainVerdict(full)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("item %d %+v\n got  %+v\n want %+v", n, it, got, want)
		}
		matched += len(got.Matches)
		noted += len(got.Notes)
	}
	if matched < 5000 || held < 500 || noted < 2000 {
		t.Fatalf("the corpus does not exercise the matcher: %d matches, %d held, %d notes", matched, held, noted)
	}
}

// benchInventory is the shape of a real installation: a few projects, each
// with four environments sharing one lockfile of many scoped packages.
func benchInventory() ([]model.Tech, []Target, []model.Item) {
	techs := []model.Tech{{Name: "php", CPE: []string{"php:php"}}, {Name: "magento", CPE: []string{"adobe:commerce"}}, {Name: "nginx", CPE: []string{"f5:nginx"}},
		{Name: "redis"}, {Name: "elasticsearch", CPE: []string{"elastic:elasticsearch"}}}
	var targets []Target
	for p := 0; p < 3; p++ {
		var pkgs []model.Package
		for i := 0; i < 600; i++ {
			pkgs = append(pkgs, model.Package{Ecosystem: "composer", Name: fmt.Sprintf("vendor%d/package-%d", i%60, i), Version: "1.2.3"})
		}
		for _, env := range []model.Env{model.EnvDev, "int", "staging", model.EnvProd} {
			targets = append(targets, Target{Project: fmt.Sprintf("p%d", p), Env: env, Packages: pkgs,
				Techs: []model.ProjectTech{{Name: "php", Version: "8.2"}, {Name: "magento", Version: "2.4.7"}, {Name: "nginx"}, {Name: "redis"}, {Name: "elasticsearch"}}})
		}
	}
	var items []model.Item
	for i := 0; i < 300; i++ {
		it := model.Item{Title: fmt.Sprintf("CVE-2026-%d: A flaw in some unrelated product allows remote attackers to do things", i),
			Summary: strings.Repeat("The issue is reachable over the network; see https://example.test/advisory/"+fmt.Sprint(i)+" for details. ", 4)}
		switch i % 3 {
		case 0:
			it.Affected = []model.Affected{{Ecosystem: model.EcoCPE, Name: fmt.Sprintf("acme:product%d", i)}}
		case 1:
			it.Affected = []model.Affected{{Ecosystem: "composer", Name: fmt.Sprintf("other%d/thing", i), Ranges: []model.Range{{Max: "2.0.0", MaxExcl: true}}}}
		}
		items = append(items, it)
	}
	return techs, targets, items
}

func BenchmarkReferenceJudge(b *testing.B) {
	techs, targets, items := benchInventory()
	j := New(techs)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		refJudge(j, items[i%len(items)], targets)
	}
}

func BenchmarkCachedLoopJudge(b *testing.B) {
	techs, targets, items := benchInventory()
	j := New(techs)
	cache := map[string]words{}
	for _, tg := range targets {
		for _, p := range tg.Packages {
			cache[p.Name] = newWords([]string{p.Name})
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		refJudgeWith(j, items[i%len(items)], targets, cache)
	}
}

func BenchmarkMatcherJudge(b *testing.B) {
	techs, targets, items := benchInventory()
	m := New(techs).Compile(targets)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Judge(items[i%len(items)])
	}
}
