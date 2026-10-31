package confdoc

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/defaults"
	"github.com/b070nd/cvewatch/app/src/model"
)

func put(t *testing.T, root, rel, body string) string {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func read(t *testing.T, root, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func mustRead(t *testing.T, root string) *Set {
	t.Helper()
	s, err := Read(root)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func mustWith(t *testing.T, s *Set, e ...Edit) *Set {
	t.Helper()
	c, err := s.With(e...)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func text(t *testing.T, s *Set, id string) string {
	t.Helper()
	b, err := s.Doc(id).Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

const commented = `# Global settings.
interval: 4h        # daemon period
lookback: 168h

http:
  timeout: 30s      # per request
  retries: 3
  host_rates:       # stricter limits
    example.org: 0.1

# Optional access rules.
# access:
#   alice: {projects: [shop], write: true}
`

func TestEditKeepsCommentsAndLayout(t *testing.T) {
	root := t.TempDir()
	put(t, root, "config/config.yaml", commented)
	s := mustRead(t, root)
	c := mustWith(t, s,
		Edit{Op: OpSet, Path: "http.timeout", Value: "45s"},
		Edit{Op: OpSet, Path: "http.host_rates[slow.example.com]", Value: 0.5},
		Edit{Op: OpSet, Path: "slack.min_severity", Value: "HIGH"},
	)
	got := text(t, c, IDSettings)
	for _, want := range []string{"# Global settings.", "interval: 4h        # daemon period", "timeout: 45s", "# per request", "# stricter limits", "# access:", "slow.example.com: 0.5", "min_severity: high"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	if !strings.Contains(got, "\nhttp:\n") || strings.Contains(got, "\n\n\n") {
		t.Errorf("layout changed:\n%s", got)
	}
	if text(t, s, IDSettings) != commented {
		t.Fatal("With changed its receiver")
	}
	d := Diff(s, c)
	if len(d) != 1 || !strings.Contains(d[0].Diff, "- ") || !strings.Contains(d[0].Diff, "+   ") {
		t.Fatalf("diff: %+v", d)
	}
}

func TestUnsetAndPrune(t *testing.T) {
	root := t.TempDir()
	put(t, root, "config/config.yaml", "http:\n  retries: 3\n")
	c := mustWith(t, mustRead(t, root), Edit{Op: OpUnset, Path: "http.retries"})
	if got := text(t, c, IDSettings); strings.Contains(got, "http") {
		t.Fatalf("an emptied section stays:\n%s", got)
	}
	if _, err := mustRead(t, root).With(Edit{Op: OpUnset, Path: "http.timeout"}); err == nil {
		t.Fatal("unset of a missing key must fail")
	}
}

func TestSetOnEmptySectionAndMissingFile(t *testing.T) {
	root := t.TempDir()
	c := mustWith(t, mustRead(t, root), Edit{Op: OpSet, Path: "interval", Value: "2h"})
	if got := text(t, c, IDSettings); got != "interval: 2h\n" {
		t.Fatalf("%q", got)
	}
	put(t, root, "config/config.yaml", "# only a comment\n")
	c = mustWith(t, mustRead(t, root), Edit{Op: OpSet, Path: "http.timeout", Value: "5s"})
	if got := text(t, c, IDSettings); !strings.HasPrefix(got, "# only a comment\n") || !strings.Contains(got, "http:\n  timeout: 5s") {
		t.Fatalf("%q", got)
	}
	put(t, root, "config/config.yaml", "http:\ninterval: 1h\n")
	c = mustWith(t, mustRead(t, root), Edit{Op: OpSet, Path: "http.timeout", Value: "5s"})
	if got := text(t, c, IDSettings); !strings.Contains(got, "http:\n  timeout: 5s") {
		t.Fatalf("%q", got)
	}
}

func TestAppendAndRemoveRecords(t *testing.T) {
	root := t.TempDir()
	put(t, root, "config/config.yaml", "interval: 4h\n")
	s := mustRead(t, root)
	c := mustWith(t, s,
		Edit{Op: OpAppend, Path: "policy.rules", Value: map[string]any{"fix_within": "72h", "name": "prod-kev", "kev": true, "env": "prod"}},
		Edit{Op: OpAppend, Path: "policy.rules", Value: map[string]any{"name": "slow", "owner_within": "168h"}},
		Edit{Op: OpAppend, Path: "notify.digest.channels", Value: "slack"},
		Edit{Op: OpAppend, Path: "notify.digest.channels", Value: "slack"},
	)
	got := text(t, c, IDSettings)
	if !strings.Contains(got, "name: prod-kev\n") || strings.Index(got, "name: prod-kev") > strings.Index(got, "kev: true") || strings.Count(got, "slack") != 1 {
		t.Fatalf("%s", got)
	}
	if r := c.Validate(); r.Blocked() {
		t.Fatalf("%+v", r.Issues)
	}
	if _, err := c.With(Edit{Op: OpAppend, Path: "policy.rules", Value: map[string]any{"name": "SLOW", "fix_within": "1h"}}); err == nil {
		t.Fatal("a duplicate rule name was accepted")
	}
	c2 := mustWith(t, c, Edit{Op: OpUnset, Path: "policy.rules.[name=slow]"})
	if got := text(t, c2, IDSettings); strings.Contains(got, "slow") || !strings.Contains(got, "prod-kev") {
		t.Fatalf("%s", got)
	}
	c3 := mustWith(t, c2, Edit{Op: OpUnset, Path: "policy.rules.0"})
	if got := text(t, c3, IDSettings); strings.Contains(got, "policy") {
		t.Fatalf("emptied list stays:\n%s", got)
	}
}

func TestAccessEntriesFollowTheirNeighbours(t *testing.T) {
	root := t.TempDir()
	put(t, root, "config/config.yaml", "access:\n  alice: {projects: [shop], write: true}\n")
	put(t, root, "config/projects/shop.yaml", "name: shop\n")
	c := mustWith(t, mustRead(t, root), Edit{Op: OpSet, Path: "access.bob", Value: map[string]any{"projects": []any{"*"}, "write": false}})
	got := text(t, c, IDSettings)
	if !strings.Contains(got, "  bob: {projects: ['*'], write: false}") {
		t.Fatalf("%s", got)
	}
	if r := c.Validate(); r.Blocked() {
		t.Fatalf("%+v", r.Issues)
	}
}

func TestEditRejectsBadValues(t *testing.T) {
	root := t.TempDir()
	s := mustRead(t, root)
	cases := map[string]Edit{
		"duration":  {Op: OpSet, Path: "interval", Value: "soon"},
		"zero":      {Op: OpSet, Path: "interval", Value: "0"},
		"int":       {Op: OpSet, Path: "http.retries", Value: "many"},
		"range":     {Op: OpSet, Path: "notify.email.port", Value: 70000},
		"bool":      {Op: OpSet, Path: "http.allow_private", Value: "maybe"},
		"enum":      {Op: OpSet, Path: "storage.backend", Value: "postgres"},
		"envref":    {Op: OpSet, Path: "slack.webhook_env", Value: "https://hooks.slack.com/services/T/B/x"},
		"unknown":   {Op: OpSet, Path: "http.timeoutt", Value: "5s"},
		"no value":  {Op: OpSet, Path: "interval"},
		"not list":  {Op: OpAppend, Path: "interval", Value: "1h"},
		"bad key":   {Op: OpSet, Path: "access.bob", Value: map[string]any{"project": "x"}},
		"bad item":  {Op: OpAppend, Path: "notify.digest.channels", Value: "pager"},
		"bad op":    {Op: "poke", Path: "interval", Value: "1h"},
		"readonly":  {Doc: IDShippedTechs, Op: OpSet, Path: "techs.[name=php].title", Value: "x"},
		"bad doc":   {Doc: "projects/x", Op: OpSet, Path: "interval", Value: "1h"},
		"bad brack": {Op: OpSet, Path: "http.host_rates[x", Value: 1},
	}
	for name, e := range cases {
		if _, err := s.With(e); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// text from an input box is converted to the field's type
	c := mustWith(t, s, Edit{Op: OpSet, Path: "http.retries", Value: "5"}, Edit{Op: OpSet, Path: "http.allow_private", Value: "yes"}, Edit{Op: OpSet, Path: "http.rate", Value: "0.5"},
		Edit{Op: OpSet, Path: "notify.email.to", Value: "a@x.test, b@x.test"}, Edit{Op: OpSet, Path: "retention", Value: "0"})
	got := text(t, c, IDSettings)
	for _, want := range []string{"retries: 5", "allow_private: true", "rate: 0.5", "to: [a@x.test, b@x.test]", "retention: 0s\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
}

func TestValidationIsAttributedToFields(t *testing.T) {
	root := t.TempDir()
	put(t, root, "config/projects/shop.yaml", "name: shop\n")
	s := mustRead(t, root)
	cases := []struct {
		edit  Edit
		doc   string
		field string
	}{
		{Edit{Op: OpSet, Path: "lookback", Value: "3000h"}, IDSettings, "retention"},
		{Edit{Op: OpSet, Path: "notify.digest.daily_at", Value: "8am"}, IDSettings, "notify.digest.daily_at"},
		{Edit{Op: OpSet, Path: "access.bob", Value: map[string]any{"projects": []any{"nope"}}}, IDSettings, "access.bob.projects"},
		{Edit{Op: OpAppend, Path: "policy.rules", Value: map[string]any{"name": "x"}}, IDSettings, "policy.rules.0.fix_within"},
		{Edit{Op: OpAppend, Path: "sources", Value: map[string]any{"id": "v", "type": "rss", "url": "http://a.test/f"}}, "sources/custom", "sources.[id=v].url"},
		{Edit{Op: OpAppend, Path: "techs", Value: map[string]any{"name": "acme", "detect": map[string]any{"versions": []any{map[string]any{"file": ".x", "pattern": "abc"}}}}}, IDTechs, "techs.[name=acme].detect.versions"},
		{Edit{Op: OpAppend, Path: "techs", Value: map[string]any{"name": "acme", "cpe": []any{"Bad"}}}, IDTechs, "techs.[name=acme].cpe"},
	}
	for _, c := range cases {
		r := mustWith(t, s, c.edit).Validate()
		var found bool
		for _, is := range r.Errors() {
			if is.Doc == c.doc && is.Field == c.field {
				found = true
			}
		}
		if !found || !r.Blocked() {
			t.Errorf("%v: want an error on %s %s, got %+v", c.edit.Path, c.doc, c.field, r.Issues)
		}
	}
}

func TestBrokenDocumentsAreReportedWithLine(t *testing.T) {
	root := t.TempDir()
	put(t, root, "config/config.yaml", "interval: 4h\nintervall: 1h\nhttp:\n  retries: lots\n")
	s := mustRead(t, root)
	r := s.Validate()
	if r.Bundle != nil || !r.Blocked() {
		t.Fatalf("%+v", r)
	}
	want := map[string]int{"intervall": 2, "http.retries": 4}
	for _, is := range r.Issues {
		if line, ok := want[is.Field]; ok && is.Line == line && is.Doc == IDSettings {
			delete(want, is.Field)
		}
	}
	if len(want) != 0 {
		t.Fatalf("not attributed: %v in %+v", want, r.Issues)
	}
	// fixing one problem at a time is allowed: the other errors are not new
	fixed := mustWith(t, s, Edit{Op: OpUnset, Path: "intervall"})
	after := fixed.Validate()
	after.MarkExisting(r)
	if after.Blocked() || len(after.Errors()) != 1 {
		t.Fatalf("%+v", after.Issues)
	}
	// a syntax error leaves only a whole-document replace
	put(t, root, "config/config.yaml", "interval: [\n")
	s = mustRead(t, root)
	if s.Doc(IDSettings).ParseErr == nil {
		t.Fatal("syntax error not kept")
	}
	if _, err := s.With(Edit{Op: OpSet, Path: "interval", Value: "1h"}); err == nil {
		t.Fatal("field edit on a broken document")
	}
	fixed = mustWith(t, s, Edit{Doc: IDSettings, Op: OpReplace, Value: "interval: 1h\n"})
	if r := fixed.Validate(); r.Blocked() || text(t, fixed, IDSettings) != "interval: 1h\n" {
		t.Fatalf("%+v", r.Issues)
	}
}

func TestWriteBacksUpAndRefusesStaleSets(t *testing.T) {
	root := t.TempDir()
	put(t, root, "config/config.yaml", commented)
	s := mustRead(t, root)
	c := mustWith(t, s, Edit{Op: OpSet, Path: "interval", Value: "6h"})
	backups := filepath.Join(root, "data", "config-backups")
	now := time.Date(2026, 5, 6, 7, 8, 9, 0, time.UTC)

	put(t, root, "config/config.yaml", commented+"# changed elsewhere\n")
	if _, err := c.Write(backups, now); err == nil {
		t.Fatal("a stale set overwrote a newer file")
	}
	put(t, root, "config/config.yaml", commented)
	written, err := c.Write(backups, now)
	if err != nil || len(written) != 1 {
		t.Fatalf("%v %v", written, err)
	}
	if !strings.Contains(read(t, root, "config/config.yaml"), "interval: 6h") {
		t.Fatal("not written")
	}
	bk, _ := os.ReadDir(backups)
	if len(bk) != 1 || !strings.HasPrefix(bk[0].Name(), "config-20260506-070809") {
		t.Fatalf("backups: %v", bk)
	}
	if old, _ := os.ReadFile(filepath.Join(backups, bk[0].Name())); string(old) != commented {
		t.Fatal("backup is not the old file")
	}
	// a new sources file needs no backup
	n := mustWith(t, mustRead(t, root), Edit{Op: OpAppend, Path: "sources", Value: map[string]any{"id": "v", "type": "rss", "url": "https://a.test/f"}})
	if _, err := n.Write(backups, now); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(read(t, root, "sources/custom.yaml"), "id: v") {
		t.Fatal(read(t, root, "sources/custom.yaml"))
	}
	if b, err := config.Load(root); err != nil || len(b.Sources) == 0 {
		t.Fatalf("%v", err)
	}
}

func TestSecretsNeverAppearInViews(t *testing.T) {
	root := t.TempDir()
	put(t, root, "sources/custom.yaml", `# my feeds
sources:
  - id: vendor
    type: rss
    url: https://example.com/feed.xml?token=TOPSECRET
    headers:
      Authorization: Bearer TOPSECRET2
  - id: plain
    type: rss
    url: https://example.com/plain.xml
`)
	s := mustRead(t, root)
	doc := s.Doc("sources/custom")
	for _, e := range doc.Entries() {
		if strings.Contains(e.Value+strings.Join(e.Items, ","), "TOPSECRET") {
			t.Fatalf("entry leaks: %+v", e)
		}
	}
	if strings.Contains(doc.Text(), "TOPSECRET") || !strings.Contains(doc.Text(), "(set)") || !strings.Contains(doc.Text(), "# my feeds") {
		t.Fatalf("text:\n%s", doc.Text())
	}
	c := mustWith(t, s,
		Edit{Op: OpSet, Path: "sources.[id=vendor].headers.Authorization", Value: "Bearer NEWSECRET"},
		Edit{Op: OpSet, Path: "sources.[id=plain].type", Value: "hn"},
	)
	d := Diff(s, c)
	if len(d) != 1 || strings.Contains(d[0].Diff, "SECRET") {
		t.Fatalf("diff leaks or is missing: %+v", d)
	}
	if !strings.Contains(d[0].Diff, "(set, changed)") || !strings.Contains(d[0].Diff, "type: hn") {
		t.Fatalf("diff:\n%s", d[0].Diff)
	}
	for _, is := range c.Validate().Issues {
		if strings.Contains(is.Message, "SECRET") {
			t.Fatalf("issue leaks: %+v", is)
		}
	}
	// a secret that stays shows no change
	same := mustWith(t, s, Edit{Op: OpSet, Path: "sources.[id=plain].type", Value: "hn"})
	for _, l := range strings.Split(Diff(s, same)[0].Diff, "\n") {
		if (strings.HasPrefix(l, "+") || strings.HasPrefix(l, "-")) && strings.Contains(l, "(set") {
			t.Fatalf("unchanged secret shown as a change:\n%s", l)
		}
	}
}

func TestShippedDocumentsAreReadOnlyReferences(t *testing.T) {
	s := mustRead(t, t.TempDir())
	for _, id := range []string{IDShippedTechs, IDShippedSource} {
		d := s.Doc(id)
		if d == nil || d.Layer != LayerShipped || !d.ReadOnly || d.ParseErr != nil || len(d.Entries()) == 0 {
			t.Fatalf("%s: %+v", id, d)
		}
	}
	if u := s.Doc(IDSettings); u.Layer != LayerUser || u.Exists || u.ReadOnly {
		t.Fatalf("%+v", u)
	}
}

// ---- schema ----

// walk lists the schema paths config.Settings and the tech and source types
// should have: every plain value, and every list or map, with "*" for items.
func walkType(t reflect.Type, prefix string, out map[string]reflect.Type) {
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name := yamlName(f)
		if name == "" || name == "-" {
			continue
		}
		path := prefix + name
		walkValue(f.Type, path, out)
	}
}

func walkValue(ft reflect.Type, path string, out map[string]reflect.Type) {
	switch {
	case ft.Kind() == reflect.Struct && ft.PkgPath() != "time":
		walkType(ft, path+".", out)
	case ft.Kind() == reflect.Slice && ft.Elem().Kind() == reflect.Struct:
		out[path] = ft
		walkType(ft.Elem(), path+".*.", out)
	case ft.Kind() == reflect.Map && ft.Elem().Kind() == reflect.Struct:
		out[path] = ft
		walkType(ft.Elem(), path+".*.", out)
	default:
		out[path] = ft
	}
}

var durationType = reflect.TypeOf(time.Duration(0))

func TestSchemaCoversEveryKey(t *testing.T) {
	want := map[string]reflect.Type{}
	byDoc := map[string]map[string]reflect.Type{}
	walkType(reflect.TypeOf(config.Settings{}), "", want)
	byDoc[KindSettings] = want
	techs := map[string]reflect.Type{}
	walkValue(reflect.TypeOf([]model.Tech{}), "techs", techs)
	byDoc[KindTechs] = techs
	srcs := map[string]reflect.Type{}
	walkValue(reflect.TypeOf([]model.Source{}), "sources", srcs)
	byDoc[KindSources] = srcs

	have := map[string]map[string]Field{}
	for _, f := range Schema() {
		if have[f.Doc] == nil {
			have[f.Doc] = map[string]Field{}
		}
		if _, dup := have[f.Doc][f.Path]; dup {
			t.Errorf("duplicate row %s %s", f.Doc, f.Path)
		}
		have[f.Doc][f.Path] = f
		if f.Label == "" || f.Section == "" || f.Type == "" {
			t.Errorf("incomplete row %+v", f)
		}
	}
	for doc, paths := range byDoc {
		for path, ft := range paths {
			f, ok := have[doc][path]
			if !ok {
				t.Errorf("%s: %s has no schema row (add it to confdoc.fields)", doc, path)
				continue
			}
			if !typeFits(f, ft) {
				t.Errorf("%s: %s is %s in the schema but %v in Go", doc, path, f.Type, ft)
			}
		}
		for path := range have[doc] {
			if _, ok := paths[path]; !ok {
				t.Errorf("%s: schema row %s matches no yaml key", doc, path)
			}
		}
	}
	// the feeds inside a technology repeat the source fields
	for path := range srcs {
		if rest, ok := strings.CutPrefix(path, "sources"); ok {
			if _, ok := have[KindTechs]["techs.*.feeds"+rest]; !ok {
				t.Errorf("techs.*.feeds%s missing", rest)
			}
		}
	}
}

func typeFits(f Field, ft reflect.Type) bool {
	switch {
	case ft == durationType:
		return f.Type == TypeDuration
	case ft.Kind() == reflect.Bool:
		return f.Type == TypeBool
	case ft.Kind() == reflect.Int || ft.Kind() == reflect.Int64:
		return f.Type == TypeInt
	case ft.Kind() == reflect.Float64:
		return f.Type == TypeFloat
	case ft.Kind() == reflect.Slice:
		return f.Type == TypeList
	case ft.Kind() == reflect.Map:
		return f.Type == TypeMap
	case ft.Kind() == reflect.String:
		return f.Type == TypeString || f.Type == TypeEnum || f.Type == TypeEnvRef
	}
	return false
}

func TestSchemaRowsAreUsable(t *testing.T) {
	for _, f := range Schema() {
		if f.Type == TypeEnum && len(f.Enum) == 0 && f.Elem == "" {
			t.Errorf("%s: enum without values", f.Path)
		}
		if (f.Type == TypeList || f.Type == TypeMap) && f.Elem == "" {
			t.Errorf("%s: collection without Elem", f.Path)
		}
		if _, ok := Lookup(f.Doc, strings.ReplaceAll(f.Path, "*", "0")); !ok {
			t.Errorf("%s not found by Lookup", f.Path)
		}
	}
	f, _ := Lookup(KindSettings, "http.timeout")
	if f.Default != "30s" || f.Section != SecHTTP {
		t.Fatalf("%+v", f)
	}
	if f, _ := Lookup(KindSettings, "interval"); f.Default != "4h" {
		t.Fatalf("%+v", f)
	}
	if f, _ := Lookup(KindSources, "sources.[id=x].url"); !f.Secret {
		t.Fatal("feed URLs must be secret")
	}
	got := map[string]bool{}
	for _, f := range Schema() {
		got[f.Section] = true
	}
	for _, s := range Sections() {
		if !got[s] {
			t.Errorf("section %s has no fields", s)
		}
	}
}

func TestPathRoundTrip(t *testing.T) {
	for _, p := range []string{"http.timeout", "http.host_rates.[services.nvd.nist.gov]", "policy.rules.[name=a.b].fix_within", "access.alice.projects"} {
		segs, err := ParsePath(p)
		if err != nil || FormatPath(segs) != p {
			t.Errorf("%q -> %v -> %q (%v)", p, segs, FormatPath(segs), err)
		}
	}
	if segs, _ := ParsePath("http.host_rates[a.b].x"); !reflect.DeepEqual(segs, []string{"http", "host_rates", "a.b", "x"}) {
		t.Fatalf("%v", segs)
	}
	for _, bad := range []string{"a..b", "a.", "a[", "[]"} {
		if _, err := ParsePath(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestShippedTemplatesEditCleanly(t *testing.T) {
	root := t.TempDir()
	put(t, root, "config/config.yaml", string(defaults.Settings()))
	put(t, root, "config/techs.yaml", string(defaults.UserTechs()))
	put(t, root, "sources/custom.yaml", string(defaults.UserSources()))
	put(t, root, "config/projects/shop.yaml", "name: shop\n")
	s := mustRead(t, root)
	if r := s.Validate(); r.Blocked() {
		t.Fatalf("the templates do not load: %+v", r.Issues)
	}
	c := mustWith(t, s,
		Edit{Op: OpSet, Path: "http.timeout", Value: "45s"},
		Edit{Op: OpSet, Path: "access.alice", Value: map[string]any{"projects": []any{"shop"}, "write": true}},
		Edit{Op: OpAppend, Path: "techs", Value: map[string]any{"name": "acme", "title": "ACME", "aliases": []any{"acme gateway"}, "cpe": []any{"acme:gateway"}}},
		Edit{Op: OpAppend, Path: "sources", Value: map[string]any{"id": "v", "type": "rss", "url": "https://x.test/f"}},
	)
	if r := c.Validate(); r.Blocked() {
		t.Fatalf("%+v", r.Issues)
	}
	for _, d := range Diff(s, c) {
		for _, l := range strings.Split(d.Diff, "\n") {
			if strings.HasPrefix(l, "-") && !strings.Contains(l, "timeout") && !strings.Contains(l, "techs: []") && !strings.Contains(l, "sources: []") {
				t.Errorf("%s: unrelated line removed: %q", d.Doc, l)
			}
		}
	}
	if got := text(t, c, IDTechs); !strings.Contains(got, "# Your own technologies.") || !strings.Contains(got, "  - name: acme\n    aliases: [acme gateway]") {
		t.Fatalf("%s", got)
	}
}

func TestTUISettingsAreEditableAndChecked(t *testing.T) {
	root := t.TempDir()
	if f, ok := Lookup(KindSettings, "tui.editor"); !ok || f.Type != TypeString || f.Default != "" || !strings.Contains(f.Help, "VISUAL") {
		t.Fatalf("tui.editor: %+v", f)
	}
	f, ok := Lookup(KindSettings, "tui.refresh")
	if !ok || f.Default != "30s" || f.Type != TypeDuration || f.Min == nil || *f.Min != 1 {
		t.Fatalf("tui.refresh: %+v", f)
	}
	if f, ok = Lookup(KindSettings, "tui.fetch"); !ok || f.Default != "" || f.Min == nil || *f.Min != 0 {
		t.Fatalf("tui.fetch: %+v", f)
	}
	s := mustRead(t, root)
	for _, e := range []Edit{
		{Op: OpSet, Path: "tui.refresh", Value: "500ms"},
		{Op: OpSet, Path: "tui.refresh", Value: "0"},
		{Op: OpSet, Path: "tui.fetch", Value: "-5m"},
	} {
		if _, err := s.With(e); err == nil {
			t.Errorf("%v %v accepted", e.Path, e.Value)
		}
	}
	c := mustWith(t, s, Edit{Op: OpSet, Path: "tui.refresh", Value: "5s"}, Edit{Op: OpSet, Path: "tui.fetch", Value: "0"})
	if r := c.Validate(); r.Blocked() {
		t.Fatalf("a valid tui section must pass the loader: %+v", r.Issues)
	}
	if got := text(t, c, IDSettings); !strings.Contains(got, "refresh: 5s") || !strings.Contains(got, "fetch: 0s") {
		t.Fatalf("\n%s", got)
	}
	c = mustWith(t, c, Edit{Op: OpSet, Path: "tui.editor", Value: "code --wait"})
	if r := c.Validate(); r.Blocked() {
		t.Fatalf("a valid editor must pass the loader: %+v", r.Issues)
	}
	if got := text(t, c, IDSettings); !strings.Contains(got, "editor: code --wait") {
		t.Fatalf("\n%s", got)
	}
	if blank := mustWith(t, s, Edit{Op: OpSet, Path: "tui.editor", Value: "  "}); !blank.Validate().Blocked() {
		t.Fatal("a blank editor must be refused")
	}
}

func TestHorizonSettingsAreEditableAndChecked(t *testing.T) {
	root := t.TempDir()
	f, ok := Lookup(KindSettings, "horizon.window")
	if !ok || f.Type != TypeEnum || f.Default != "unlimited" || !reflect.DeepEqual(f.Enum, config.Windows) {
		t.Fatalf("horizon.window: %+v", f)
	}
	s := mustRead(t, root)
	if _, err := s.With(Edit{Op: OpSet, Path: "horizon.window", Value: "decade"}); err == nil {
		t.Error("an unknown window was accepted")
	}
	c := mustWith(t, s, Edit{Op: OpSet, Path: "horizon.window", Value: "custom"}, Edit{Op: OpSet, Path: "horizon.from", Value: "2026-03-01"}, Edit{Op: OpSet, Path: "horizon.to", Value: "2026-01-01"})
	r := c.Validate()
	if !r.Blocked() || r.Issues[0].Field != "horizon.to" || r.Issues[0].Level != "error" {
		t.Fatalf("to before from must block and name horizon.to: %+v", r.Issues)
	}
	c = mustWith(t, s, Edit{Op: OpSet, Path: "horizon.window", Value: "week"})
	if r := c.Validate(); r.Blocked() {
		t.Fatalf("a valid horizon must pass the loader: %+v", r.Issues)
	}
	if got := text(t, c, IDSettings); !strings.Contains(got, "window: week") {
		t.Fatalf("\n%s", got)
	}
}

func TestUpdateSettingsAreEditableAndChecked(t *testing.T) {
	root := t.TempDir()
	f, ok := Lookup(KindSettings, "update.auto")
	if !ok || f.Type != TypeBool || f.Default != "true" || f.Section != SecCore || !strings.Contains(f.Help, "update.every") {
		t.Fatalf("update.auto: %+v", f)
	}
	if f, ok = Lookup(KindSettings, "tui.auto"); !ok || f.Type != TypeBool || f.Default != "true" || !strings.Contains(f.Help, "daemon") {
		t.Fatalf("tui.auto: %+v", f)
	}
	if f, ok = Lookup(KindSettings, "interval"); !ok || !strings.Contains(f.Help, "update.every") {
		t.Fatalf("interval is the default period of a project: %+v", f)
	}
	s := mustRead(t, root)
	if _, err := s.With(Edit{Op: OpSet, Path: "update.auto", Value: "sometimes"}); err == nil {
		t.Error("a bool setting took a word")
	}
	if _, err := s.With(Edit{Op: OpSet, Path: "update.every", Value: "1h"}); err == nil {
		t.Error("update.every is a key of the project file, not of config.yaml")
	}
	c := mustWith(t, s, Edit{Op: OpSet, Path: "update.auto", Value: false}, Edit{Op: OpSet, Path: "tui.auto", Value: false})
	if r := c.Validate(); r.Blocked() {
		t.Fatalf("both must pass the loader: %+v", r.Issues)
	}
	if got := text(t, c, IDSettings); !strings.Contains(got, "update:\n  auto: false") || !strings.Contains(got, "auto: false") {
		t.Fatalf("\n%s", got)
	}
}

func TestShippedSettingsFileDocumentsTheUpdateKeys(t *testing.T) {
	text := string(defaults.Settings())
	for _, want := range []string{"# update:", "#   auto: true", "#   auto: true       # without a running daemon", "update: {every: 1h, auto: false}"} {
		if !strings.Contains(text, want) {
			t.Errorf("config.yaml template lacks %q", want)
		}
	}
	if example := string(defaults.ProjectExample()); !strings.Contains(example, "# update:") || !strings.Contains(example, "every: 1h") {
		t.Errorf("the project example does not show the update block:\n%s", example)
	}
}

func TestSourceAuthEnvTakesAVariableNameNeverAToken(t *testing.T) {
	root := t.TempDir()
	put(t, root, "sources/custom.yaml", "sources:\n  - {id: vendor, type: rss, url: \"https://example.com/feed.xml\"}\n")
	s := mustRead(t, root)
	if f, ok := Lookup(KindSources, "sources.[id=vendor].auth_env"); !ok || f.Type != TypeEnvRef {
		t.Fatalf("schema: %+v %v", f, ok)
	}
	c := mustWith(t, s, Edit{Op: OpSet, Path: "sources.[id=vendor].auth_env", Value: "VENDOR_TOKEN"})
	if !strings.Contains(text(t, c, "sources/custom"), "auth_env: VENDOR_TOKEN") {
		t.Fatalf("not written:\n%s", text(t, c, "sources/custom"))
	}
	if _, err := s.With(Edit{Op: OpSet, Path: "sources.[id=vendor].auth_env", Value: "ghp_abc-123 def"}); err == nil || strings.Contains(err.Error(), "ghp_abc") {
		t.Fatalf("a token must be refused without echoing it: %v", err)
	}
}
