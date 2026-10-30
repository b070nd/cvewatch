package setup

import (
	"strings"
	"testing"

	"github.com/b070nd/cvewatch/app/src/catalog"
	"github.com/b070nd/cvewatch/app/src/model"
)

func customCatalog() *catalog.Catalog {
	return catalog.New([]model.Tech{
		{Name: "mysql", Title: "MySQL", Category: "database"},
		{Name: "rabbitmq", Title: "RabbitMQ", Category: "messaging"},
		{Name: "php", Title: "PHP", Category: "language"},
	})
}

func toAddTechs(t *testing.T, f *Flow) {
	t.Helper()
	answer(t, f, "name", "shop")
	answer(t, f, "techs", "")
}

func TestAddTechsOffersWhatTheUserMeantOrTheirOwnKeyword(t *testing.T) {
	f := NewFlow(customCatalog(), nil)
	toAddTechs(t, f)

	// the terms from the user's message: unknown ones are not guessed at
	err := f.Answer("algolia akeneo channable gcp")
	if err == nil {
		t.Fatal("unknown terms accepted")
	}
	for _, term := range []string{"algolia", "akeneo", "channable", "gcp"} {
		if !strings.Contains(err.Error(), `"`+term+`" is not in the catalog; write +`+term) {
			t.Errorf("%s: %v", term, err)
		}
	}
	if strings.Contains(err.Error(), "Did you mean") || len(f.Draft().Project.Techs) != 0 {
		t.Fatalf("nothing is close and nothing may change: %v %+v", err, f.Draft().Project.Techs)
	}

	err = f.Answer("rabbitMW myssql")
	if err == nil || !strings.Contains(err.Error(), "Did you mean: rabbitmq") || !strings.Contains(err.Error(), "Did you mean: mysql") {
		t.Fatalf("typos must point at the real names: %v", err)
	}
	if strings.Contains(err.Error(), "php") {
		t.Fatalf("no unrelated fillers: %v", err)
	}
	if st := f.Current(); st.ID != "add-techs" || st.Problem == "" {
		t.Fatalf("%+v", st)
	}
}

func TestAddTechsPlusMakesAnOwnKeyword(t *testing.T) {
	f := NewFlow(customCatalog(), nil)
	toAddTechs(t, f)
	answer(t, f, "add-techs", "+Algolia mysql +akeneo")

	var names []string
	for _, p := range f.Draft().Project.Techs {
		names = append(names, p.Name)
	}
	if strings.Join(names, ",") != "mysql,algolia,akeneo" {
		t.Fatalf("techs: %v", names)
	}
	custom := f.Custom()
	if len(custom) != 2 || custom[0].Name != "algolia" || strings.Join(custom[0].Aliases, ",") != "algolia" {
		t.Fatalf("custom: %+v", custom)
	}
	if st := f.Current(); !strings.Contains(st.Help, "algolia") {
		t.Errorf("added so far: %q", st.Help)
	}
	if lk := f.Lookup("algolia"); !lk.Found {
		t.Fatal("a staged technology counts as known")
	}
	// a plus on a catalog name is just the catalog name
	answer(t, f, "add-techs", "+php")
	if len(f.Custom()) != 2 || techIndex(f.Draft().Project.Techs, "php") < 0 {
		t.Fatalf("%+v", f.Draft().Project.Techs)
	}
	// a bad name changes nothing
	if err := f.Answer("+redis +!!"); err == nil || techIndex(f.Draft().Project.Techs, "redis") >= 0 {
		t.Fatalf("all or nothing: %v %+v", err, f.Draft().Project.Techs)
	}
}

func TestAddCustomWithKeywordsAndHints(t *testing.T) {
	f := NewFlow(customCatalog(), nil)
	toAddTechs(t, f)
	if err := f.AddCustom(model.Tech{Name: "Acme Gateway", Aliases: []string{"acme gateway", " Acme-GW ", "acme gateway"}, Category: "proxy", CPE: []string{" Acme:Gateway "}}); err != nil {
		t.Fatal(err)
	}
	c := f.Custom()
	if len(c) != 1 || c[0].Name != "acme-gateway" || strings.Join(c[0].Aliases, "|") != "acme gateway|Acme-GW" || c[0].CPE[0] != "acme:gateway" {
		t.Fatalf("%+v", c)
	}
	// with no keywords the typed name and its slug are the keywords
	if err := f.AddCustom(model.Tech{Name: "Foo Bar"}); err != nil {
		t.Fatal(err)
	}
	if got := f.Custom()[1].Aliases; strings.Join(got, "|") != "foo bar|foo-bar" {
		t.Fatalf("%v", got)
	}
	for _, bad := range []model.Tech{{Name: "!!"}, {Name: "mysql"}, {Name: "x", Category: "weird"}, {Name: "y", Aliases: []string{"a,b"}}} {
		if err := f.AddCustom(bad); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}

	hs, err := f.Hints()
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range hs {
		if h.Keyword != "" || strings.Contains(h.Message, "not in the catalog") {
			t.Errorf("staged technologies are known to the hints: %+v", h)
		}
	}
	found := false
	for _, h := range hs {
		found = found || h.Field == "techs[0]" && strings.Contains(h.Message, "your own keyword") && !strings.Contains(h.Message, "add a CPE")
	}
	if !found {
		// acme-gateway has a CPE, foo-bar has none
		for _, h := range hs {
			if h.Field == "techs[1]" && strings.Contains(h.Message, "add a CPE") {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("a keyword-only technology gets the CPE advice: %+v", hs)
	}
}

func TestRemoveCustomAndDeselect(t *testing.T) {
	f := NewFlow(customCatalog(), nil)
	toAddTechs(t, f)
	answer(t, f, "add-techs", "+algolia +akeneo")
	if err := f.RemoveCustom("algolia"); err != nil {
		t.Fatal(err)
	}
	if f.Lookup("algolia").Found || len(f.Custom()) != 1 || techIndex(f.Draft().Project.Techs, "algolia") >= 0 {
		t.Fatalf("%+v", f.Custom())
	}
	if err := f.RemoveCustom("mysql"); err == nil {
		t.Fatal("only staged ones can be removed")
	}
	// deselecting in the techs step drops the staged entry, so it is never written
	answer(t, f, "add-techs", "")
	f.Back()
	f.Back()
	if f.Current().ID != "techs" {
		t.Fatalf("at %s", f.Current().ID)
	}
	answer(t, f, "techs", "")
	if len(f.Custom()) != 0 || f.Lookup("akeneo").Found {
		t.Fatalf("%+v", f.Custom())
	}
}

func TestFlowHintsForANewProject(t *testing.T) {
	f := NewFlow(customCatalog(), nil)
	answer(t, f, "name", "shop")
	answer(t, f, "techs", "")
	answer(t, f, "add-techs", "php")
	answer(t, f, "add-techs", "")
	hs, err := f.Hints()
	if err != nil {
		t.Fatal(err)
	}
	has := func(field, msg string) bool {
		for _, h := range hs {
			if h.Field == field && strings.Contains(h.Message, msg) {
				return true
			}
		}
		return false
	}
	for field, msg := range map[string]string{"techs[0].version": "no version", "lockfiles": "no lockfile", "since": "no start date", "envs": "no prod"} {
		if !has(field, msg) {
			t.Errorf("missing %s %q in %+v", field, msg, hs)
		}
	}
}
