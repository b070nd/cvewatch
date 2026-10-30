package tui

import (
	"strings"
	"testing"
)

// assistTo moves the cursor over the rows the add-techs step offers to the one whose label has text.
func (d *driver) assistTo(text string) {
	d.t.Helper()
	a := d.m.(*app)
	for range 40 {
		if hasAssist(a) && a.frm.ta.focus && strings.Contains(a.frm.ta.rows[a.frm.ta.vp.at()].label, text) {
			return
		}
		d.press("down")
	}
	d.t.Fatalf("no row %q among the suggestions:\n%s", text, d.view())
}

// toAddTechs starts the guided new project and goes to the step that adds technologies by name.
func (d *driver) toAddTechs() {
	d.t.Helper()
	d.press("3", "a")
	for i := 0; i < 8 && d.m.(*app).frm.step.ID != "add-techs"; i++ {
		d.press("enter")
	}
	if d.m.(*app).frm.step.ID != "add-techs" {
		d.t.Fatalf("not at the step:\n%s", d.view())
	}
}

func TestUnknownWordsAreExplainedAndCanBeKeptAsOwnKeywords(t *testing.T) {
	b, root := diskFake(t, nil)
	d := start(t, b, Options{})
	d.toAddTechs()
	d.typ("algolia akeneo channable gcp rabbitMW myssql")
	d.press("enter")

	f := d.m.(*app).frm
	if f.step.ID != "add-techs" {
		t.Fatalf("the answer must be refused, step %q", f.step.ID)
	}
	for _, want := range []string{`"algolia" is not in the catalog`, `"akeneo" is not in the catalog`, `"channable" is not in the catalog`, `"gcp" is not in the catalog`,
		`"rabbitMW" is not in the catalog`, "rabbitmq", `"myssql" is not in the catalog`, "mysql"} {
		if !strings.Contains(f.step.Problem, want) {
			t.Errorf("the reason lacks %q:\n%s", want, f.step.Problem)
		}
	}
	for _, unrelated := range []string{"exchange", "dovecot"} {
		if strings.Contains(f.step.Problem, unrelated) {
			t.Errorf("%s has nothing to do with the typed words:\n%s", unrelated, f.step.Problem)
		}
		for _, r := range f.ta.rows {
			if r.name == unrelated {
				t.Errorf("%s is offered", unrelated)
			}
		}
	}
	d.want("Not in the catalog", `"rabbitMW": use rabbitmq`, `"myssql": use mysql`, `"algolia": add as my own keyword`, "add all 4 words")
	if b.writes != 0 || d.exists(root, "config/techs.yaml") {
		t.Fatal("explaining wrote something")
	}

	// the typos are replaced by the names offered, the rest becomes the person's own keywords
	d.assistTo(`"rabbitMW": use rabbitmq`)
	d.press("enter")
	d.assistTo(`"myssql": use mysql`)
	d.press("enter")
	if got := f.in.String(); got != "algolia akeneo channable gcp rabbitmq mysql" {
		t.Fatalf("text %q", got)
	}
	d.assistTo("add all 4 words")
	d.press("enter")
	if got := f.in.String(); got != "+algolia +akeneo +channable +gcp rabbitmq mysql" {
		t.Fatalf("text %q", got)
	}
	if hasAssist(d.m.(*app)) {
		t.Fatalf("nothing is left to offer:\n%s", d.view())
	}
	d.press("enter")
	d.want("Add other technologies", "Added so far: ")
	d.press("enter")
	d.toReview()
	d.want("config/techs.yaml: your own technologies", "algolia", "gcp")

	before := b.writes
	d.press("y")
	d.want("ok: created project project")
	if b.writes != before+1 {
		t.Fatalf("the project and the technologies are one write, got %d", b.writes-before)
	}
	file := fileAt(t, root, "config/projects/project.yaml")
	for _, n := range []string{"algolia", "akeneo", "channable", "gcp", "rabbitmq", "mysql"} {
		if !strings.Contains(file, "name: "+n) {
			t.Errorf("the project lacks %s:\n%s", n, file)
		}
	}
	techs := fileAt(t, root, "config/techs.yaml")
	for _, n := range []string{"algolia", "akeneo", "channable", "gcp"} {
		if !strings.Contains(techs, "name: "+n) {
			t.Errorf("techs.yaml lacks %s:\n%s", n, techs)
		}
	}
	if strings.Contains(techs, "rabbitmq") || strings.Contains(techs, "mysql") {
		t.Errorf("catalog technologies do not go to techs.yaml:\n%s", techs)
	}
}

func TestCtrlOAsksForTheKeywordsOfAnOwnTechnology(t *testing.T) {
	b, root := diskFake(t, nil)
	d := start(t, b, Options{})
	d.toAddTechs()
	d.typ("acme")
	d.press("ctrl+o")
	d.want("Add acme as your own keyword", "> Name", "acme", "Keywords", "Category", "CPE")
	d.press("esc")
	d.wantNot("Keywords")
	d.press("ctrl+o", "ctrl+u")
	d.typ("Acme Gateway")
	d.press("enter")
	d.typ("acme gateway, acme-gw")
	d.press("enter")
	d.typ("not-a-category")
	d.press("enter", "enter")
	d.want("problem: unknown category")
	d.press("shift+tab", "ctrl+u")
	d.typ("network")
	d.press("enter", "enter")
	if a := d.m.(*app); a.prm != nil {
		t.Fatalf("the prompt should be closed:\n%s", d.view())
	}
	d.want("Added so far: acme-gateway", "ok: added acme-gateway as your own keyword")
	if got := d.m.(*app).frm.in.String(); got != "" {
		t.Fatalf("the word answered leaves the text, got %q", got)
	}
	if d.exists(root, "config/techs.yaml") {
		t.Fatal("nothing is written before the project is saved")
	}
	d.press("enter")
	d.toReview()
	d.want("config/techs.yaml: your own technologies", "name: acme-gateway")
	d.press("y")
	d.want("ok: created project")
	techs := fileAt(t, root, "config/techs.yaml")
	for _, w := range []string{"name: acme-gateway", "acme gateway", "acme-gw", "category: network"} {
		if !strings.Contains(techs, w) {
			t.Errorf("techs.yaml lacks %q:\n%s", w, techs)
		}
	}
}

const hintSvc = "name: svc\nenvs: [prod]\ntechs:\n  - {name: myssql, version: \"8\"}\n  - {name: algolia, version: \"1\"}\n"

func TestProjectsListCountsHintsAndThePageListsThem(t *testing.T) {
	b, _ := diskFake(t, map[string]string{"config/projects/svc.yaml": hintSvc})
	d := start(t, b, Options{})
	d.press("3")
	d.want("HINTS", "hints")
	d.press("down", "down") // mw, shop, svc in order of the list
	for i := 0; i < 3 && !strings.Contains(d.view(), "> svc"); i++ {
		d.press("down")
	}
	d.press("enter")
	d.want("Hints", `"myssql" is not in the catalog`, "Did you mean", `"algolia" is not in the catalog`, "H works through them")
}

func TestHintOnATypoReplacesItAfterAPreview(t *testing.T) {
	b, root := diskFake(t, map[string]string{"config/projects/svc.yaml": hintSvc})
	d := start(t, b, Options{})
	d.press("3")
	for i := 0; i < 3 && !strings.Contains(d.view(), "> svc"); i++ {
		d.press("down")
	}
	d.press("H")
	d.want("Hints", `warn techs[0]: "myssql" is not in the catalog`, "choose: mysql")
	d.press("enter")
	d.want("Instead of myssql", "use mysql", "keep myssql as my own keyword")
	d.press("enter")
	d.want("Save this change?", `use technology name "mysql" instead of "myssql"`, "{name: myssql", "{name: mysql")
	before := b.writes
	d.press("y")
	d.want("ok: saved svc")
	if b.writes != before+1 {
		t.Fatalf("writes %d", b.writes-before)
	}
	if got := fileAt(t, root, "config/projects/svc.yaml"); !strings.Contains(got, "name: mysql") || strings.Contains(got, "myssql") {
		t.Fatalf("project file:\n%s", got)
	}
}

func TestHintOnAnUnknownTechnologyAddsItAsAKeywordAndTheHintGoes(t *testing.T) {
	b, root := diskFake(t, map[string]string{"config/projects/svc.yaml": "name: svc\nenvs: [prod]\ntechs:\n  - {name: algolia, version: \"1\"}\n"})
	d := start(t, b, Options{})
	d.press("3")
	for i := 0; i < 3 && !strings.Contains(d.view(), "> svc"); i++ {
		d.press("down")
	}
	d.press("enter")
	d.want(`"algolia" is not in the catalog`)
	d.press("H", "enter")
	d.want("Add algolia as your own keyword", "Keywords")
	d.press("enter", "enter", "enter", "enter")
	d.want("ok: added algolia to techs.yaml")
	techs := fileAt(t, root, "config/techs.yaml")
	if !strings.Contains(techs, "name: algolia") {
		t.Fatalf("techs.yaml:\n%s", techs)
	}
	d.wantNot(`"algolia" is not in the catalog`)
	if got := fileAt(t, root, "config/projects/svc.yaml"); !strings.Contains(got, "algolia") {
		t.Fatalf("the project is as it was:\n%s", got)
	}
}

func TestReviewHintsReplaceATypoAndKeepAnUnknownTechnologyAsAKeyword(t *testing.T) {
	b, root := diskFake(t, map[string]string{"config/projects/svc.yaml": hintSvc})
	d := start(t, b, Options{})
	d.press("3")
	for i := 0; i < 3 && !strings.Contains(d.view(), "> svc"); i++ {
		d.press("down")
	}
	d.press("e", "end", "enter")
	d.want("Save this project?", "Hints", `"myssql" is not in the catalog`, "H hints")
	d.wantNot("warning: techs[0]") // the hint says it, once

	d.press("H")
	d.want("warn techs[0]", "choose: mysql")
	d.press("enter")
	d.want("Instead of myssql", "use mysql")
	d.press("enter")
	d.want("Save this project?", "using mysql instead of myssql", "+   - {name: mysql")
	d.wantNot(`"myssql" is not in the catalog`)

	d.press("H")
	d.want("warn techs[", `"algolia" is not in the catalog`, "add it as your own keyword")
	d.press("enter")
	d.want("Add algolia as your own keyword")
	d.press("enter", "enter", "enter", "enter")
	d.want("Save this project?", "config/techs.yaml: your own technologies", "name: algolia")
	d.wantNot(`"algolia" is not in the catalog`)

	before := b.writes
	d.press("y")
	d.want("ok: saved project svc")
	if b.writes != before+1 {
		t.Fatalf("one write session, got %d", b.writes-before)
	}
	file := fileAt(t, root, "config/projects/svc.yaml")
	if !strings.Contains(file, "name: mysql") || !strings.Contains(file, "name: algolia") || strings.Contains(file, "myssql") {
		t.Fatalf("project:\n%s", file)
	}
	if !strings.Contains(fileAt(t, root, "config/techs.yaml"), "name: algolia") {
		t.Fatal("techs.yaml lacks algolia")
	}
}

// pickTo moves the cursor of the open list to the row whose label has text.
func (d *driver) pickTo(text string) {
	d.t.Helper()
	a := d.m.(*app)
	pk := a.pickerOf()
	for range 40 {
		if pk != nil && pk.vp.at() < len(pk.items) && strings.Contains(pk.items[pk.vp.at()].label, text) {
			return
		}
		d.press("down")
	}
	d.t.Fatalf("no row %q in the list:\n%s", text, d.view())
}

func TestHintsOpenTheEditorThatSettlesThem(t *testing.T) {
	b, root := diskFake(t, map[string]string{"config/projects/web.yaml": "name: web\nenvs: [prod]\ntechs:\n  - {name: php}\n"})
	d := start(t, b, Options{})
	d.press("3")
	for i := 0; i < 3 && !strings.Contains(d.view(), "> web"); i++ {
		d.press("down")
	}
	d.press("H")
	d.want("Hints")
	d.pickTo(".version")
	d.press("enter")
	d.want("Version of php in web")
	d.typ("8.3")
	d.press("enter")
	d.want("Save this change?", `version: "8.3"`)
	d.press("y")
	d.want("ok: saved web")
	if !strings.Contains(fileAt(t, root, "config/projects/web.yaml"), "8.3") {
		t.Fatal("the version is in the file")
	}

	d.press("H")
	d.pickTo("since")
	d.press("enter")
	d.want("Since date of web")
	d.press("esc")

	// the review of a project being set up sends the hint to its step
	d.press("e", "end", "enter")
	d.want("Save this project?")
	d.press("H")
	d.pickTo("since")
	d.press("enter")
	d.want("Save this project?", "since is set once the project is saved")
	d.press("H")
	d.pickTo("lockfiles")
	d.press("enter")
	d.want("Add a lockfile to the project being set up")
}

func TestHintsKeyIsQuietWithoutHints(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	d.press("3")
	d.wantNot("hints  ")
	d.press("H")
	d.wantNot("Hints", "Instead of")
}

func TestSettingsTechnologiesAreAddedChangedAndRemovedThroughOps(t *testing.T) {
	d, root := setStart(t, nil)
	d.toSetting("techs")
	d.want("Technologies")
	d.press("a")
	d.want("Add a technology of your own", "Name", "Keywords", "Category", "CPE")
	d.typ("Algolia Search")
	d.press("enter")
	d.typ("algolia, algolia search")
	d.press("enter")
	d.typ("search")
	d.press("enter", "enter")
	d.want("Change settings: add algolia-search to Technologies", "techs.yaml", "name: algolia-search")
	d.press("y")
	d.want("saved: add algolia-search to Technologies")
	techs := fileAt(t, root, "config/techs.yaml")
	for _, w := range []string{"name: algolia-search", "category: search", "algolia search"} {
		if !strings.Contains(techs, w) {
			t.Fatalf("techs.yaml lacks %q:\n%s", w, techs)
		}
	}

	// a name the catalog has is refused in the prompt, which stays open
	d.toSetting("techs")
	d.press("a")
	d.typ("php")
	d.press("enter", "enter", "enter", "enter")
	d.want("problem:", "already in the catalog")
	d.press("esc")

	d.toSetting("techs")
	d.press("e")
	d.want("Change algolia-search", "Keywords: algolia, algolia search")
	d.press("tab", "ctrl+u")
	d.typ("algolia")
	d.press("enter", "enter", "enter")
	d.want("Change settings: change algolia-search in Technologies")
	d.press("y")
	d.want("saved: change algolia-search in Technologies")
	techs = fileAt(t, root, "config/techs.yaml")
	if strings.Contains(techs, "algolia search") || !strings.Contains(techs, "algolia") {
		t.Fatalf("techs.yaml:\n%s", techs)
	}

	d.toSetting("techs")
	d.press("home", "x")
	d.want("Change settings: remove algolia-search from Technologies")
	d.press("y")
	d.want("saved: remove algolia-search from Technologies")
	if strings.Contains(fileAt(t, root, "config/techs.yaml"), "algolia-search") {
		t.Fatal("the technology should be gone")
	}
}

func TestOwnTechnologyIsAddedToAProjectAndTechsYamlInOnePreview(t *testing.T) {
	b, root := diskFake(t, nil)
	d := start(t, b, Options{})
	d.press("3", "down", "c", "down", "enter") // shop: fields, technologies
	d.want("TECHNOLOGY", "K own tech")
	d.press("K")
	d.want("Add your own technology to shop", "Name")
	d.typ("Algolia")
	d.press("enter")
	d.typ("algolia")
	d.press("enter", "enter", "enter")
	d.want("Save this change?", "add your own technology algolia", "config/techs.yaml: your own technologies", "name: algolia", "{name: algolia}")
	if b.writes != 0 {
		t.Fatal("previewing wrote something")
	}
	before := b.writes
	d.press("y")
	d.want("ok: saved shop")
	if b.writes != before+1 {
		t.Fatalf("one write session, got %d", b.writes-before)
	}
	if !strings.Contains(fileAt(t, root, "config/projects/shop.yaml"), "name: algolia") || !strings.Contains(fileAt(t, root, "config/techs.yaml"), "name: algolia") {
		t.Fatal("both files have it")
	}
}

func TestAssistRowsFollowTheTextAndEscGoesBackToIt(t *testing.T) {
	b, _ := diskFake(t, nil)
	d := start(t, b, Options{})
	d.toAddTechs()
	d.typ("rabbitMW")
	d.press("enter")
	d.want("Not in the catalog", `"rabbitMW": use rabbitmq`)
	d.press("down")
	d.want("enter takes the selected row")
	d.press("esc")
	d.want("Add other technologies") // esc only left the rows
	if a := d.m.(*app); a.frm.ta.focus || a.frm.step.ID != "add-techs" {
		t.Fatal("esc must go back to the text, not leave the step")
	}
	d.press("backspace")
	d.wantNot("Not in the catalog") // the rows were about the old text
	d.press("ctrl+u")
	d.typ("zzzz")
	d.press("enter")
	d.want("Not in the catalog", `"zzzz": add as my own keyword`)
	d.wantNot("add all")

	// with the cursor on the text, enter answers: a word the catalog has is taken
	d.press("ctrl+u")
	d.typ("redis rabbitmq")
	d.press("enter")
	d.wantNot("Not in the catalog")
	d.want("Added so far: ")
	d.press("ctrl+o")
	d.want("nothing to add")
}

func TestTechnologyKeysAreInTheTablesAndTheHelp(t *testing.T) {
	has := func(md *mode, key, help string) {
		t.Helper()
		found := false
		for _, b := range md.binds {
			found = found || (b.has(key) && b.short != "" && strings.Contains(b.help, help))
		}
		if !found {
			t.Errorf("%s: no footer key %q about %q", md.name, key, help)
		}
		if !strings.Contains(strings.Join(helpLines(md, 100), "\n"), help) {
			t.Errorf("%s: help lacks %q", md.name, help)
		}
	}
	has(mo.formText, "ctrl+o", "as your own keyword")
	has(mo.formText, "up", "rows offered")
	has(mo.formText, "enter", "take the selected row")
	has(mo.formReview, "H", "hints")
	has(mo.projects, "H", "hints of the project")
	has(mo.project, "H", "hints of the project")
	has(mo.fieldSub, "K", "one of your own")
	has(mo.setFields, "e", "category and CPE")
}

func TestReplaceTechKeepsTheVersionAndStagedKeywordsFollow(t *testing.T) {
	b, _ := diskFake(t, map[string]string{"config/projects/svc.yaml": hintSvc})
	d := start(t, b, Options{})
	d.press("3")
	for i := 0; i < 3 && !strings.Contains(d.view(), "> svc"); i++ {
		d.press("down")
	}
	d.press("e", "end", "enter")
	d.press("H", "enter", "enter")
	d.want("using mysql instead of myssql", `version: "8"`)
}
