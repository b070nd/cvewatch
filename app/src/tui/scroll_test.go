package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/b070nd/cvewatch/app/src/ledger"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/ops"
	"github.com/b070nd/cvewatch/app/src/query"
	"github.com/b070nd/cvewatch/app/src/setup"
)

func addProjects(b *fake, n int) {
	for i := 0; i < n; i++ {
		b.cfg.Projects = append(b.cfg.Projects, model.Project{Name: fmt.Sprintf("app%02d", i)})
	}
}

func selectedName(t *testing.T, d *driver) string {
	t.Helper()
	p, ok := d.m.(*app).selectedProject()
	if !ok {
		t.Fatal("no project selected")
	}
	return p.Name
}

func TestProjectsPageAndJumpKeys(t *testing.T) {
	b := newFake(t, nil)
	addProjects(b, 40)
	d := start(t, b, Options{})
	d.send(tea_window(100, 24))
	d.press("3")
	a := d.m.(*app)
	rows := a.data.Projects
	vp := &a.prj.proj
	page := vp.page()
	if page < 3 || page > 20 {
		t.Fatalf("page %d", page)
	}

	at := func(want int) {
		t.Helper()
		if vp.at() != want {
			t.Fatalf("cursor at %d, want %d", vp.at(), want)
		}
		d.want("> " + rows[want].Name)
	}
	d.press("pgdown")
	at(page)
	d.press("pgdown")
	at(2 * page)
	d.press("pgup")
	at(page)
	d.press("end")
	at(len(rows) - 1)
	d.press("pgdown")
	at(len(rows) - 1)
	d.press("home")
	at(0)
	d.press("pgup")
	at(0)
	d.press("G")
	at(len(rows) - 1)
	d.press("g")
	at(0)
	d.press("j", "j", "k")
	at(1)
}

func TestProjectsCursorStaysOnItsProjectWhenRowsChange(t *testing.T) {
	b := newFake(t, nil)
	addProjects(b, 6)
	d := start(t, b, Options{})
	d.press("3", "G")
	if selectedName(t, d) != "app05" {
		t.Fatalf("selected %q", selectedName(t, d))
	}

	b.cfg.Projects = b.cfg.Projects[2:] // shop and mw are gone
	d.press("r")
	if selectedName(t, d) != "app05" {
		t.Fatalf("the cursor slid to %q", selectedName(t, d))
	}
	d.want("> app05")

	b.cfg.Projects = append([]model.Project{{Name: "aaa"}, {Name: "aab"}}, b.cfg.Projects...)
	d.press("r")
	if selectedName(t, d) != "app05" {
		t.Fatalf("the cursor slid to %q", selectedName(t, d))
	}

	b.cfg.Projects = b.cfg.Projects[:len(b.cfg.Projects)-1] // its own project is gone
	d.press("r")
	if n := selectedName(t, d); n != "app04" {
		t.Fatalf("the cursor must stay in the list, on %q", n)
	}
}

func TestProjectsProblemCursorFollowsItsProblemAndRestartsOnAnotherProject(t *testing.T) {
	b := newFake(t, nil)
	writeProjectFile(t, b.cfg.Root, "shop", shopWithProblems)
	d := start(t, b, Options{})
	d.press("3", "p")
	d.want("> warning")
	d.press("r")
	d.want("> warning") // a reload keeps the problem
	d.press("down", "up")
	d.want("> error") // another project and back starts on the first problem
}

func TestFindingsListPagesAndJumps(t *testing.T) {
	st := seed(t, func(l *ledger.Ledger) {
		for i := 0; i < 40; i++ {
			id := fmt.Sprintf("CVE-2026-9%02d", i)
			v := l.Create(model.Item{Title: "Bulk " + id, URL: "https://a.test/" + id, IDs: []string{id}, Severity: model.SevMedium,
				Published: t0, SourceID: "hn", SourceType: "hn"}, t0, []string{"php"})
			l.AddFinding(model.Finding{VulnID: v.ID, Project: "shop", Env: model.EnvDev, Status: model.StatusOpen, Applies: model.AppUnknown})
		}
	})
	d := start(t, newFake(t, st), Options{})
	d.press("2")
	a := d.m.(*app)
	vp := &a.fnd.vp
	if len(a.fnd.vis) != 43 {
		t.Fatalf("%d issues", len(a.fnd.vis))
	}
	page := vp.page()
	d.press("pgdown")
	if vp.at() != page {
		t.Fatalf("at %d, want %d", vp.at(), page)
	}
	d.want("> " + sevWord(a.fnd.vis[page].Severity))
	d.press("end")
	d.want("> low", "CVE-2026-4") // the lowest severity is last
	d.press("pgup")
	if vp.at() != len(a.fnd.vis)-1-page {
		t.Fatalf("at %d", vp.at())
	}
	d.press("home")
	d.want("> critical")
	d.press("G", "g")
	d.want("> critical")
}

func TestTextScreensAndHelpScroll(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	d.send(tea_window(80, 10))
	a := d.m.(*app)
	d.want("daemon:")
	d.press("pgdown")
	if a.txt[scrOverview].at() != 5 {
		t.Fatalf("a page is the body (6 lines) minus one, scrolled to %d", a.txt[scrOverview].at())
	}
	d.wantNot("daemon:")
	d.press("end")
	d.want("Policy violations")
	d.press("home")
	d.want("daemon:")
	d.press("G", "g")
	d.want("daemon:")

	d.press("4", "end")
	d.want("Recent cycles")
	d.press("home")
	d.want("Overall")

	d.press("?")
	d.want("Keys")
	d.press("end")
	d.want("NO_COLOR")
	d.press("home")
	d.want("Keys")
	d.wantNot("NO_COLOR")
	d.press("?")
	d.want("Overall")
}

func TestDetailPageScrollsAndKeepsItsLayoutWhileTheRowMoves(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	d.send(tea_window(100, 12))
	d.press("2", "down", "enter")
	a := d.m.(*app)
	det := a.fnd.det
	lay := det.lay
	if lay == nil || len(lay.rows) != 2 {
		t.Fatalf("layout %+v", lay)
	}
	d.press("down")
	d.want("> shop")
	d.press("up")
	d.want("> mw")
	d.press("down", "down", "up")
	if det.lay != lay {
		t.Fatal("the page was laid out again for a move of the row")
	}
	d.press("home", "pgdown")
	if det.body.at() != det.body.page() {
		t.Fatalf("scrolled to %d, a page is %d", det.body.at(), det.body.page())
	}
	d.press("home")
	d.want("CVE-2026-1")
	d.press("G")
	d.want("first seen by cvewatch")
	d.press("g")
	d.wantNot("first seen by cvewatch")
	d.press("down") // the selected row is scrolled into view
	d.want("> shop")
	d.send(tea_window(90, 12))
	if det.lay == lay || det.lay.w != 90 {
		t.Fatal("a new width needs a new layout")
	}
}

func TestDetailKeepsTheEnvironmentRowByProjectAndEnv(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	a := d.m.(*app)
	a.fnd.det = &detail{id: "X", body: scrolling()}
	target := func(p string) query.Target { return query.Target{Project: p, Env: model.EnvProd} }
	a.detailLoaded(detailMsg{id: "X", is: query.Issue{ID: "X", Targets: []query.Target{target("b"), target("c")}}})
	a.fnd.det.sel.handle("down")
	if a.fnd.det.sel.id() != "c/prod" {
		t.Fatalf("id %q", a.fnd.det.sel.id())
	}
	a.detailLoaded(detailMsg{id: "X", is: query.Issue{ID: "X", Targets: []query.Target{target("a"), target("b"), target("c")}}})
	if got := a.fnd.det.sel.at(); got != 2 {
		t.Fatalf("a row appeared above: selected row %d, want 2", got)
	}
	a.detailLoaded(detailMsg{id: "X", is: query.Issue{ID: "X", Targets: []query.Target{target("a")}}})
	if got := a.fnd.det.sel.at(); got != 0 {
		t.Fatalf("its row is gone: selected row %d", got)
	}
}

func TestFormListsPageAndJump(t *testing.T) {
	for _, kind := range []setup.Kind{setup.KindChoice, setup.KindMulti} {
		d := start(t, newFake(t, nil), Options{})
		d.send(tea_window(80, 16))
		d.press("3", "n")
		f := d.m.(*app).frm
		var opts []setup.Option
		for i := 0; i < 30; i++ {
			opts = append(opts, setup.Option{Value: fmt.Sprintf("o%02d", i), Label: fmt.Sprintf("option %02d", i)})
		}
		f.step = setup.Step{ID: "test", Title: "Pick", Kind: kind, Options: opts}
		f.vp.reset(len(opts))
		d.send(tea_window(80, 16)) // any message lays the step out
		page := f.vp.page()
		if page < 2 {
			t.Fatalf("page %d", page)
		}
		at := func(want int) {
			t.Helper()
			if f.vp.at() != want {
				t.Fatalf("%v: at %d, want %d", kind, f.vp.at(), want)
			}
			if !regexp.MustCompile(fmt.Sprintf(`(?m)^> (\[.\] )?option %02d`, want)).MatchString(d.view()) {
				t.Fatalf("%v: option %02d not highlighted:\n%s", kind, want, d.view())
			}
			if n := strings.Count(d.view(), "\n") + 1; n > 16 {
				t.Fatalf("%d lines on a 16 line screen", n)
			}
		}
		d.press("pgdown")
		at(page)
		d.press("pgdown")
		at(2 * page)
		d.press("pgup")
		at(page)
		d.press("end")
		at(29)
		d.press("home")
		at(0)
		d.press("G")
		at(29)
		d.press("g")
		at(0)
		d.press("j", "j", "k")
		at(1)
	}
}

func TestFormReviewScrollsWithPageKeys(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	d.send(tea_window(80, 12))
	d.press("3", "n")
	f := d.m.(*app).frm
	f.step = setup.Step{ID: "review", Kind: setup.KindConfirm}
	f.rev.reset(0)
	var diff []string
	for i := 0; i < 30; i++ {
		diff = append(diff, fmt.Sprintf("+ line %02d", i))
	}
	f.prev = &ops.ProjectPreview{Path: "p", Diff: strings.Join(diff, "\n")}
	d.send(tea_window(80, 12))
	d.want("+ line 00")
	d.press("pgdown")
	d.wantNot("+ line 00")
	d.press("end")
	d.want("+ line 29")
	d.press("home")
	d.want("+ line 00")
}

func TestFolderRowsFitSmallTerminals(t *testing.T) {
	for h, want := range map[int]int{8: 0, 10: 0, 11: 1, 12: 2, 13: 3, 16: 3, 17: 4, 20: 7, 23: 10, 24: 10, 60: 10} {
		if got := folderRows(h); got != want {
			t.Errorf("folderRows(%d) = %d, want %d", h, got, want)
		}
	}
}

func TestFolderBoxShowsSuggestionsOnASmallTerminal(t *testing.T) {
	folderTree(t)
	d := start(t, newFake(t, nil), Options{})
	d.send(tea_window(80, 14))
	d.press("3", "d")
	d.want("Scan a folder", "4 folders", "zeta-app")
	if n := strings.Count(d.view(), "\n") + 1; n > 14 {
		t.Fatalf("%d lines on a 14 line screen", n)
	}
	d.press("down", "down", "down", "down", "down")
	d.want("> shopify")
}

func TestFolderBoxPagesThroughSuggestions(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 30; i++ {
		os.MkdirAll(filepath.Join(root, fmt.Sprintf("dir%02d", i)), 0o755)
	}
	t.Chdir(root)
	d := start(t, newFake(t, nil), Options{})
	d.send(tea_window(80, 24))
	d.press("3", "d")
	b := d.m.(*app).prm.box
	d.press("pgdown")
	if b.sel() != b.vp.page()-1 {
		t.Fatalf("from no selection a page lands on row %d", b.sel())
	}
	d.press("pgdown", "pgdown", "pgdown", "pgdown")
	if b.sel() != 29 {
		t.Fatalf("sel %d", b.sel())
	}
	d.want("> dir29")
	d.press("pgup")
	d.want("> dir")
	d.typ("x") // typing resets the highlight; home and end belong to the text
	if b.sel() != -1 {
		t.Fatalf("sel %d", b.sel())
	}
}

func TestHelpOpensInAFormStep(t *testing.T) {
	b := newFake(t, nil)
	writeProjectFile(t, b.cfg.Root, "shop", "name: shop\ntechs:\n  - {name: php, version: \"8.2\"}\n  - {name: nginx}\n")
	d := start(t, b, Options{})
	d.press("3", "e")
	d.want("What do you want to change?", "? help")
	d.press("?")
	d.want("Keys in the project form")
	d.press("?")
	d.want("What do you want to change?")
	d.wantNot("Keys in the project form")

	d.press("esc", "n", "ctrl+u", "?") // a text step takes the question mark as text
	d.want("> ?")
	d.wantNot("Keys in the project form")
}
