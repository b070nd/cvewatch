package tui

import (
	"os"
	"strings"
	"testing"
	"unicode/utf8"

	tea "github.com/charmbracelet/bubbletea"
)

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestEveryModeIsConsistent(t *testing.T) {
	a := start(t, newFake(t, nil), Options{}).m.(*app)
	for _, md := range allModes() {
		seen := map[string]bool{}
		always := map[string]bool{}
		for _, b := range md.binds {
			if b.help == "" {
				t.Errorf("%s: binding %q has no help label", md.name, b.shown())
			}
			if len(b.keys) > 0 && b.do == nil {
				t.Errorf("%s: binding %q has no action", md.name, b.shown())
			}
			if b.short != "" && b.alias {
				t.Errorf("%s: alias %q is in the footer", md.name, b.shown())
			}
			for _, k := range b.keys {
				if always[k] { // the same key may serve different states, but only until one that is always on
					t.Errorf("%s: key %q is bound twice", md.name, k)
				}
				seen[k] = true
				always[k] = b.when == nil
				if md.typed != nil && utf8.RuneCountInString(k) == 1 && k != "\x00" {
					t.Errorf("%s: %q is typed into the field, it cannot be a binding", md.name, k)
				}
			}
		}
		for _, k := range moveKeys {
			if md.move != nil && seen[k] {
				t.Errorf("%s: %q is a movement key, the viewport owns it", md.name, k)
			}
		}
		for _, w := range []int{30, 80} {
			line := md.footerLine(a, w)
			if width(line) > w {
				t.Errorf("%s: footer is %d cells at width %d: %q", md.name, width(line), w, line)
			}
		}
		line := md.footerLine(a, 80)
		switch md {
		case mo.confirm, mo.formBusy:
		case mo.help:
			if !strings.Contains(line, "close help") {
				t.Errorf("%s: footer %q", md.name, line)
			}
		default:
			want := "? help"
			if md.typed != nil {
				want = "f1 help"
			}
			if !strings.Contains(line, want) {
				t.Errorf("%s: footer lacks %q: %q", md.name, want, line)
			}
		}
		for _, l := range helpLines(md, 80) {
			if width(l) > 80 {
				t.Errorf("%s: help line is %d cells: %q", md.name, width(l), l)
			}
		}
		if h := strings.Join(helpLines(md, 80), "\n"); !strings.Contains(h, md.title) || !strings.Contains(h, "Everywhere") {
			t.Errorf("%s: help lacks its heading", md.name)
		}
	}
}

func TestViewportHandlesTheSharedMovementKeys(t *testing.T) {
	for _, k := range moveKeys {
		v := list(30, 10)
		v.to(15)
		if !v.handle(k) {
			t.Errorf("the viewport does not handle %q", k)
		}
	}
}

func TestFootersFitInEveryLiveState(t *testing.T) {
	b := newFake(t, nil)
	writeProjectFile(t, b.cfg.Root, "shop", shopWithProblems)
	d := start(t, b, Options{})
	d.send(tea_window(80, 24))
	check := func(label, want string) {
		t.Helper()
		lines := strings.Split(d.view(), "\n")
		foot := lines[len(lines)-1]
		if width(foot) > 80 {
			t.Errorf("%s: footer is %d cells: %q", label, width(foot), foot)
		}
		if !strings.Contains(foot, want) {
			t.Errorf("%s: footer lacks %q: %q", label, want, foot)
		}
	}
	check("overview", "q quit")
	d.press("2")
	check("findings", "enter open")
	d.press("/")
	check("filter", "esc clear")
	d.press("esc", "enter")
	check("detail", "back")
	d.press("f")
	check("prompt", "esc cancel")
	d.press("esc", "esc", "3")
	check("projects", "enter open")
	d.press("enter")
	check("project", "enter fix")
	d.press("x")
	check("fix", "esc cancel")
	d.press("esc", "esc", "d")
	check("folder", "esc cancel")
	d.press("esc", "a")
	check("form", "back")
	d.press("f1")
	check("help", "close help")
}

func crumbOf(d *driver) string {
	line := strings.Split(d.view(), "\n")[1]
	return strings.TrimSpace(strings.TrimRight(line, "─ "))
}

func TestBreadcrumbAtEveryLevel(t *testing.T) {
	b := newFake(t, nil)
	writeProjectFile(t, b.cfg.Root, "shop", shopWithProblems)
	d := start(t, b, Options{})
	for key, want := range map[string]string{"1": "Overview", "2": "Findings", "3": "Projects", "4": "Status"} {
		d.press(key)
		if got := crumbOf(d); got != want {
			t.Errorf("screen %s: breadcrumb %q", key, got)
		}
	}
	d.press("2", "down", "enter")
	if got := crumbOf(d); got != "Findings › CVE-2026-1 › mw:prod" {
		t.Errorf("detail: %q", got)
	}
	d.press("down")
	if got := crumbOf(d); got != "Findings › CVE-2026-1 › shop:prod" {
		t.Errorf("detail row: %q", got)
	}
	d.press("esc", "3")
	d.press("enter")
	if got := crumbOf(d); got != "Projects › shop › problem: lockfile gone/composer.lock does not exist" {
		t.Errorf("project: %q", got)
	}
	d.press("down")
	if got := crumbOf(d); !strings.HasPrefix(got, "Projects › shop › problem: technology") {
		t.Errorf("second problem: %q", got)
	}
	d.press("enter")
	if got := crumbOf(d); !strings.HasPrefix(got, "Projects › shop › problem: technology") || !strings.HasSuffix(got, "› fix") {
		t.Errorf("fix: %q", got)
	}
	d.press("esc", "esc", "a")
	if got := crumbOf(d); got != "Projects › add project › Project name" {
		t.Errorf("form: %q", got)
	}
	d.press("ctrl+u")
	d.typ("blog")
	d.press("enter")
	if got := crumbOf(d); got != "Projects › add project › Technologies" {
		t.Errorf("form step: %q", got)
	}
}

func TestBreadcrumbIsTruncatedFromTheLeft(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	d.press("2", "down", "enter")
	for _, w := range []int{30, 32, 40, 60} {
		d.send(tea_window(w, 20))
		line := strings.Split(d.view(), "\n")[1]
		if width(line) > w {
			t.Errorf("width %d: the breadcrumb is %d cells: %q", w, width(line), line)
		}
		if strings.Count(d.view(), "\n")+1 > 20 {
			t.Errorf("width %d: too many lines", w)
		}
	}
	d.send(tea_window(30, 20))
	line := strings.TrimRight(strings.Split(d.view(), "\n")[1], "─ ")
	if !strings.HasPrefix(line, "…") || !strings.HasSuffix(line, "mw:prod") {
		t.Errorf("a long path loses its start: %q", line)
	}
	d.send(tea_window(80, 20))
	if line := strings.Split(d.view(), "\n")[1]; strings.Contains(line, "…") {
		t.Errorf("a short path is whole: %q", line)
	}
}

func TestLeftAndRightSwitchScreensAtTheRoot(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	for _, c := range []struct{ key, want string }{
		{"right", "[2 Findings"}, {"right", "[3 Projects]"}, {"l", "[4 Status]"}, {"right", "[5 Settings]"}, {"right", "[1 Overview]"},
		{"left", "[5 Settings]"}, {"left", "[4 Status]"}, {"h", "[3 Projects]"}, {"tab", "[4 Status]"}, {"shift+tab", "[3 Projects]"}, {"1", "[1 Overview]"},
	} {
		d.press(c.key)
		d.want(c.want)
	}
	d.press("2", "enter")
	d.press("right") // inside an issue right does not switch screens
	d.want("[2 Findings", "Environments")
}

func TestBackKeysAndEsc(t *testing.T) {
	for _, back := range []string{"esc", "left", "h", "backspace", "q"} {
		d := start(t, newFake(t, nil), Options{})
		d.press("2", "enter")
		d.want("Environments")
		d.press(back)
		d.wantNot("Environments")
		d.want("3 of 3 open issues", "[2 Findings")
		if d.quit {
			t.Fatalf("%s quit the program", back)
		}
	}
	// esc at the root of a screen with nothing to clear does nothing
	d := start(t, newFake(t, nil), Options{})
	d.press("2", "esc", "esc")
	d.want("[2 Findings")
	// esc clears the filter, and only then goes anywhere
	d.press("/")
	d.typ("nginx")
	d.press("enter")
	d.want("1 of 3")
	d.press("esc")
	d.want("3 of 3")
}

func TestQuitOnlyAtARootWithoutAPopup(t *testing.T) {
	b := newFake(t, nil)
	writeProjectFile(t, b.cfg.Root, "shop", shopWithProblems)
	for name, keys := range map[string][]string{
		"detail":      {"2", "enter"},
		"prompt":      {"2", "enter", "f"},
		"help":        {"?"},
		"filter":      {"2", "/"},
		"project":     {"3", "enter"},
		"fix preview": {"3", "x"},
		"folder box":  {"3", "d"},
		"form text":   {"3", "a"},
		"form list":   {"3", "e"},
	} {
		d := start(t, b, Options{})
		d.press(keys...)
		d.press("q")
		if d.quit {
			t.Errorf("%s: q quit the program", name)
		}
	}
	for _, scr := range []string{"1", "2", "3", "4"} {
		d := start(t, b, Options{})
		d.press(scr, "q")
		if !d.quit {
			t.Errorf("screen %s: q must quit at the root", scr)
		}
	}
	for name, keys := range map[string][]string{"detail": {"2", "enter"}, "prompt": {"2", "enter", "f"}, "form": {"3", "a"}, "help": {"?"}, "fix": {"3", "x"}} {
		d := start(t, b, Options{})
		d.press(keys...)
		d.press("ctrl+c")
		if !d.quit {
			t.Errorf("%s: ctrl+c must quit", name)
		}
	}
}

func TestQInsideAPopupWorksLikeEsc(t *testing.T) {
	b := newFake(t, nil)
	writeProjectFile(t, b.cfg.Root, "shop", shopWithProblems)
	d := start(t, b, Options{})
	d.press("3", "x")
	d.want("Apply this fix?")
	d.press("q")
	d.wantNot("Apply this fix?")
	d.want("cancelled")
	d.press("enter", "q")
	d.wantNot("problems (up/down")
	d.want("PROJECT")
	d.press("e")
	d.want("What do you want to change?")
	d.press("q")
	d.wantNot("What do you want to change?")
}

func TestProjectProblemsHaveRealNavigation(t *testing.T) {
	b := newFake(t, nil)
	path := writeProjectFile(t, b.cfg.Root, "shop", shopWithProblems)
	d := start(t, b, Options{})
	d.press("3", "right") // right switches screens at the root
	d.want("[4 Status]")
	d.press("3", "enter")
	d.want("problems (up/down move, enter or x fix)", "> error")
	d.wantNot("PROJECT") // the project has the whole body
	d.press("down")
	d.want("> warning")
	d.press("up", "up")
	d.want("> error")
	d.press("l") // deeper: the fix preview of the selected problem
	d.want("Fix project: shop", "remove lockfile gone/composer.lock")
	d.press("left")
	d.wantNot("Fix project")
	d.want("problems (up/down move")
	d.press("down", "x")
	d.want(`use technology name "php" instead of "pph"`)
	d.press("enter") // enter applies
	d.want("ok: fixed shop")
	data := readFile(t, path)
	if !strings.Contains(data, "php") || strings.Contains(data, "pph") {
		t.Fatalf("technology not renamed:\n%s", data)
	}
	d.press("esc")
	d.want("PROJECT") // back on the list
}

func TestProjectKeyAliasesStillWork(t *testing.T) {
	b := newFake(t, nil)
	writeProjectFile(t, b.cfg.Root, "shop", shopWithProblems)
	t.Setenv("EDITOR", "")
	d := start(t, b, Options{})
	d.press("3", "p")
	d.want("> warning")
	d.press("P")
	d.want("> error")
	d.press("f")
	d.want("Apply this fix?")
	d.press("esc", "o")
	if f := d.m.(*app).flash; !strings.Contains(f, "$EDITOR is not set") {
		t.Fatalf("o still opens the editor: %q", f)
	}
	d.press("n")
	d.want("Project name")
}

func TestHelpIsPerModeAndScrolls(t *testing.T) {
	b := newFake(t, nil)
	writeProjectFile(t, b.cfg.Root, "shop", shopWithProblems)
	d := start(t, b, Options{})
	d.send(tea_window(80, 12))
	d.press("3", "?")
	d.want("Keys on the projects screen", "open the project")
	d.press("end")
	d.want("NO_COLOR")
	d.press("esc", "enter", "?")
	d.want("Keys in a project", "preview the fix")
	d.press("?", "x", "?")
	d.want("Keys in the fix preview", "apply the fix")
	d.press("?", "esc", "esc", "esc")
	d.press("d", "f1")
	d.want("Keys in the folder box")
	d.press("f1")
	d.want("Scan a folder")
	d.press("esc", "a", "?")
	d.want("> project?") // a text step types the question mark
	d.press("f1")
	d.want("Keys in the project form")
}

func TestDiscardAsksOnlyWhenSomethingWasEntered(t *testing.T) {
	b := newFake(t, nil)
	d := start(t, b, Options{})
	d.press("3", "a", "esc")
	d.wantNot("Discard")
	d.want("cancelled")
	d.press("a")
	d.typ("x")
	d.press("esc")
	d.want("Discard what you entered?")
	d.press("enter")
	d.want("cancelled")
	d.wantNot("Project name")

	d.press("a", "ctrl+u")
	d.typ("blog")
	d.press("enter")
	d.press("esc", "esc") // back to the first step, then out
	d.want("Discard what you entered?")
	d.press("n")
	d.want("Project name")
	// the breadcrumb leaves the form the same way
	d.click(2, 1)
	d.want("Discard what you entered?")
	d.press("y")
	d.want("[3 Projects]", "PROJECT")
	if b.writes != 0 {
		t.Fatal("discarding wrote something")
	}
}

func TestTopModeAloneDecidesTheKeys(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	d.press("2", "down", "enter", "f")
	d.want("Note (optional)")
	d.press("f", "1", "?", "q", "a")
	if d.quit {
		t.Fatal("the prompt takes the keys")
	}
	d.want("f1?qa")
	d.press("esc")
	d.want("Environments")
}

func TestMouseWheelScrollsTheFocusedList(t *testing.T) {
	b := newFake(t, nil)
	addProjects(b, 40)
	d := start(t, b, Options{})
	d.press("3")
	d.wheel(false, 10, 6)
	if got := selectedName(t, d); got != "app01" { // shop, mw, app00, app01
		t.Fatalf("the wheel moved to %q", got)
	}
	d.wheel(true, 10, 6)
	if got := selectedName(t, d); got != "shop" {
		t.Fatalf("wheel up: %q", got)
	}
	d.press("4")
	d.send(tea_window(80, 10))
	a := d.m.(*app)
	d.wheel(false, 10, 6)
	if a.txt[scrStatus].at() == 0 {
		t.Fatal("the wheel scrolls a text screen")
	}
	// the wheel scrolls the page of an issue, not its environment row
	d.send(tea_window(100, 12))
	d.press("2", "enter")
	sel := a.fnd.det.sel.at()
	d.wheel(false, 10, 6)
	if a.fnd.det.body.at() == 0 || a.fnd.det.sel.at() != sel {
		t.Fatalf("page at %d, row %d", a.fnd.det.body.at(), a.fnd.det.sel.at())
	}
}

func TestMouseClickSelectsThenOpens(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	d.press("2")
	a := d.m.(*app)
	// rows start on screen line 4: header, breadcrumb, count, column heads
	d.click(5, 5)
	if a.fnd.vp.at() != 1 || a.fnd.det != nil {
		t.Fatalf("a click selects: at %d", a.fnd.vp.at())
	}
	d.click(5, 5)
	if a.fnd.det == nil || a.fnd.det.id != "CVE-2026-1" {
		t.Fatalf("a second click opens: %+v", a.fnd.det)
	}
	d.want("Environments")
	// a click on an environment row selects it
	line := 0
	for i, l := range strings.Split(d.view(), "\n") {
		if strings.Contains(l, "shop") && strings.Contains(l, "prod") && strings.Contains(l, "owner") {
			line = i
		}
	}
	d.click(5, line)
	d.want("> shop")
	// the breadcrumb goes back
	d.click(2, 1)
	if a.fnd.det != nil {
		t.Fatal("a click on Findings in the breadcrumb goes back to the list")
	}
	d.want("3 of 3 open issues")
	// a click on a tab switches screen
	_, spans := a.tabs()
	d.click(spans[scrStatus][0]+2, 0)
	d.want("[4 Status]")
	d.click(spans[scrProjects][0]+2, 0)
	d.want("[3 Projects]")
	// outside the list nothing happens
	d.click(5, 30)
	d.click(500, 500)
}

func TestMouseOnProjectsFormsAndPopups(t *testing.T) {
	b := newFake(t, nil)
	writeProjectFile(t, b.cfg.Root, "shop", shopWithProblems)
	d := start(t, b, Options{})
	d.press("3")
	d.click(5, 4) // second row: mw
	if got := selectedName(t, d); got != "mw" {
		t.Fatalf("selected %q", got)
	}
	d.click(5, 4)
	if !d.m.(*app).prj.deep {
		t.Fatal("a second click enters the project")
	}
	d.click(2, 1) // the breadcrumb: Projects
	if d.m.(*app).prj.deep {
		t.Fatal("back to the list")
	}

	// a list in a form: click picks, a second click answers
	d.click(5, 3)
	d.press("e")
	d.want("What do you want to change?")
	f := d.m.(*app).frm
	head, _, _ := f.frame(120, d.m.(*app).bodyH())
	d.click(5, bodyTop+len(head)) // the first option
	if f.vp.at() != 0 {
		t.Fatalf("option %d", f.vp.at())
	}
	d.click(5, bodyTop+len(head))
	if d.m.(*app).frm.step.ID == "" || strings.Contains(d.view(), "What do you want to change?") {
		t.Fatalf("a second click answers:\n%s", d.view())
	}

	// a popup swallows clicks outside it
	d.press("esc", "esc", "y", "d")
	spans := func() [numScreens][2]int { _, s := d.m.(*app).tabs(); return s }()
	d.click(spans[scrStatus][0]+2, 0)
	d.want("Scan a folder")
	d.wantNot("[4 Status]")
}

func TestMouseMotionIsIgnored(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	d.press("2")
	d.send(tea.MouseMsg{X: 5, Y: 5, Action: tea.MouseActionMotion, Button: tea.MouseButtonNone})
	d.send(tea.MouseMsg{X: 5, Y: 5, Action: tea.MouseActionRelease, Button: tea.MouseButtonLeft})
	if d.m.(*app).fnd.vp.at() != 0 {
		t.Fatal("only a press clicks")
	}
}
