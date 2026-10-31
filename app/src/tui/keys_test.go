package tui

import (
	"strings"
	"testing"
)

// screenOf is the screen the driver shows, read from the model.
func screenOf(d *driver) screen { return d.app().scr }

func TestNoModeHasAKeyOnAScreenCapital(t *testing.T) {
	for _, md := range allModes() {
		if !md.switches() {
			continue
		}
		for i := range md.binds {
			b := &md.binds[i]
			if b.tabs {
				continue
			}
			for _, sc := range screens {
				if b.has(sc.key) {
					t.Errorf("%s: %q is bound to %q and is the key of the %s screen", md.name, sc.key, b.help, sc.name)
				}
			}
			if b.has("tab") || b.has("shift+tab") {
				t.Errorf("%s: tab is the screen cycle, not %q", md.name, b.help)
			}
		}
	}
}

func TestScreenKeysAreTheCapitalOfTheName(t *testing.T) {
	seen := map[string]bool{}
	for _, sc := range screens {
		if strings.ToUpper(sc.name[:1]) != sc.key || seen[sc.key] {
			t.Errorf("%s: key %q", sc.name, sc.key)
		}
		seen[sc.key] = true
	}
}

func TestNumbersDoNotSwitchScreens(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	d.screen("findings")
	for _, k := range []string{"1", "2", "3", "4", "5"} {
		d.press(k)
		if screenOf(d) != scrFindings {
			t.Fatalf("%s switched the screen", k)
		}
	}
	d.press("?")
	d.wantNot("1-5")
}

func TestCapitalLetterJumpsFromEveryScreen(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	for _, from := range screens {
		for i, to := range screens {
			d.press(from.key)
			d.press(to.key)
			if screenOf(d) != screen(i) {
				t.Errorf("%s then %s: on %s", from.name, to.name, screens[screenOf(d)].name)
			}
		}
	}
}

func TestSmallLetterJumpsOnlyWhereTheScreenHasNoKeyOnIt(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	d.press("p")
	if screenOf(d) != scrProjects {
		t.Fatalf("p on the overview: %s", screens[screenOf(d)].name)
	}
	d.press("O")
	d.screen("findings")
	d.press("s") // the severity cycle
	if screenOf(d) != scrFindings {
		t.Fatalf("s on the findings is the severity, not Settings: %s", screens[screenOf(d)].name)
	}
	d.want("min severity: low+")
	d.press("S")
	if screenOf(d) != scrSettings {
		t.Fatalf("S: %s", screens[screenOf(d)].name)
	}
	d.press("o")
	if screenOf(d) != scrOverview {
		t.Fatalf("o on the settings: %s", screens[screenOf(d)].name)
	}
	d.screen("projects")
	d.press("f") // fixes the selected problem, if there is one: never a switch
	if screenOf(d) != scrProjects {
		t.Fatalf("f on the projects: %s", screens[screenOf(d)].name)
	}
	d.press("h") // left, the previous screen
	if screenOf(d) != scrFindings {
		t.Fatalf("h is left: %s", screens[screenOf(d)].name)
	}
}

func TestLettersTypeTextWhereATextFieldIsActive(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	d.screen("findings")
	d.press("/")
	d.typ("OFPHSofphs")
	if screenOf(d) != scrFindings {
		t.Fatalf("typing a filter switched to %s", screens[screenOf(d)].name)
	}
	d.want("OFPHSofphs")
	d.press("esc")

	d.press("down", "enter", "i")
	d.typ("SHOP fp")
	if screenOf(d) != scrFindings {
		t.Fatalf("typing a note switched to %s", screens[screenOf(d)].name)
	}
	d.want("SHOP fp")
}

func TestTheTabBarMarksTheKeyAndTheScreenShown(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	d.want("▸[O]verview", "[F]indings (3)", "[P]rojects", "[H]ealth", "[S]ettings")
	d.wantNot("▸[F]indings", "1 Overview", "[1")
	d.screen("health")
	d.want("▸[H]ealth", "[O]verview")
	d.wantNot("▸[O]verview")
}

func TestTheFooterAndTheHelpListTheScreenKeys(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	d.send(tea_window(200, 40))
	d.want("O/F/P/H/S screen")
	d.press("?")
	d.want("tab, O/F/P/H/S", "switch screen: tab and shift+tab cycle", "O F P H S jump to Overview, Findings, Projects, Health, Settings")
	d.press("esc")
	d.screen("projects")
	d.press("?")
	d.want("tab, O/F/P/H/S")
}

func TestFetchIsOnUAndCapitalFOnlyGoesToFindings(t *testing.T) {
	b := newFake(t, nil)
	d := start(t, b, Options{})
	d.press("F")
	if screenOf(d) != scrFindings || b.fetched() != 0 {
		t.Fatalf("F: screen %s, fetches %d", screens[screenOf(d)].name, b.fetched())
	}
	d.press("O")
	g := newBG(d)
	g.press("u")
	g.until("the fetch", func() bool { return b.fetched() == 1 })
}

func TestAssignAllEnvironmentsHasAnAlternativeInThePrompt(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	d.screen("findings")
	d.press("down", "enter", "a")
	d.want("Assign CVE-2026-1 in mw/prod")
	d.press("ctrl+p")
	d.want("Assign CVE-2026-1 in mw (all environments)")
	d.press("ctrl+p")
	d.want("Assign CVE-2026-1 in mw/prod")
	d.press("esc", "A")
	d.want("Assign CVE-2026-1 in mw (all environments)")
	d.press("ctrl+p")
	d.want("Assign CVE-2026-1 in mw/prod")
}

func TestHintsAreOnWAndHIsTheHealthScreen(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	d.screen("projects")
	d.press("?")
	d.want("work through the hints")
	d.press("esc")
	d.press("H")
	if screenOf(d) != scrStatus {
		t.Fatalf("H is the Health screen: %s", screens[screenOf(d)].name)
	}
}
