package tui

import (
	"strings"
	"testing"
)

func TestHorizonWindowShowsGoogleStyleLabels(t *testing.T) {
	d, _ := setStart(t, nil)
	d.toSetting("horizon.window")
	d.wantLine("Alert horizon", "Any time")
	d.press("enter")
	d.want("Choose Alert horizon", "Any time", "Past hour", "Past 24 hours", "Past week", "Past month", "Past year", "Custom range", "applies from the next fetch or cycle")
	d.want("- week") // the name in the file stays beside the label
	d.press("down", "down", "down")
	d.wantSel("Past week")
	d.press("enter")
	d.saveSetting("set Alert horizon to Past week")
	d.toSetting("horizon.window")
	d.wantLine("Alert horizon", "Past week")
}

func TestHorizonDatesAreMarkedUnusedUntilTheWindowIsCustom(t *testing.T) {
	d, root := setStart(t, nil)
	d.toSetting("horizon.from")
	d.wantLine("Horizon from", "custom range only")
	d.wantLine("Horizon to", "custom range only")
	d.want("used only when the window is a custom range")

	d.toSetting("horizon.window")
	d.press("enter")
	d.press("down", "down", "down", "down", "down", "down")
	d.wantSel("Custom range")
	d.press("enter")
	d.saveSetting("set Alert horizon to Custom range")
	if got := cfgOf(t, root); !strings.Contains(got, "window: custom") {
		t.Fatalf("custom:\n%s", got)
	}
	d.toSetting("horizon.from")
	d.wantNot("custom range only")
	d.wantLine("Horizon from", "-")
}

func TestHorizonDateErrorsNameTheirOwnField(t *testing.T) {
	d, root := setStart(t, map[string]string{"config/config.yaml": setCfg + "horizon:\n  window: custom\n"})
	d.toSetting("horizon.from")
	d.press("enter")
	d.want("YYYY-MM-DD", "applies from the next fetch or cycle")
	d.typ("yesterday")
	d.press("enter")
	d.want("> Horizon from: yesterday", "problem:", "horizon.from")
	d.press("ctrl+u")
	d.typ("2026-03-01")
	d.press("enter")
	d.saveSetting("set Horizon from to 2026-03-01")

	d.toSetting("horizon.to")
	d.press("enter")
	d.typ("2026-01-01")
	d.press("enter")
	d.want("problem:", "horizon.to is before horizon.from")
	d.press("esc")
	if got := cfgOf(t, root); strings.Contains(got, "to: 2026-01-01") {
		t.Fatalf("a range that ends before it starts was written:\n%s", got)
	}
}

func TestHorizonLookbackWarningIsOnTheWindowSetting(t *testing.T) {
	d, _ := setStart(t, map[string]string{"config/config.yaml": setCfg + "lookback: 24h\nhorizon:\n  window: month\n"})
	d.wantNot("(!)") // a warning is not an error
	d.toSetting("horizon.window")
	d.wantLine("~ Alert horizon", "Past month")
	d.want("horizon reaches back 30d but lookback is 1d", "raise lookback")
}
