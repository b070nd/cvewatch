package tui

import (
	"testing"

	"github.com/b070nd/cvewatch/app/src/ledger"
	"github.com/b070nd/cvewatch/app/src/model"
)

func TestDetailShowsTheScoreWithItsVersionAndVector(t *testing.T) {
	b := newFake(t, seed(t, func(l *ledger.Ledger) {
		l.Vuln("CVE-2026-3").SetRating(model.Rating{Score: 9.3, Version: model.CVSS40, Vector: "CVSS:4.0/AV:N/AC:L", Source: model.ScoreCNA})
	}))
	d := start(t, b, Options{})
	d.send(tea_window(150, 70))
	d.press("2", "enter")
	d.want("CVSS 9.3 (v4.0)", "cvss: CVSS:4.0/AV:N/AC:L from cna")
}
