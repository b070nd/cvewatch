package tui

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/ledger"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/ops"
	"github.com/b070nd/cvewatch/app/src/pipeline"
)

// autoFake is a fake whose configuration schedules updates and whose
// interface is told tui.auto is on; the update itself is scripted.
func autoFake(t *testing.T, mutate func(*ledger.Ledger)) *fake {
	t.Helper()
	b := newFake(t, seed(t, mutate))
	b.cfg.Update.Auto = true
	b.cfg.Interval = time.Hour
	b.auto.Store(true)
	b.updateFn = func(context.Context, func(ops.RefreshProgress)) (pipeline.Result, error) {
		return pipeline.Result{New: 1, Findings: 2, Updated: []string{"shop", "mw"}}, nil
	}
	return b
}

func daemonBeat(l *ledger.Ledger) {
	l.SetHeartbeat(model.Heartbeat{Mode: "daemon", Started: tNow.Add(-24 * time.Hour), LastCycle: tNow.Add(-10 * time.Minute),
		NextRun: tNow.Add(50 * time.Minute), Interval: time.Hour, PID: 1})
}

func TestAutoUpdateStartsWhenNoDaemonRunsAndAProjectIsDue(t *testing.T) {
	b := autoFake(t, nil)
	d := start(t, b, Options{Auto: b.auto.Load()})
	if b.updated() != 1 || b.fetched() != 0 {
		t.Fatalf("one update by itself, no plain fetch: %d, %d", b.updated(), b.fetched())
	}
	d.want("updated shop, mw: 1 new, 2 findings")
	if d.app().autoUpdate() != nil {
		t.Error("the next one waits for the retry pause")
	}
}

func TestAutoUpdateDoesNotStartNextToALiveDaemon(t *testing.T) {
	b := autoFake(t, daemonBeat)
	d := start(t, b, Options{Auto: b.auto.Load()})
	if d.app().data.Status.Daemon.Alive() != true {
		t.Fatalf("the daemon should look alive: %+v", d.app().data.Status.Daemon)
	}
	g := newBG(d)
	g.spawn(d.m.Init())
	g.quiet()
	if b.updated() != 0 || b.fetched() != 0 {
		t.Fatalf("the daemon does the updates: %d, %d", b.updated(), b.fetched())
	}
}

func TestAutoUpdateStartsWhenTheDaemonIsOverdue(t *testing.T) {
	b := autoFake(t, func(l *ledger.Ledger) {
		l.SetHeartbeat(model.Heartbeat{Mode: "daemon", Started: tNow.Add(-72 * time.Hour), LastCycle: tNow.Add(-5 * time.Hour),
			NextRun: tNow.Add(-4 * time.Hour), Interval: time.Hour, PID: 1})
	})
	start(t, b, Options{Auto: b.auto.Load()})
	if b.updated() != 1 {
		t.Fatalf("a dead daemon does no updates, so the program does: %d", b.updated())
	}
}

func TestAutoUpdateIsOffByTheSettings(t *testing.T) {
	for name, set := range map[string]func(*fake){
		"tui.auto":             func(b *fake) { b.auto.Store(false) },
		"update.auto":          func(b *fake) { b.cfg.Update.Auto = false },
		"every project paused": func(b *fake) { b.cfg.Projects[0].Update.Auto, b.cfg.Projects[1].Update.Auto = off(), off() },
	} {
		t.Run(name, func(t *testing.T) {
			b := autoFake(t, nil)
			set(b)
			d := start(t, b, Options{Auto: b.auto.Load()})
			newBG(d).quiet()
			if b.updated() != 0 || b.fetched() != 0 {
				t.Fatalf("no update: %d, %d", b.updated(), b.fetched())
			}
		})
	}
}

func off() *bool { v := false; return &v }

func TestAutoUpdateWaitsForTheScheduleAndIgnoresPausedProjects(t *testing.T) {
	b := autoFake(t, func(l *ledger.Ledger) {
		l.SetLastUpdate("shop", tNow.Add(-10*time.Minute))
		l.SetLastUpdate("mw", tNow.Add(-10*time.Minute))
	})
	b.cfg.Projects[1].Update.Auto = off()
	start(t, b, Options{Auto: b.auto.Load()})
	if b.updated() != 0 {
		t.Fatalf("shop is due in 50 minutes and mw never: %d", b.updated())
	}

	b = autoFake(t, func(l *ledger.Ledger) {
		l.SetLastUpdate("shop", tNow.Add(-2*time.Hour))
		l.SetLastUpdate("mw", tNow.Add(-10*time.Minute))
	})
	start(t, b, Options{Auto: b.auto.Load()})
	if b.updated() != 1 {
		t.Fatalf("shop is due, mw is not: %d", b.updated())
	}
}

func TestAFixedFetchPeriodReplacesTheSchedule(t *testing.T) {
	b := autoFake(t, nil)
	b.cfg.TUI.Fetch = time.Hour
	b.fetchFn = func(context.Context, func(ops.RefreshProgress)) (pipeline.Result, error) {
		return pipeline.Result{}, nil
	}
	d := start(t, b, Options{Auto: true, Fetch: time.Hour})
	g := newBG(d)
	g.spawn(d.m.Init())
	g.until("the fixed fetch", func() bool { return b.fetched() == 1 && d.app().fet.job == nil })
	g.quiet()
	if b.updated() != 0 {
		t.Fatalf("tui.fetch fetches everything on its own period and the schedule stays out: %d", b.updated())
	}
}

func TestTheFetchKeyStillDoesEverythingAndAutoUpdateFollowsTheSettingsScreen(t *testing.T) {
	b := autoFake(t, daemonBeat)
	b.fetchFn = func(context.Context, func(ops.RefreshProgress)) (pipeline.Result, error) {
		return pipeline.Result{New: 3}, nil
	}
	d := start(t, b, Options{Auto: b.auto.Load()})
	g := newBG(d)
	g.press("u")
	g.until("the manual fetch", func() bool { return b.fetched() == 1 && d.app().fet.job == nil })
	g.quiet()
	if b.updated() != 0 {
		t.Errorf("F is a fetch of everything, not an update: %d", b.updated())
	}
	if d.app().tui.Auto != true {
		t.Error("the interface knows tui.auto")
	}
	g.send(tuiMsg{set: config.TUI{Refresh: time.Hour, Auto: false}})
	if d.app().tui.Auto {
		t.Error("a new tui.auto is taken over")
	}
}

func TestSettingsScreenEditsTheAutoUpdateSwitches(t *testing.T) {
	d, root := setStart(t, nil)
	d.toSetting("update.auto")
	d.want("Scheduled updates", "update.auto")
	d.press(" ")
	d.saveSetting("turn off Scheduled updates")
	if !strings.Contains(cfgOf(t, root), "auto: false") {
		t.Errorf("not saved:\n%s", cfgOf(t, root))
	}

	d.toSetting("tui.auto")
	d.wantLine("TUI auto update", "true", "bool")
	d.press(" ")
	d.want("Change settings: turn off TUI auto update", "Changes apply on the next re-read of the interface.")
	d.press("y")
	d.want("saved: turn off TUI auto update")
	if d.app().tui.Auto {
		t.Error("the switch of the interface was not picked up")
	}
}

func TestProjectsScreenShowsEachProjectsUpdateStatus(t *testing.T) {
	b := autoFake(t, func(l *ledger.Ledger) {
		l.SetLastUpdate("shop", tNow.Add(-20*time.Minute))
	})
	b.cfg.Projects[0].Update.Every = 2 * time.Hour
	b.cfg.Projects[1].Update.Auto = off()
	d := start(t, b, Options{})
	d.screen("projects")
	d.want("updates: every 2h")
	d.wantNot("updates: every 2h · due now")
	d.press("down")
	d.want("updates: paused")

	b.cfg.Update.Auto = false
	d.press("r")
	d.want("updates: manual")
}

func TestStatusScreenListsLastAndNextUpdate(t *testing.T) {
	b := autoFake(t, func(l *ledger.Ledger) {
		l.SetLastUpdate("shop", tNow.Add(-20*time.Minute))
	})
	b.cfg.Projects[1].Update.Auto = off()
	d := start(t, b, Options{})
	d.screen("health")
	d.want("Projects (2)", "PROJECT", "LAST UPDATE", "NEXT")
	d.wantLine("shop", "every 1h", "11:40", "12:40")
	d.wantLine("mw", "paused")

	b.cfg.Update.Auto = false
	d.press("r")
	d.want("scheduled updates are off", "update.auto")
}
