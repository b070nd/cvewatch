package ops

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/pipeline"
	"github.com/b070nd/cvewatch/app/src/status"
)

func off() *bool { b := false; return &b }

func scheduled(t *testing.T) (*Session, time.Time) {
	t.Helper()
	cfg := bundle(t, nil)
	cfg.Update.Auto = true
	cfg.Interval = 4 * time.Hour
	cfg.Projects = []model.Project{
		{Name: "shop"},
		{Name: "blog", Update: model.ProjectUpdate{Every: time.Hour}},
		{Name: "lab", Update: model.ProjectUpdate{Auto: off()}},
	}
	s := open(t, cfg, seeded(t), "alice")
	return s, s.Now()
}

func TestScheduleDueAndWakeWithMixedPeriods(t *testing.T) {
	s, now := scheduled(t)
	sc := s.Schedule()
	if got := sc.Due(now); len(got) != 2 || got[0] != "shop" || got[1] != "blog" {
		t.Fatalf("never updated is due at once, paused is never due: %v", got)
	}
	if sc.Wake(now, 4*time.Hour) != 0 {
		t.Error("something is due, so no waiting")
	}

	s.Ledger.SetLastUpdate("shop", now.Add(-time.Hour))
	s.Ledger.SetLastUpdate("blog", now.Add(-20*time.Minute))
	s.Ledger.SetLastUpdate("lab", now.Add(-100*time.Hour))
	sc = s.Schedule()
	if got := sc.Due(now); len(got) != 0 {
		t.Fatalf("shop is due in 3h, blog in 40m, lab never: %v", got)
	}
	if got := sc.Wake(now, 4*time.Hour); got != 40*time.Minute {
		t.Errorf("wake at the earliest due time, got %s", got)
	}
	if got := sc.Wake(now, 10*time.Minute); got != 10*time.Minute {
		t.Errorf("the interval caps the wait, got %s", got)
	}
	if got := sc.Due(now.Add(41 * time.Minute)); len(got) != 1 || got[0] != "blog" {
		t.Errorf("only blog after 41 minutes: %v", got)
	}
	if got := sc.Due(now.Add(3 * time.Hour)); len(got) != 2 {
		t.Errorf("shop and blog after 3 hours: %v", got)
	}
	for _, p := range sc.Projects {
		if p.Project == "lab" && (!p.Next.IsZero() || p.Auto) {
			t.Errorf("a paused project has no next time: %+v", p)
		}
		if p.Project == "blog" && p.Every != time.Hour {
			t.Errorf("blog has its own period: %+v", p)
		}
		if p.Project == "shop" && p.Every != 4*time.Hour {
			t.Errorf("shop takes the interval: %+v", p)
		}
	}
}

func TestScheduleIsOffWhenTheGlobalSwitchIsOff(t *testing.T) {
	s, now := scheduled(t)
	s.Cfg.Update.Auto = false
	sc := s.Schedule()
	if sc.On || len(sc.Due(now)) != 0 || sc.Wake(now, 4*time.Hour) != 4*time.Hour {
		t.Fatalf("nothing is scheduled: %+v", sc)
	}
	res, err := s.RefreshScheduled(t.Context(), nil)
	if err != nil || len(res.Updated) != 0 || !s.Ledger.LastUpdate("shop").IsZero() {
		t.Fatalf("a scheduled run does nothing: %+v %v", res, err)
	}
}

func TestRefreshScheduledUpdatesOnlyTheDueProjectsAndAManualRefreshAll(t *testing.T) {
	s, now := scheduled(t)
	s.Ledger.SetLastUpdate("shop", now.Add(-time.Hour)) // not due for 3 hours
	before := time.Now()                                // the runner stamps with the real clock
	var phases int
	res, err := s.RefreshScheduled(t.Context(), func(RefreshProgress) { phases++ })
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Updated) != 1 || res.Updated[0] != "blog" || phases == 0 {
		t.Fatalf("only blog is due: %+v", res)
	}
	if s.Ledger.LastUpdate("blog").Before(before) || !s.Ledger.LastUpdate("shop").Equal(now.Add(-time.Hour)) || !s.Ledger.LastUpdate("lab").IsZero() {
		t.Errorf("only the due project is marked: %+v", s.Ledger.State().Updated)
	}

	phases = 0
	res, err = s.RefreshScheduled(t.Context(), func(RefreshProgress) { phases++ })
	if err != nil || len(res.Updated) != 0 || phases != 0 {
		t.Fatalf("nothing is due, nothing is fetched: %+v %v phases=%d", res, err, phases)
	}

	res, err = s.Refresh(t.Context())
	if err != nil || len(res.Updated) != 3 {
		t.Fatalf("a manual refresh covers every project, paused or not: %+v %v", res, err)
	}
	for _, name := range []string{"shop", "blog", "lab"} {
		if s.Ledger.LastUpdate(name).Before(before) {
			t.Errorf("%s counts as updated: %v", name, s.Ledger.LastUpdate(name))
		}
	}
}

func TestStatusListsTheScheduleOfTheVisibleProjects(t *testing.T) {
	s, now := scheduled(t)
	s.Ledger.SetLastUpdate("blog", now.Add(-20*time.Minute))
	rep, err := s.Status()
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Scheduled || len(rep.Projects) != 3 {
		t.Fatalf("report = %+v", rep)
	}
	rows := map[string]status.ProjectRow{}
	for _, p := range rep.Projects {
		rows[p.Name] = p
	}
	if every, next := rep.Schedule(rows["blog"]); every != "every 1h" || next != "next 12:40" {
		t.Errorf("blog: %q %q", every, next)
	}
	if every, next := rep.Schedule(rows["shop"]); every != "every 4h" || next != "due now" {
		t.Errorf("shop was never updated: %q %q", every, next)
	}
	if every, next := rep.Schedule(rows["lab"]); every != "paused" || next != "" {
		t.Errorf("lab: %q %q", every, next)
	}

	s.Cfg.Update.Auto = false
	if rep, _ = s.Status(); rep.Scheduled {
		t.Error("the main switch is off")
	}
}

func TestProgressLogSaysWhichChunkOrPageFinished(t *testing.T) {
	var buf bytes.Buffer
	p := ProgressLog(slog.New(slog.NewTextHandler(&buf, nil)))
	p(pipeline.Progress{Phase: pipeline.PhaseFetch, Source: "nvd", Chunk: 2, Chunks: 9})
	p(pipeline.Progress{Phase: pipeline.PhaseFetch, Source: "ghsa", Chunk: 3})
	p(pipeline.Progress{Phase: pipeline.PhaseFetch, Source: "kev", Done: 1, Total: 2})
	got := buf.String()
	if !strings.Contains(got, "source=nvd chunk=2 of=9") || !strings.Contains(got, "source=ghsa page=3") || strings.Contains(got, "kev") {
		t.Fatalf("log = %q", got)
	}
}
