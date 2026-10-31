package status

import (
	"strings"
	"testing"
	"time"

	"github.com/b070nd/cvewatch/app/src/model"
)

var now = time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)

func TestFeedLevels(t *testing.T) {
	r := Build(Input{Now: now, Interval: 4 * time.Hour,
		Sources: []Ref{{"nvd", "nvd"}, {"kev", "kev"}, {"rss", "rss"}, {"new", "rss"}, {"old", "rss"}},
		Health: map[string]model.SourceHealth{
			"nvd": {LastAttempt: now, LastSuccess: now, Items: 12},
			"kev": {LastAttempt: now, Failures: 4, LastError: "status 503", LastSuccess: now.Add(-3 * 24 * time.Hour)},
			"rss": {LastAttempt: now, Failures: 1, LastError: "timeout", LastSuccess: now.Add(-time.Hour)},
			"old": {LastAttempt: now.Add(-30 * time.Hour), LastSuccess: now.Add(-30 * time.Hour)},
		}})
	want := map[string]Level{"nvd": OK, "kev": Fail, "rss": Warn, "new": Unknown, "old": Warn}
	for _, row := range r.Sources {
		if row.Level != want[row.ID] {
			t.Errorf("%s: %s, want %s", row.ID, row.Level, want[row.ID])
		}
	}
	if r.Level != Fail || len(r.Warnings) < 2 || !strings.Contains(strings.Join(r.Warnings, "|"), "feed kev has failed 4 times in a row: status 503") {
		t.Fatalf("overall: %s %v", r.Level, r.Warnings)
	}
}

func TestChannelsAndNeverRan(t *testing.T) {
	r := Build(Input{Now: now, Interval: time.Hour, Channels: []string{"slack", "email"},
		Delivery: map[string]model.ChannelHealth{"slack": {LastAttempt: now, LastSuccess: now}, "email": {LastAttempt: now, Failures: 3, LastError: "smtp down"}}})
	if r.Channels[0].Name != "email" || r.Channels[0].Level != Fail || r.Channels[1].Level != OK {
		t.Fatalf("channels: %+v", r.Channels)
	}
	empty := Build(Input{Now: now, Interval: time.Hour, Sources: []Ref{{"a", "rss"}}, Channels: []string{"slack"}})
	if empty.Level != Unknown || empty.Sources[0].Level != Unknown || empty.Daemon.Level != Unknown || empty.Reason() == "" {
		t.Fatalf("nothing ran yet is unknown, not ok and not broken: %+v", empty)
	}
}

func TestOverallIsUnknownUntilACycleSucceeded(t *testing.T) {
	src := []Ref{{"a", "rss"}, {"b", "rss"}}
	ok := map[string]model.SourceHealth{"a": {LastAttempt: now, LastSuccess: now}, "b": {LastAttempt: now, LastSuccess: now}}
	beat := &model.Heartbeat{Mode: "daemon", LastCycle: now, NextRun: now.Add(time.Hour), Interval: 4 * time.Hour}
	cycle := func(c model.CycleRecord) []model.CycleRecord { return []model.CycleRecord{c} }

	if r := Build(Input{Now: now, Interval: time.Hour, Sources: src, Beat: beat}); r.Level != Unknown {
		t.Errorf("a heartbeat without a cycle: %s", r.Level)
	}
	if r := Build(Input{Now: now, Interval: time.Hour, Sources: src, Health: ok, Beat: beat, Cycles: cycle(model.CycleRecord{Finished: now})}); r.Level != OK || r.Reason() != "" {
		t.Errorf("a cycle that read the feeds: %s", r.Level)
	}
	if r := Build(Input{Now: now, Interval: time.Hour, Sources: src, Health: ok, Beat: beat, Cycles: cycle(model.CycleRecord{Finished: now, Failed: 2})}); r.Level != Unknown {
		t.Errorf("a cycle in which every feed failed: %s", r.Level)
	}
	if r := Build(Input{Now: now, Interval: time.Hour, Sources: src, Health: ok, Beat: beat, Cycles: cycle(model.CycleRecord{Finished: now, Failed: 1})}); r.Level != OK {
		t.Errorf("a cycle in which one feed failed: %s", r.Level)
	}
	if r := Build(Input{Now: now, Interval: time.Hour, Sources: src, Health: ok, Beat: beat, Cycles: cycle(model.CycleRecord{Finished: now, Err: "disk full"})}); r.Level != Unknown {
		t.Errorf("a cycle that errored: %s", r.Level)
	}
}

func TestNoEnabledSourcesWarns(t *testing.T) {
	r := Build(Input{Now: now, Interval: time.Hour, Cycles: []model.CycleRecord{{Finished: now}}})
	if r.Level != Warn || !strings.Contains(strings.Join(r.Warnings, "|"), "no enabled sources: nothing will be fetched") {
		t.Fatalf("%s %v", r.Level, r.Warnings)
	}
	if r := Build(Input{Now: now, Interval: time.Hour}); r.Level != Warn {
		t.Errorf("never run and nothing enabled: %s", r.Level)
	}
}

func TestDaemonLiveness(t *testing.T) {
	beat := func(next time.Time) *model.Heartbeat {
		return &model.Heartbeat{Mode: "daemon", LastCycle: next.Add(-4 * time.Hour), NextRun: next, Interval: 4 * time.Hour}
	}
	if d := Build(Input{Now: now, Interval: 4 * time.Hour, Beat: beat(now.Add(time.Hour))}).Daemon; d.Level != OK || !strings.Contains(d.Message, "next cycle") {
		t.Fatalf("alive: %+v", d)
	}
	if d := Build(Input{Now: now, Interval: 4 * time.Hour, Beat: beat(now.Add(-time.Hour))}).Daemon; d.Level != OK {
		t.Fatalf("an hour late is within half an interval (2h): %+v", d)
	}
	late := Build(Input{Now: now, Interval: 4 * time.Hour, Beat: beat(now.Add(-3 * time.Hour))})
	if late.Daemon.Level != Fail || late.Level != Fail || !strings.Contains(late.Daemon.Message, "overdue") {
		t.Fatalf("overdue: %+v", late)
	}
	cli := Build(Input{Now: now, Interval: time.Hour, Cycles: []model.CycleRecord{{Finished: now.Add(-2 * time.Hour)}}}).Daemon
	if cli.Mode != "cli" || cli.Level != Unknown {
		t.Fatalf("manual runs: %+v", cli)
	}
}

func TestCyclesNewestFirstAndCapped(t *testing.T) {
	var cs []model.CycleRecord
	for i := 0; i < 15; i++ {
		cs = append(cs, model.CycleRecord{Items: i})
	}
	r := Build(Input{Now: now, Interval: time.Hour, Cycles: cs})
	if len(r.Cycles) != 10 || r.Cycles[0].Items != 14 || r.Cycles[9].Items != 5 {
		t.Fatalf("cycles: %+v", r.Cycles)
	}
}

func TestProjectScheduleWords(t *testing.T) {
	r := Build(Input{Now: now, Interval: 4 * time.Hour, Projects: []ProjectRow{
		{Name: "soon", Auto: true, Every: time.Hour, LastUpdate: now.Add(-30 * time.Minute), Next: now.Add(30 * time.Minute)},
		{Name: "tomorrow", Auto: true, Every: 36 * time.Hour, LastUpdate: now, Next: now.Add(36 * time.Hour)},
		{Name: "late", Auto: true, Every: 90 * time.Minute, LastUpdate: now.Add(-3 * time.Hour), Next: now.Add(-90 * time.Minute)},
		{Name: "new", Auto: true, Every: 4 * time.Hour, Next: now},
		{Name: "off", Every: time.Hour},
	}})
	want := map[string][2]string{
		"soon": {"every 1h", "next 12:30"}, "tomorrow": {"every 36h", "next 10-30 00:00"},
		"late": {"every 1h30m", "due now"}, "new": {"every 4h", "due now"}, "off": {"paused", ""},
	}
	if !r.Scheduled || len(r.Projects) != 5 {
		t.Fatalf("report: %+v", r)
	}
	for _, p := range r.Projects {
		if every, next := r.Schedule(p); every != want[p.Name][0] || next != want[p.Name][1] {
			t.Errorf("%s: %q, %q; want %q", p.Name, every, next, want[p.Name])
		}
	}

	manual := Build(Input{Now: now, Interval: 4 * time.Hour, Unscheduled: true, Projects: []ProjectRow{{Name: "soon", Auto: true, Every: time.Hour}}})
	if every, next := manual.Schedule(manual.Projects[0]); manual.Scheduled || every != "manual" || next != "" {
		t.Errorf("update.auto off leaves manual runs: %v %q %q", manual.Scheduled, every, next)
	}

	// times are shown where the report is, not in UTC
	zone := time.FixedZone("CET", 3600)
	local := Build(Input{Now: now.In(zone), Interval: time.Hour, Projects: []ProjectRow{{Name: "p", Auto: true, Every: time.Hour, Next: now.Add(30 * time.Minute)}}})
	if _, next := local.Schedule(local.Projects[0]); next != "next 13:30" {
		t.Errorf("next = %q", next)
	}
}

func TestDaemonAliveNeedsALiveHeartbeat(t *testing.T) {
	beat := func(next time.Time) *model.Heartbeat {
		return &model.Heartbeat{Mode: "daemon", LastCycle: now.Add(-time.Hour), NextRun: next, Interval: time.Hour}
	}
	for name, c := range map[string]struct {
		in   Input
		want bool
	}{
		"on time":    {Input{Now: now, Beat: beat(now.Add(10 * time.Minute))}, true},
		"overdue":    {Input{Now: now, Beat: beat(now.Add(-3 * time.Hour))}, false},
		"no beat":    {Input{Now: now}, false},
		"cli cycles": {Input{Now: now, Cycles: []model.CycleRecord{{Finished: now.Add(-time.Hour)}}}, false},
	} {
		if got := Build(c.in).Daemon.Alive(); got != c.want {
			t.Errorf("%s: alive = %v", name, got)
		}
	}
}
