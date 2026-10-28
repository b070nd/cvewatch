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
	if empty.Level != OK || empty.Sources[0].Level != Unknown || empty.Daemon.Level != Unknown {
		t.Fatalf("nothing ran yet is unknown, not broken: %+v", empty)
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
