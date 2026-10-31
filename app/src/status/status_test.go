package status

import (
	"encoding/json"
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
	want := map[string]Level{"nvd": Green, "kev": Red, "rss": Yellow, "new": Yellow, "old": Yellow}
	for _, row := range r.Sources {
		if row.Level != want[row.ID] {
			t.Errorf("%s: %s, want %s", row.ID, row.Level, want[row.ID])
		}
	}
	if r.Level != Red || len(r.Warnings) < 2 || !strings.Contains(strings.Join(r.Warnings, "|"), "feed kev has failed 4 times in a row: status 503") {
		t.Fatalf("overall: %s %v", r.Level, r.Warnings)
	}
}

func TestChannelsAndNeverRan(t *testing.T) {
	r := Build(Input{Now: now, Interval: time.Hour, Channels: []string{"slack", "email"},
		Delivery: map[string]model.ChannelHealth{"slack": {LastAttempt: now, LastSuccess: now}, "email": {LastAttempt: now, Failures: 3, LastError: "smtp down"}}})
	if r.Channels[0].Name != "email" || r.Channels[0].Level != Red || r.Channels[1].Level != Green {
		t.Fatalf("channels: %+v", r.Channels)
	}
	empty := Build(Input{Now: now, Interval: time.Hour, Sources: []Ref{{"a", "rss"}}, Channels: []string{"slack"}})
	if empty.Level != Yellow || empty.Sources[0].Level != Yellow || empty.Daemon.Level != Yellow || empty.Reason() != "no cycle has run yet" {
		t.Fatalf("nothing ran yet is yellow, not green and not red: %+v", empty)
	}
}

func TestOverallIsYellowUntilACycleSucceeded(t *testing.T) {
	src := []Ref{{"a", "rss"}, {"b", "rss"}}
	ok := map[string]model.SourceHealth{"a": {LastAttempt: now, LastSuccess: now}, "b": {LastAttempt: now, LastSuccess: now}}
	beat := &model.Heartbeat{Mode: "daemon", LastCycle: now, NextRun: now.Add(time.Hour), Interval: 4 * time.Hour}
	cycle := func(c model.CycleRecord) []model.CycleRecord { return []model.CycleRecord{c} }

	if r := Build(Input{Now: now, Interval: time.Hour, Sources: src, Beat: beat}); r.Level != Yellow {
		t.Errorf("a heartbeat without a cycle: %s", r.Level)
	}
	if r := Build(Input{Now: now, Interval: time.Hour, Sources: src, Health: ok, Beat: beat, Cycles: cycle(model.CycleRecord{Finished: now})}); r.Level != Green || r.Reason() != "" {
		t.Errorf("a cycle that read the feeds: %s", r.Level)
	}
	if r := Build(Input{Now: now, Interval: time.Hour, Sources: src, Health: ok, Beat: beat, Cycles: cycle(model.CycleRecord{Finished: now, Failed: 2})}); r.Level != Yellow {
		t.Errorf("a cycle in which every feed failed: %s", r.Level)
	}
	if r := Build(Input{Now: now, Interval: time.Hour, Sources: src, Health: ok, Beat: beat, Cycles: cycle(model.CycleRecord{Finished: now, Failed: 1})}); r.Level != Green {
		t.Errorf("a cycle in which one feed failed: %s", r.Level)
	}
	if r := Build(Input{Now: now, Interval: time.Hour, Sources: src, Health: ok, Beat: beat, Cycles: cycle(model.CycleRecord{Finished: now, Err: "disk full"})}); r.Level != Yellow {
		t.Errorf("a cycle that errored: %s", r.Level)
	}
}

func TestNoEnabledSourcesWarns(t *testing.T) {
	r := Build(Input{Now: now, Interval: time.Hour, Cycles: []model.CycleRecord{{Finished: now}}})
	if r.Level != Yellow || !strings.Contains(strings.Join(r.Warnings, "|"), "no enabled sources: nothing will be fetched") {
		t.Fatalf("%s %v", r.Level, r.Warnings)
	}
	if r := Build(Input{Now: now, Interval: time.Hour}); r.Level != Yellow {
		t.Errorf("never run and nothing enabled: %s", r.Level)
	}
}

func TestDaemonLiveness(t *testing.T) {
	beat := func(next time.Time) *model.Heartbeat {
		return &model.Heartbeat{Mode: "daemon", LastCycle: next.Add(-4 * time.Hour), NextRun: next, Interval: 4 * time.Hour}
	}
	if d := Build(Input{Now: now, Interval: 4 * time.Hour, Beat: beat(now.Add(time.Hour))}).Daemon; d.Level != Green || !strings.Contains(d.Message, "next cycle") {
		t.Fatalf("alive: %+v", d)
	}
	if d := Build(Input{Now: now, Interval: 4 * time.Hour, Beat: beat(now.Add(-time.Hour))}).Daemon; d.Level != Green {
		t.Fatalf("an hour late is within half an interval (2h): %+v", d)
	}
	late := Build(Input{Now: now, Interval: 4 * time.Hour, Beat: beat(now.Add(-3 * time.Hour))})
	if late.Daemon.Level != Red || late.Level != Red || !strings.Contains(late.Daemon.Message, "overdue") {
		t.Fatalf("overdue: %+v", late)
	}
	cli := Build(Input{Now: now, Interval: time.Hour, Cycles: []model.CycleRecord{{Finished: now.Add(-2 * time.Hour)}}}).Daemon
	if cli.Mode != "cli" || cli.Level != Green {
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

func problem(r Report, key string) (Problem, bool) {
	for _, p := range r.Problems {
		if p.Key == key {
			return p, true
		}
	}
	return Problem{}, false
}

func provenInput() Input {
	return Input{Now: now, Interval: time.Hour, Sources: []Ref{{"nvd", "nvd"}},
		Health: map[string]model.SourceHealth{"nvd": {LastAttempt: now, LastSuccess: now}},
		Beat:   &model.Heartbeat{Mode: "daemon", LastCycle: now, NextRun: now.Add(time.Hour), Interval: time.Hour},
		Cycles: []model.CycleRecord{{Started: now.Add(-time.Minute), Finished: now.Add(-4 * time.Minute)}}}
}

func TestGreenHasNoProblems(t *testing.T) {
	r := Build(provenInput())
	if r.Level != Green || len(r.Problems) != 0 || r.Problems == nil {
		t.Fatalf("%s %+v", r.Level, r.Problems)
	}
	raw, err := json.Marshal(r)
	if err != nil || !strings.Contains(string(raw), `"level":"green"`) || !strings.Contains(string(raw), `"problems":[]`) {
		t.Fatalf("%v %s", err, raw)
	}
}

func TestFeedProblems(t *testing.T) {
	in := provenInput()
	in.Sources = []Ref{{"nvd", "nvd"}, {"kev", "kev"}, {"rss", "rss"}, {"old", "rss"}, {"new", "rss"}}
	in.Health = map[string]model.SourceHealth{
		"nvd": {LastAttempt: now, LastSuccess: now},
		"kev": {LastAttempt: now, Failures: 4, LastError: "status 503", LastSuccess: now.Add(-3 * 24 * time.Hour), FailingSince: now.Add(-2 * time.Hour)},
		"rss": {LastAttempt: now, Failures: 1, LastError: "timeout", LastSuccess: now.Add(-time.Hour)},
		"old": {LastAttempt: now.Add(-30 * time.Hour), LastSuccess: now.Add(-30 * time.Hour)},
	}
	r := Build(in)
	if _, ok := problem(r, "feed:nvd"); ok {
		t.Error("a healthy feed is no problem")
	}
	kev, ok := problem(r, "feed:kev")
	if !ok || kev.Level != Red || !strings.Contains(kev.Detail, "status 503") || kev.Hint == "" || !kev.Since.Equal(now.Add(-2*time.Hour)) {
		t.Errorf("kev: %+v", kev)
	}
	rss, _ := problem(r, "feed:rss")
	if rss.Level != Yellow || !strings.Contains(rss.Detail, "timeout") || !rss.Since.Equal(now.Add(-time.Hour)) {
		t.Errorf("rss: the streak began after the last success: %+v", rss)
	}
	if old, _ := problem(r, "feed:old"); old.Level != Yellow || !strings.Contains(old.Title, "stale") {
		t.Errorf("old: %+v", old)
	}
	if _, ok := problem(r, "feed:new"); ok {
		t.Errorf("a feed added since the last cycle is no problem: %+v", r.Problems)
	}
	for _, row := range r.Sources {
		if row.ID == "new" && row.Level != Yellow {
			t.Errorf("but its row is not green: %+v", row)
		}
	}
	if r.Level != Red {
		t.Errorf("level = %s", r.Level)
	}
}

func TestNeverReadFeedsAreOneProblemUntilACycleSucceeded(t *testing.T) {
	r := Build(Input{Now: now, Interval: time.Hour, Sources: []Ref{{"a", "rss"}, {"b", "rss"}}})
	if len(r.Problems) != 1 || r.Problems[0].Key != KeyCycle || r.Problems[0].Level != Yellow || r.Problems[0].Title != "no cycle has run yet" {
		t.Fatalf("%+v", r.Problems)
	}
	failed := Build(Input{Now: now, Interval: time.Hour, Sources: []Ref{{"a", "rss"}}, Cycles: []model.CycleRecord{{Finished: now, Err: "disk full"}}})
	if p, ok := problem(failed, KeyCycle); !ok || p.Title != "no cycle has read a feed yet" {
		t.Fatalf("%+v", failed.Problems)
	}
}

func TestNoEnabledSourcesIsAProblem(t *testing.T) {
	r := Build(Input{Now: now, Interval: time.Hour, Cycles: []model.CycleRecord{{Finished: now}}})
	if p, ok := problem(r, "sources"); !ok || p.Level != Yellow || p.Hint == "" || len(r.Problems) != 1 {
		t.Fatalf("%+v", r.Problems)
	}
}

func TestDaemonOverdueIsRed(t *testing.T) {
	in := provenInput()
	in.Beat = &model.Heartbeat{Mode: "daemon", LastCycle: now.Add(-7 * time.Hour), NextRun: now.Add(-3 * time.Hour), Interval: 4 * time.Hour}
	r := Build(in)
	p, ok := problem(r, "daemon")
	if !ok || p.Level != Red || !strings.Contains(p.Detail, "overdue") || !p.Since.Equal(now.Add(-3*time.Hour)) || r.Level != Red {
		t.Fatalf("%s %+v", r.Level, r.Problems)
	}
}

func TestChannelProblems(t *testing.T) {
	in := provenInput()
	in.Channels = []string{"slack", "email", "hook", "quiet"}
	in.Delivery = map[string]model.ChannelHealth{
		"slack": {LastAttempt: now, LastSuccess: now},
		"email": {LastAttempt: now, Failures: 3, LastError: "smtp down", FailingSince: now.Add(-time.Hour)},
		"hook":  {LastAttempt: now, Failures: 1, LastError: "502"},
	}
	r := Build(in)
	if p, _ := problem(r, "channel:email"); p.Level != Red || !strings.Contains(p.Detail, "smtp down") || !p.Since.Equal(now.Add(-time.Hour)) {
		t.Errorf("email: %+v", p)
	}
	if p, _ := problem(r, "channel:hook"); p.Level != Yellow || !p.Since.Equal(now) {
		t.Errorf("hook: no success yet, so the streak began at the first attempt: %+v", p)
	}
	for _, name := range []string{"slack", "quiet"} {
		if _, ok := problem(r, "channel:"+name); ok {
			t.Errorf("%s is no problem", name)
		}
	}
	if r.Channels[0].Name != "email" || r.Channels[len(r.Channels)-1].Level != Green {
		t.Errorf("a channel that never delivered is not broken: %+v", r.Channels)
	}
}

func TestProblemsAreOrderedRedFirstThenOldest(t *testing.T) {
	in := provenInput()
	in.Problems = []Problem{
		{Key: "z-yellow-new", Level: Yellow, Since: now.Add(-time.Hour)},
		{Key: "b-yellow-undated", Level: Yellow},
		{Key: "a-yellow-old", Level: Yellow, Since: now.Add(-5 * time.Hour)},
		{Key: "red-new", Level: Red, Since: now.Add(-time.Minute)},
		{Key: "red-old", Level: Red, Since: now.Add(-9 * time.Hour)},
	}
	r := Build(in)
	var keys []string
	for _, p := range r.Problems {
		keys = append(keys, p.Key)
	}
	if got, want := strings.Join(keys, ","), "red-old,red-new,a-yellow-old,z-yellow-new,b-yellow-undated"; got != want {
		t.Fatalf("order = %s, want %s", got, want)
	}
	if r.Level != Red {
		t.Errorf("the overall level is the worst problem: %s", r.Level)
	}
	in.Problems = in.Problems[:1]
	if r := Build(in); r.Level != Yellow {
		t.Errorf("yellow only: %s", r.Level)
	}
}

func TestSummary(t *testing.T) {
	in := provenInput()
	if got := Build(in).Summary(now); got != "GREEN · last check 11:56 (4m ago)" {
		t.Errorf("green: %q", got)
	}
	if got := Build(in).Summary(now.Add(60 * time.Hour)); got != "GREEN · last check 10-28 11:56 (2d ago)" {
		t.Errorf("green, another day: %q", got)
	}
	zone := time.FixedZone("CET", 3600)
	if got := Build(in).Summary(now.In(zone)); !strings.Contains(got, "last check 12:56") {
		t.Errorf("shown where the viewer is: %q", got)
	}
	in.Problems = []Problem{{Key: "a", Level: Yellow}, {Key: "b", Level: Yellow}}
	if got := Build(in).Summary(now); got != "YELLOW · 2 problems" {
		t.Errorf("yellow: %q", got)
	}
	in.Problems = []Problem{{Key: "a", Level: Red}}
	if got := Build(in).Summary(now); got != "RED · 1 problem" {
		t.Errorf("red: %q", got)
	}
	if got := (Report{Level: Green}).Summary(now); got != "GREEN" {
		t.Errorf("green without a cycle on record: %q", got)
	}
}
