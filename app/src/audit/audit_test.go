package audit

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestChainDetectsTampering(t *testing.T) {
	dir := t.TempDir()
	l := Open(dir)
	ev := func(a string) Event { return Event{Time: time.Unix(1, 0).UTC(), Actor: "t", Action: a} }
	if err := l.Append(ev("detected"), ev("alerted")); err != nil {
		t.Fatal(err)
	}
	if err := l.Append(ev("status")); err != nil { // a second call must continue the chain
		t.Fatal(err)
	}
	if n, err := l.Verify(); err != nil || n != 3 {
		t.Fatalf("n=%d err=%v", n, err)
	}

	raw, _ := os.ReadFile(l.path)
	forged := strings.Replace(string(raw), `"alerted"`, `"nothing"`, 1)
	os.WriteFile(l.path, []byte(forged), 0o600)
	if _, err := l.Verify(); err == nil || !strings.Contains(err.Error(), "line 3") {
		t.Fatalf("edit in the middle must break the next link: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	os.WriteFile(l.path, []byte(lines[0]+"\n"+lines[2]+"\n"), 0o600)
	if _, err := l.Verify(); err == nil {
		t.Fatal("deleting a line must be detected")
	}
}

func TestNilLogAndMissingFile(t *testing.T) {
	var l *Log
	if err := l.Append(Event{}); err != nil {
		t.Fatal(err)
	}
	if n, err := Open(t.TempDir()).Verify(); n != 0 || err != nil {
		t.Fatal(n, err)
	}
	t.Setenv("CVEWATCH_ACTOR", "team-sec")
	if Actor() != "team-sec" {
		t.Fatal("actor override ignored")
	}
}

func TestRenamesChainOldNotesAndFailures(t *testing.T) {
	at := func(h int, e Event) Event { e.Time = time.Unix(int64(h)*3600, 0).UTC(); e.Action = "project"; return e }
	evs := []Event{
		{Action: "detected", Project: "a"},                                                           // 0
		at(1, Event{Project: "a", To: "b", Note: "renamed project to b: 2 findings moved"}),          // 1
		{Action: "detected", Project: "b"},                                                           // 2
		at(2, Event{Project: "b", Note: "renamed project to c: 2 findings moved; access x updated"}), // 3: old log, no To
		at(3, Event{Project: "c", To: "d", Note: "renamed project to d: 2 findings moved"}),          // 4: failed below
		{Time: time.Unix(3*3600, 0).UTC(), Action: "project-failed", Project: "c"},                   // 5
		at(4, Event{Project: "c", Note: "edited project file: 1 change(s)"}),                         // 6
		{Action: "detected", Project: "a"},                                                           // 7: a new project reusing the name
	}
	rs := Renames(evs)
	if len(rs) != 2 || rs[0] != (Rename{"a", "b", 1}) || rs[1] != (Rename{"b", "c", 3}) {
		t.Fatalf("renames: %+v", rs)
	}
	for _, c := range []struct {
		name string
		at   int
		want string
	}{{"a", 0, "c"}, {"b", 2, "c"}, {"c", 5, "c"}, {"a", 7, "a"}, {"b", 4, "b"}, {"x", 0, "x"}} {
		if got := CurrentName(rs, c.name, c.at); got != c.want {
			t.Errorf("%s at %d: %s, want %s", c.name, c.at, got, c.want)
		}
	}
}
