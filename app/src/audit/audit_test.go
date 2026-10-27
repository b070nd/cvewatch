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
