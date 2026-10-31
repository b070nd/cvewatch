package main

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/b070nd/cvewatch/app/src/ledger"
	"github.com/b070nd/cvewatch/app/src/ops"
	"github.com/b070nd/cvewatch/app/src/store"
)

func statusWith(t *testing.T, root string, args ...string) (string, error) {
	t.Helper()
	return capture(t, func() error {
		return withSession(root, slog.New(slog.NewTextHandler(io.Discard, nil)), func(s *ops.Session) error { return statusCmd(s, args) })
	})
}

func withFeed(t *testing.T, root string, fail int, ok bool) {
	t.Helper()
	feed := "sources:\n  - id: hn\n    type: rss\n    url: https://feed.example.com/rss\n"
	if err := os.WriteFile(filepath.Join(root, "sources", "s.yaml"), []byte(feed), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := store.OpenFile(filepath.Join(root, "data"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	state, err := st.Load()
	if err != nil {
		t.Fatal(err)
	}
	l := ledger.New(state)
	now := time.Now()
	if ok {
		l.SourceOutcome("hn", "rss", now.Add(-5*time.Minute), 3, nil)
	}
	for range fail {
		l.SourceOutcome("hn", "rss", now, 0, errors.New("status 503"))
	}
	if err := st.Save(l.State()); err != nil {
		t.Fatal(err)
	}
}

func TestStatusExitCodeIsNonzeroOnlyOnRed(t *testing.T) {
	root := fixtureRoot(t)
	out, err := statusWith(t, root)
	if err != nil || !strings.HasPrefix(out, "YELLOW · 2 problems\n") || !strings.Contains(out, "no cycle has run yet") || !strings.Contains(out, "project shop") {
		t.Fatalf("yellow exits 0 and lists the problem: %v\n%s", err, out)
	}

	withFeed(t, root, 1, true)
	if out, err = statusWith(t, root); err != nil || !strings.HasPrefix(out, "YELLOW · ") || !strings.Contains(out, "feed hn had a failed fetch") {
		t.Fatalf("a single failure is yellow: %v\n%s", err, out)
	}

	withFeed(t, root, 3, true)
	out, err = statusWith(t, root)
	if err == nil {
		t.Fatalf("red exits non-zero:\n%s", out)
	}
	for _, want := range []string{"RED · ", "RED    feed hn is failing", "status 503", "since "} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Overall") {
		t.Errorf("the old overall line is gone:\n%s", out)
	}
}

func TestStatusJSONUsesTheNewLevels(t *testing.T) {
	root := fixtureRoot(t)
	withFeed(t, root, 3, true)
	out, _ := statusWith(t, root, "-json")
	for _, want := range []string{`"level": "red"`, `"problems": [`, `"key": "feed:hn"`} {
		if !strings.Contains(out, want) {
			t.Errorf("json lacks %q:\n%s", want, out)
		}
	}
	for _, old := range []string{`"fail"`, `"warn"`, `"unknown"`, `"ok"`} {
		if strings.Contains(out, old) {
			t.Errorf("json still says %s", old)
		}
	}
}
