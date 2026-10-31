package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/b070nd/cvewatch/app/src/ops"
)

func runRevalidate(t *testing.T, root string, args ...string) (string, error) {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return capture(t, func() error {
		return dispatch(context.Background(), root, log, append([]string{"revalidate"}, args...))
	})
}

func TestRevalidateCommandPreviewsThenApplies(t *testing.T) {
	root := fixtureRoot(t)
	out, err := runRevalidate(t, root)
	if err != nil || !strings.Contains(out, "Nothing was changed. Run again with -apply") || !strings.Contains(out, "Projects changed: shop") {
		t.Fatalf("preview: %v\n%s", err, out)
	}
	s, err := ops.OpenReadOnly(root, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := s.Stale(); !st.Stale || !st.Never {
		t.Fatalf("a preview records nothing: %+v", st)
	}
	s.Close()

	if out, err = runRevalidate(t, root, "-apply", "-json"); err != nil || !strings.Contains(out, `"applied": true`) {
		t.Fatalf("apply: %v\n%s", err, out)
	}

	// The project gets a since date: stale again, and the old name still works.
	p := filepath.Join(root, "config", "projects", "shop.yaml")
	body, _ := os.ReadFile(p)
	if err := os.WriteFile(p, append([]byte("since: 2024-01-01\n"), body...), 0o644); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	out, err = capture(t, func() error { return dispatch(context.Background(), root, log, []string{"rescan"}) })
	if err != nil || !strings.Contains(out, "Projects changed: shop") {
		t.Fatalf("rescan is the old name: %v\n%s", err, out)
	}
}
