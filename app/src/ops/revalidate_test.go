package ops

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/b070nd/cvewatch/app/src/audit"
	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/ledger"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/store"
)

func TestRevalidateDryRunApplyAndIdempotence(t *testing.T) {
	cfg, st := bundle(t, nil), seeded(t)
	s := open(t, cfg, st, "alice")

	pre, err := s.Revalidate(false)
	if err != nil || pre.Applied || pre.NewFindings == 0 || len(pre.Projects) != 2 {
		t.Fatalf("preview: %+v %v", pre, err)
	}
	if s.Ledger.Judged() != nil || len(s.Ledger.FindingsOf("CVE-2026-2")) != 0 {
		t.Fatal("a preview changes nothing")
	}
	if n, _ := audit.Open(cfg.DataDir).Verify(); n != 0 {
		t.Fatalf("a preview writes no audit event, got %d", n)
	}

	done, err := s.Revalidate(true)
	if err != nil || !done.Applied || done.NewFindings != pre.NewFindings {
		t.Fatalf("apply must do what the preview said: %+v vs %+v (%v)", done, pre, err)
	}
	if n, err := audit.Open(cfg.DataDir).Verify(); err != nil || n != 1 {
		t.Fatalf("one audit event expected: n=%d err=%v", n, err)
	}
	re := open(t, cfg, st, "alice") // persisted
	if again, err := re.Revalidate(true); err != nil || again.NewFindings+again.Closed+again.Reopened+again.Reconciled != 0 {
		t.Fatalf("second run: %+v %v", again, err)
	}
	stale, err := re.Stale()
	if err != nil || stale.Stale || stale.Never || stale.JudgedAt.IsZero() {
		t.Fatalf("freshly judged: %+v %v", stale, err)
	}
}

func TestStaleSeesEditsAndWorksReadOnly(t *testing.T) {
	cfg, st := bundle(t, nil), seeded(t)
	rw := open(t, cfg, st, "alice")
	if got, err := rw.Stale(); err != nil || !got.Stale || !got.Never || len(got.Projects) != 2 {
		t.Fatalf("never judged: %+v %v", got, err)
	}
	if _, err := rw.Revalidate(true); err != nil {
		t.Fatal(err)
	}

	cfg.Projects[0].Since = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC) // shop gets a since date, as an edit would
	ro, err := OpenReadOnlyWith(cfg, st, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err != nil {
		t.Fatal(err)
	}
	got, err := ro.Stale()
	if err != nil || !got.Stale || got.Never || !slices.Equal(got.Projects, []string{"shop"}) || !got.Backfill.Equal(cfg.Projects[0].Since) {
		t.Fatalf("stale: %+v %v", got, err)
	}
	if pre, err := ro.Revalidate(false); err != nil || pre.Applied {
		t.Fatalf("a read-only session may preview: %+v %v", pre, err)
	}
	if _, err := ro.Revalidate(true); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("applying needs a writable session: %v", err)
	}
}

func TestRevalidateAccess(t *testing.T) {
	cfg := bundle(t, map[string]config.Grant{
		"alice": {Projects: []string{"shop"}, Write: true},
		"bob":   {Projects: []string{"*"}},
		"root":  {Projects: []string{"*"}, Write: true},
	})
	st := seeded(t)

	alice := open(t, cfg, st, "alice")
	if _, err := alice.Revalidate(true); !errors.Is(err, ErrDenied) {
		t.Fatalf("revalidating touches every project and needs access to all: %v", err)
	}
	pre, err := alice.Revalidate(false)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(pre.Projects, []string{"shop"}) {
		t.Errorf("alice sees only her project: %v", pre.Projects)
	}
	for _, c := range pre.Changes {
		if slices.Contains(c.Projects, "mw") {
			t.Errorf("another project's issue leaked: %+v", c)
		}
	}
	if _, err := open(t, cfg, st, "bob").Revalidate(true); !errors.Is(err, ErrDenied) {
		t.Fatalf("bob is read-only: %v", err)
	}
	if _, err := open(t, cfg, st, "mallory").Revalidate(false); !errors.Is(err, ErrDenied) {
		t.Fatalf("unlisted actors get nothing: %v", err)
	}
	if _, err := open(t, cfg, st, "root").Revalidate(true); err != nil {
		t.Fatalf("root may: %v", err)
	}
	if _, err := alice.Backfill(context.Background(), nil); !errors.Is(err, ErrDenied) {
		t.Fatalf("fetching the back-fill is a refresh and needs the same access: %v", err)
	}
}

func TestRevalidateMarksSourcesAndRescanAppliesSince(t *testing.T) {
	cfg := bundle(t, nil)
	cfg.Sources = []model.Source{{ID: "nvd", Type: "nvd", URL: "https://nvd.test/?s={since}"}, {ID: "off", Type: "kev", URL: "https://k.test", Disabled: true}}
	cfg.Projects[0].Since = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	st := store.NewMemory()
	l := ledger.New(ledger.State{})
	old := l.Create(model.Item{Title: "Old PHP bug", URL: "https://a.test/o", IDs: []string{"CVE-2023-9"}, Published: time.Date(2023, 5, 1, 0, 0, 0, 0, time.UTC),
		SourceID: "nvd", SourceType: "nvd"}, day, []string{"php"})
	l.AddFinding(model.Finding{VulnID: old.ID, Project: "shop", Env: model.EnvProd, Status: model.StatusOpen})
	l.SetFeed("nvd", model.FeedState{LastRun: day, Covered: time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC)})
	if err := st.Save(l.State()); err != nil {
		t.Fatal(err)
	}

	s := open(t, cfg, st, "alice")
	rv, err := s.Revalidate(true)
	if err != nil || rv.Closed != 1 || !slices.Equal(rv.BackfillSources, []string{"nvd"}) || !rv.Backfill.Equal(cfg.Projects[0].Since) {
		t.Fatalf("%+v %v", rv, err)
	}
	if got := s.Ledger.Feed("nvd").Backfill; !got.Equal(cfg.Projects[0].Since) {
		t.Fatalf("nvd must owe a back-fill to the since date: %v", got)
	}
	if pending, _ := s.Stale(); !slices.Equal(pending.BackfillPending, []string{"nvd"}) {
		t.Fatalf("pending back-fill must be visible: %+v", pending)
	}
	f := s.Ledger.FindingsOf("CVE-2023-9")[0]
	if f.Status != model.StatusNotAffected || !f.Auto || !strings.Contains(f.Note, "2024-01-01") {
		t.Fatalf("finding: %+v", f)
	}
	// Resolve by a person takes over.
	if _, err := s.Resolve(Change{ID: "CVE-2023-9", Project: "shop", Status: model.StatusOpen}); err != nil {
		t.Fatal(err)
	}
	if s.Ledger.FindingsOf("CVE-2023-9")[0].Auto {
		t.Fatal("a status set through Resolve is manual")
	}
}
