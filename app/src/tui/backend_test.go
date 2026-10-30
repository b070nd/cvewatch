package tui

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/ops"
	"github.com/b070nd/cvewatch/app/src/pipeline"
	"github.com/b070nd/cvewatch/app/src/store"
)

// backendRoot is an empty configuration folder; the data folder defaults to
// its sibling, so the whole tree lives in the test's temp folder.
func backendRoot(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "app")
	if err := os.MkdirAll(filepath.Join(root, "config"), 0o755); err != nil {
		t.Fatal(err)
	}
	return root
}

func writeConfig(t *testing.T, root, text string) {
	t.Helper()
	if err := os.WriteFile(config.SettingsPath(root), []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestBackendReadsTheTUISettings(t *testing.T) {
	root := backendRoot(t)
	b := NewBackend(root, nil)
	if got := b.TUISettings(); got != (config.TUI{Refresh: 30 * time.Second}) {
		t.Fatalf("no config.yaml: defaults expected, got %+v", got)
	}
	writeConfig(t, root, "tui:\n  refresh: 5s\n  fetch: 15m\n")
	if got := b.TUISettings(); got != (config.TUI{Refresh: 5 * time.Second, Fetch: 15 * time.Minute}) {
		t.Fatalf("got %+v", got)
	}
	writeConfig(t, root, "tui:\n  fetch: 1h\n")
	if got := b.TUISettings(); got != (config.TUI{Refresh: 30 * time.Second, Fetch: time.Hour}) {
		t.Fatalf("a missing key keeps its default, got %+v", got)
	}
}

func TestBackendSettingsFallBackToDefaultsWhenConfigIsBroken(t *testing.T) {
	root := backendRoot(t)
	b := NewBackend(root, nil)
	for name, text := range map[string]string{
		"not yaml":          "tui: [unclosed\n  - : :\n",
		"wrong type":        "tui: nope\n",
		"refresh too small": "tui:\n  refresh: 100ms\n  fetch: -5m\n",
		"other key broken":  "interval: soon\ntui:\n  refresh: 5s\n",
	} {
		writeConfig(t, root, text)
		got := b.TUISettings()
		want := config.TUI{Refresh: 30 * time.Second}
		if name == "other key broken" {
			want.Refresh = 5 * time.Second // the tui section alone decides its values
		}
		if got != want {
			t.Errorf("%s: got %+v, want %+v", name, got, want)
		}
	}
}

func TestBackendFetchReportsBusyWhileAnotherProcessHoldsTheData(t *testing.T) {
	root := backendRoot(t)
	held, err := store.OpenFile(filepath.Join(filepath.Dir(root), "data"))
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	_, err = NewBackend(root, nil).Fetch(t.Context(), nil)
	if !errors.Is(err, ErrBusy) {
		t.Fatalf("want ErrBusy, got %v", err)
	}
}

func TestBackendFetchRunsACycleWithProgress(t *testing.T) {
	root := backendRoot(t)
	cfg, err := config.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	off := make([]map[string]any, 0, len(cfg.Sources)) // switch every feed off: the test must not reach the network
	for _, s := range cfg.Sources {
		off = append(off, map[string]any{"id": s.ID, "type": s.Type, "url": s.URL, "disabled": true})
	}
	raw, err := yaml.Marshal(map[string]any{"sources": off})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(config.SourcesDir(root), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(config.SourcesDir(root), "off.yaml"), raw, 0o600); err != nil {
		t.Fatal(err)
	}

	var phases []pipeline.Phase
	res, err := NewBackend(root, nil).Fetch(t.Context(), func(p ops.RefreshProgress) { phases = append(phases, p.Phase) })
	if err != nil {
		t.Fatal(err)
	}
	want := []pipeline.Phase{pipeline.PhaseFetch, pipeline.PhaseProcess, pipeline.PhaseEnrich, pipeline.PhaseSave, pipeline.PhaseAlert}
	if len(phases) != len(want) || res.Items != 0 {
		t.Fatalf("phases %v, result %+v", phases, res)
	}
	for i := range want {
		if phases[i] != want[i] {
			t.Fatalf("phases %v, want %v", phases, want)
		}
	}
	// the session was closed again: a second fetch must not find the data busy
	if _, err := NewBackend(root, nil).Fetch(t.Context(), nil); err != nil {
		t.Fatalf("second fetch: %v", err)
	}
}
