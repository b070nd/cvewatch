package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/b070nd/cvewatch/app/src/confdoc"
	"github.com/b070nd/cvewatch/app/src/ops"
)

func TestSettingsShowSharedValuesUntilTheUserSetsThem(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(root, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("config/config.yaml.dist", "interval: 2h\nlookback: 72h\n")
	write("config/config.yaml", "lookback: 96h\n")
	ss, err := ops.OpenSettings(root)
	if err != nil {
		t.Fatal(err)
	}
	v, err := ss.View()
	if err != nil {
		t.Fatal(err)
	}
	m := newSetModel(v)
	row := func(path string) setRow {
		f, ok := confdoc.Lookup(confdoc.KindSettings, path)
		if !ok {
			t.Fatalf("no field %s", path)
		}
		return m.fieldRow(f, strings.Split(path, "."))
	}
	if r := row("interval"); r.value != "2h (shared)" || r.doc != confdoc.IDSettings {
		t.Fatalf("a shared value is shown as such and edited in config.yaml: %+v", r)
	}
	if r := row("lookback"); r.value != "96h" {
		t.Fatalf("the user's value wins: %+v", r)
	}
}
