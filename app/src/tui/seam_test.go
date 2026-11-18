package tui

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The TUI reaches the monitor only through ops methods: a session's
// configuration, ledger and audit log are not its to read, so a rule or an
// access check cannot be bypassed or written a second time here.
func TestTheTUIUsesOnlyOpsMethods(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	field := regexp.MustCompile(`\.(Cfg|Ledger|Audit)\b`)
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(src), "\n") {
			if m := field.FindString(line); m != "" {
				t.Errorf("%s:%d reads a session's %s; add an ops method instead", f, i+1, strings.TrimPrefix(m, "."))
			}
		}
	}
}
