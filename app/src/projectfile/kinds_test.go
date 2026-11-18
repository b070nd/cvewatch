package projectfile

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// A kind written as a string compiles, because a string constant converts to
// Kind; only the named constants are checked by the compiler. Code outside
// tests therefore names kinds by their constants.
func TestNoKindIsSpelledAsAString(t *testing.T) {
	var names []string
	for _, k := range Kinds() {
		names = append(names, regexp.QuoteMeta(string(k)))
	}
	spelled := regexp.MustCompile(`Kind(:| ==| !=) "(` + strings.Join(names, "|") + `)"|case "(` + strings.Join(names, "|") + `)"`)
	err := filepath.WalkDir("..", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for i, line := range strings.Split(string(src), "\n") {
			if m := spelled.FindString(line); m != "" {
				t.Errorf("%s:%d spells a kind as a string (%s); use its constant from kinds.go", path, i+1, m)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
