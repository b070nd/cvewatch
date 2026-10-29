package discovery

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode"

	"github.com/b070nd/cvewatch/app/src/matrix"
)

const (
	maxEntries = 200
	maxMarks   = 5
	maxScanned = 300 // folders whose contents are read per call, so a huge folder stays quick
	sep        = string(filepath.Separator)
)

type Entry struct {
	Path    string   // absolute path of the folder
	Name    string   // base name
	Marks   []string // names found directly inside that say "project": lockfiles, manifests, .git, Dockerfile...
	Score   int
	Project bool // lockfiles or manifests were found inside
}

var manifestMarks = []string{"go.mod", "package.json", "composer.json", "pom.xml", "build.gradle", "requirements.txt", "pyproject.toml"}

var otherMarks = []string{"Dockerfile", "compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml", ".tool-versions"}

var markWeights = func() map[string]int {
	w := map[string]int{".git": 5}
	for _, n := range matrix.FileNames() {
		w[n] = 10
	}
	for _, n := range manifestMarks {
		w[strings.ToLower(n)] = 10
	}
	for _, n := range otherMarks {
		w[strings.ToLower(n)] = 2
	}
	return w
}()

func Suggest(typed string) (parent string, entries []Entry, err error) {
	folder, prefix := split(typed)
	folder, err = expandHome(folder)
	if err != nil {
		return "", nil, err
	}
	parent, err = filepath.Abs(folder)
	if err != nil {
		return "", nil, err
	}
	info, err := os.Stat(parent)
	if err != nil {
		return parent, nil, fmt.Errorf("no such folder: %s", parent)
	}
	if !info.IsDir() {
		return parent, nil, fmt.Errorf("%s is a file, not a folder", parent)
	}
	children, err := os.ReadDir(parent)
	if err != nil {
		return parent, nil, fmt.Errorf("no such folder: %s", parent)
	}
	scanned := 0
	for _, d := range children {
		name := d.Name()
		if skipDirs[name] {
			continue
		}
		if strings.HasPrefix(name, ".") && !strings.HasPrefix(prefix, ".") {
			continue
		}
		if !hasPrefixFold(name, prefix) && !containsFold(name, prefix) {
			continue
		}
		path := filepath.Join(parent, name)
		if !isFolder(path, d) {
			continue
		}
		e := Entry{Path: path, Name: name}
		if scanned < maxScanned {
			scanned++
			e.Marks, e.Score = scanMarks(path)
			e.Project = e.Score >= 10
		}
		if hasPrefixFold(name, prefix) {
			e.Score += 20
		}
		entries = append(entries, e)
	}
	// names that only contain the typed text come after the ones that start with it
	slices.SortStableFunc(entries, func(a, b Entry) int {
		pa, pb := hasPrefixFold(a.Name, prefix), hasPrefixFold(b.Name, prefix)
		if pa != pb {
			if pa {
				return -1
			}
			return 1
		}
		if a.Score != b.Score {
			return b.Score - a.Score
		}
		return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name))
	})
	if len(entries) > maxEntries {
		entries = entries[:maxEntries]
	}
	return parent, entries, nil
}

func Complete(typed string, entries []Entry) string {
	out := completion(typed, entries)
	if len(out) < len(typed) {
		return typed
	}
	return out
}

func completion(typed string, entries []Entry) string {
	folder, prefix := split(typed)
	if folder != "" && !strings.HasSuffix(folder, sep) {
		folder += sep
	}
	switch len(entries) {
	case 0:
		return typed
	case 1:
		return folder + entries[0].Name + sep
	}
	common := entries[0].Name
	for _, e := range entries[1:] {
		common = commonPrefix(common, e.Name)
	}
	if !hasPrefixFold(common, prefix) {
		return typed
	}
	return folder + common
}

func split(typed string) (folder, prefix string) {
	base := filepath.Base(typed)
	if typed == "" || typed == "~" || strings.HasSuffix(typed, sep) || base == "." || base == ".." {
		return typed, ""
	}
	i := strings.LastIndex(typed, sep)
	return typed[:i+1], typed[i+1:]
}

func expandHome(folder string) (string, error) {
	if folder != "~" && !strings.HasPrefix(folder, "~"+sep) {
		return folder, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, folder[1:]), nil
}

func isFolder(path string, d os.DirEntry) bool {
	if d.Type()&os.ModeSymlink != 0 {
		info, err := os.Stat(path)
		return err == nil && info.IsDir()
	}
	return d.IsDir()
}

func scanMarks(dir string) ([]string, int) {
	children, _ := os.ReadDir(dir)
	var names []string
	score := 0
	for _, d := range children {
		if w, ok := markWeights[strings.ToLower(d.Name())]; ok {
			names = append(names, d.Name())
			score += w
		}
	}
	slices.SortStableFunc(names, func(a, b string) int {
		return markWeights[strings.ToLower(b)] - markWeights[strings.ToLower(a)]
	})
	if len(names) > maxMarks {
		names = names[:maxMarks]
	}
	return names, score
}

func hasPrefixFold(name, prefix string) bool {
	return strings.HasPrefix(strings.ToLower(name), strings.ToLower(prefix))
}

func containsFold(name, sub string) bool {
	return strings.Contains(strings.ToLower(name), strings.ToLower(sub))
}

func commonPrefix(a, b string) string {
	ra, rb := []rune(a), []rune(b)
	n := 0
	for n < len(ra) && n < len(rb) && unicode.ToLower(ra[n]) == unicode.ToLower(rb[n]) {
		n++
	}
	return string(ra[:n])
}
