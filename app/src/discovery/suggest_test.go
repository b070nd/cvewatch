package discovery

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func makeTree(t *testing.T, root string, folders map[string][]string) {
	t.Helper()
	for name, marks := range folders {
		dir := filepath.Join(root, name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		for _, m := range marks {
			p := filepath.Join(dir, m)
			if m == ".git" {
				if err := os.MkdirAll(p, 0o755); err != nil {
					t.Fatal(err)
				}
				continue
			}
			if err := os.WriteFile(p, nil, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func namesOf(entries []Entry) []string {
	out := []string{}
	for _, e := range entries {
		out = append(out, e.Name)
	}
	return out
}

func TestSuggestRanking(t *testing.T) {
	tests := []struct {
		name      string
		folders   map[string][]string
		typed     string // appended to the root folder
		wantNames []string
	}{
		{"manifest before empty", map[string][]string{"empty": nil, "svc": {"go.mod"}}, "/", []string{"svc", "empty"}},
		{"git beats a dockerfile", map[string][]string{"plain": {"Dockerfile"}, "repo": {".git"}}, "/", []string{"repo", "plain"}},
		{"lockfile beats dockerfiles", map[string][]string{"a-docker": {"Dockerfile", "compose.yaml", "compose.yml"}, "b-lock": {"package-lock.json"}}, "/", []string{"b-lock", "a-docker"}},
		{"prefix before contains", map[string][]string{"my-api": {"go.mod", "pom.xml", ".git"}, "api-gw": nil}, "/api", []string{"api-gw", "my-api"}},
		{"ties sort by name ignoring case", map[string][]string{"beta": nil, "Alpha": nil}, "/", []string{"Alpha", "beta"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			makeTree(t, root, tt.folders)
			_, entries, err := Suggest(root + filepath.FromSlash(tt.typed))
			if err != nil {
				t.Fatal(err)
			}
			if got := namesOf(entries); !slices.Equal(got, tt.wantNames) {
				t.Errorf("names = %v, want %v", got, tt.wantNames)
			}
		})
	}
}

func TestSuggestHiddenAndSkipped(t *testing.T) {
	tests := []struct {
		typed     string
		wantNames []string
	}{
		{"/", []string{"visible"}},
		{"/.h", []string{".hidden"}},
		{"/vis", []string{"visible"}},
		{"/node", nil},
		{"/.c", nil},
	}
	root := t.TempDir()
	makeTree(t, root, map[string][]string{
		"visible": nil, ".hidden": nil, "node_modules": nil, "vendor": nil, "target": nil, ".cache": nil, ".git": nil,
	})
	for _, tt := range tests {
		t.Run(tt.typed, func(t *testing.T) {
			_, entries, err := Suggest(root + filepath.FromSlash(tt.typed))
			if err != nil {
				t.Fatal(err)
			}
			if got := namesOf(entries); !slices.Equal(got, tt.wantNames) {
				t.Errorf("names = %v, want %v", got, tt.wantNames)
			}
		})
	}
}

func TestSuggestSymlinks(t *testing.T) {
	root := t.TempDir()
	makeTree(t, root, map[string][]string{"real": {"go.mod"}})
	if err := os.Symlink(filepath.Join(root, "real"), filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "nowhere"), filepath.Join(root, "dangling")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "note.txt"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	_, entries, err := Suggest(root + string(filepath.Separator))
	if err != nil {
		t.Fatal(err)
	}
	if got := namesOf(entries); !slices.Equal(got, []string{"link", "real"}) {
		t.Fatalf("names = %v, want [link real]", got)
	}
	if entries[0].Path != filepath.Join(root, "link") || !slices.Equal(entries[0].Marks, []string{"go.mod"}) {
		t.Errorf("link entry = %+v", entries[0])
	}
}

func TestSuggestTrailingSeparator(t *testing.T) {
	tests := []struct {
		name      string
		typed     string // appended to the base folder
		wantRel   string // the listed parent, relative to the base folder
		wantNames []string
	}{
		{"separator lists inside the folder", "/alpha/", "alpha", []string{"sub"}},
		{"no separator lists siblings", "/alp", "", []string{"alpha", "alps"}},
		{"no separator names the folder itself", "/alpha", "", []string{"alpha"}},
	}
	base := t.TempDir()
	makeTree(t, base, map[string][]string{"alpha/sub": nil, "alps": nil})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parent, entries, err := Suggest(base + filepath.FromSlash(tt.typed))
			if err != nil {
				t.Fatal(err)
			}
			if want := filepath.Join(base, tt.wantRel); parent != want {
				t.Errorf("parent = %s, want %s", parent, want)
			}
			if got := namesOf(entries); !slices.Equal(got, tt.wantNames) {
				t.Errorf("names = %v, want %v", got, tt.wantNames)
			}
		})
	}
}

func TestSuggestEmptyUsesWorkingDirectory(t *testing.T) {
	dir := t.TempDir()
	makeTree(t, dir, map[string][]string{"svc": {"go.mod"}})
	t.Chdir(dir)
	parent, entries, err := Suggest("")
	if err != nil {
		t.Fatal(err)
	}
	wantDir, _ := filepath.EvalSymlinks(dir)
	if got, _ := filepath.EvalSymlinks(parent); got != wantDir {
		t.Errorf("parent = %s, want %s", parent, dir)
	}
	if got := namesOf(entries); !slices.Equal(got, []string{"svc"}) {
		t.Errorf("names = %v, want [svc]", got)
	}
}

func TestSuggestHome(t *testing.T) {
	home := t.TempDir()
	makeTree(t, home, map[string][]string{"projects": {"go.mod"}, "Music": nil})
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	tests := []struct {
		typed     string
		wantNames []string
	}{
		{"~", []string{"projects", "Music"}},
		{"~/", []string{"projects", "Music"}},
		{"~/pro", []string{"projects"}},
	}
	for _, tt := range tests {
		t.Run(tt.typed, func(t *testing.T) {
			parent, entries, err := Suggest(filepath.FromSlash(tt.typed))
			if err != nil {
				t.Fatal(err)
			}
			if parent != home {
				t.Errorf("parent = %s, want %s", parent, home)
			}
			if got := namesOf(entries); !slices.Equal(got, tt.wantNames) {
				t.Errorf("names = %v, want %v", got, tt.wantNames)
			}
		})
	}
}

func TestSuggestErrors(t *testing.T) {
	base := t.TempDir()
	makeTree(t, base, map[string][]string{"sub": nil})
	if err := os.WriteFile(filepath.Join(base, "afile"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		typed   string
		parent  string
		wantErr string
	}{
		{"missing parent", "/nope/x", "nope", "no such folder: " + filepath.Join(base, "nope")},
		{"parent is a file", "/afile/", "afile", filepath.Join(base, "afile") + " is a file, not a folder"},
		{"prefix matches nothing", "/zzz", "", ""},
		{"a file is not listed", "/afi", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parent, entries, err := Suggest(base + filepath.FromSlash(tt.typed))
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if len(entries) != 0 {
					t.Errorf("entries = %v, want none", namesOf(entries))
				}
				return
			}
			if err == nil || err.Error() != tt.wantErr {
				t.Fatalf("error = %v, want %q", err, tt.wantErr)
			}
			if parent != filepath.Join(base, tt.parent) {
				t.Errorf("parent = %s", parent)
			}
		})
	}
}

func TestSuggestCapsAt200(t *testing.T) {
	root := t.TempDir()
	for i := range 250 {
		if err := os.Mkdir(filepath.Join(root, fmt.Sprintf("d%03d", i)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	_, entries, err := Suggest(root + string(filepath.Separator))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 200 {
		t.Fatalf("len = %d, want 200", len(entries))
	}
	if entries[0].Name != "d000" || entries[199].Name != "d199" {
		t.Errorf("first = %s, last = %s", entries[0].Name, entries[199].Name)
	}
}

func TestSuggestMarksAndScore(t *testing.T) {
	tests := []struct {
		name      string
		marks     []string
		wantMarks []string
		wantScore int
	}{
		{"strongest marks first", []string{"Dockerfile", ".git", "go.mod"}, []string{"go.mod", ".git", "Dockerfile"}, 10 + 5 + 2 + 20},
		{"capped at five", []string{"go.mod", "package.json", "pom.xml", "composer.json", "requirements.txt", ".git", "Dockerfile"},
			[]string{"composer.json", "go.mod", "package.json", "pom.xml", "requirements.txt"}, 50 + 5 + 2 + 20},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			makeTree(t, root, map[string][]string{"svc": tt.marks})
			_, entries, err := Suggest(root + string(filepath.Separator))
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 {
				t.Fatalf("len = %d, want 1", len(entries))
			}
			if !slices.Equal(entries[0].Marks, tt.wantMarks) {
				t.Errorf("marks = %v, want %v", entries[0].Marks, tt.wantMarks)
			}
			if entries[0].Score != tt.wantScore {
				t.Errorf("score = %d, want %d", entries[0].Score, tt.wantScore)
			}
		})
	}
}

func TestComplete(t *testing.T) {
	tests := []struct {
		name  string
		typed string
		names []string
		want  string
	}{
		{"no entries keeps typed", "src/fo", nil, "src/fo"},
		{"one entry adds separator", "src/fo", []string{"foo"}, "src/foo/"},
		{"one entry with trailing separator", "~/", []string{"projects"}, "~/projects/"},
		{"empty typed gives the bare name", "", []string{"svc"}, "svc/"},
		{"tilde keeps tilde", "~", []string{"projects"}, "~/projects/"},
		{"tilde prefix keeps tilde", "~/pro", []string{"projects"}, "~/projects/"},
		{"common prefix of several", "src/f", []string{"foo", "fork", "food"}, "src/fo"},
		{"common prefix keeps first case", "~/pro", []string{"projects", "Projector"}, "~/project"},
		{"several entries never add a separator", "src/d", []string{"Docs", "docs-old"}, "src/Docs"},
		{"whole name shared by a longer one", "~/ap", []string{"api", "api-v2"}, "~/api"},
		{"no common text keeps typed", "api", []string{"my-api", "api-x"}, "api"},
		{"common prefix equal to typed", "src/fo", []string{"foo", "fork"}, "src/fo"},
		{"tilde with several", "~/a", []string{"alpha", "alps"}, "~/alp"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var entries []Entry
			for _, n := range tt.names {
				entries = append(entries, Entry{Name: n})
			}
			if got := Complete(filepath.FromSlash(tt.typed), entries); got != filepath.FromSlash(tt.want) {
				t.Errorf("Complete(%q) = %q, want %q", tt.typed, got, tt.want)
			}
		})
	}
}
