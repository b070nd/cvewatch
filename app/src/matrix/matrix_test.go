package matrix

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"cvewatch/src/model"
)

func TestLoad(t *testing.T) {
	tests := []struct {
		name    string
		typ     string
		content string
		want    []model.Package
		wantErr string
	}{
		{
			name:    "composer strips v prefix and lowercases",
			typ:     "composer",
			content: `{"packages":[{"name":"Symfony/HTTP-Kernel","version":"v6.4.1"}],"packages-dev":[{"name":"phpunit/phpunit","version":"10.5.0"}]}`,
			want: []model.Package{
				{Name: "phpunit/phpunit", Version: "10.5.0", Ecosystem: "composer"},
				{Name: "symfony/http-kernel", Version: "6.4.1", Ecosystem: "composer"},
			},
		},
		{
			name:    "npm v1 walks nested dependencies",
			typ:     "npm",
			content: `{"lockfileVersion":1,"dependencies":{"lodash":{"version":"4.17.21"},"a":{"version":"1.0.0","dependencies":{"@Scope/B":{"version":"2.0.0"}}}}}`,
			want: []model.Package{
				{Name: "@scope/b", Version: "2.0.0", Ecosystem: "npm"},
				{Name: "a", Version: "1.0.0", Ecosystem: "npm"},
				{Name: "lodash", Version: "4.17.21", Ecosystem: "npm"},
			},
		},
		{
			name:    "npm v3 packages map with nested and scoped names",
			typ:     "npm",
			content: `{"lockfileVersion":3,"packages":{"":{"name":"app","version":"1.0.0"},"node_modules/lodash":{"version":"4.17.21"},"node_modules/a":{"version":"1.0.0"},"node_modules/a/node_modules/@Scope/B":{"version":"2.0.0"}}}`,
			want: []model.Package{
				{Name: "@scope/b", Version: "2.0.0", Ecosystem: "npm"},
				{Name: "a", Version: "1.0.0", Ecosystem: "npm"},
				{Name: "lodash", Version: "4.17.21", Ecosystem: "npm"},
			},
		},
		{
			name:    "dedupes name+version and keeps other versions",
			typ:     "composer",
			content: `{"packages":[{"name":"x/y","version":"v1.0.0"},{"name":"x/y","version":"2.0.0"}],"packages-dev":[{"name":"X/Y","version":"1.0.0"}]}`,
			want: []model.Package{
				{Name: "x/y", Version: "1.0.0", Ecosystem: "composer"},
				{Name: "x/y", Version: "2.0.0", Ecosystem: "composer"},
			},
		},
		{
			name:    "unknown type",
			typ:     "pip",
			content: `{}`,
			wantErr: `unknown lockfile type "pip"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "lock.json")
			if err := os.WriteFile(path, []byte(tt.content), 0o644); err != nil {
				t.Fatal(err)
			}

			got, err := Load(model.Lockfile{Type: tt.typ, Path: path})
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}
