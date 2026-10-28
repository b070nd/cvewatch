package matrix

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/b070nd/cvewatch/app/src/model"
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
				{Name: "phpunit/phpunit", Version: "10.5.0", Ecosystem: "composer", Dev: true},
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
			typ:     "bundler",
			content: `{}`,
			wantErr: `unknown lockfile type "bundler" (valid types: composer, cyclonedx, go, gradle, maven, npm, pip, pipfile, poetry, spdx)`,
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

func writeLock(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "lockfile")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadResultFormats(t *testing.T) {
	tests := []struct {
		name        string
		typ         string
		content     string
		want        []model.Package
		wantSkipped []string // substrings, in order
	}{
		{
			name: "npm dev flags v1 and v3",
			typ:  "npm",
			content: `{"lockfileVersion":3,"packages":{"":{"name":"app"},` +
				`"node_modules/a":{"version":"1.0.0"},"node_modules/b":{"version":"2.0.0","dev":true}}}`,
			want: []model.Package{
				{Name: "a", Version: "1.0.0", Ecosystem: "npm"},
				{Name: "b", Version: "2.0.0", Ecosystem: "npm", Dev: true},
			},
		},
		{
			name:    "npm v1 dev flag on nested entry",
			typ:     "npm",
			content: `{"lockfileVersion":1,"dependencies":{"a":{"version":"1.0.0","dependencies":{"b":{"version":"2.0.0","dev":true}}}}}`,
			want: []model.Package{
				{Name: "a", Version: "1.0.0", Ecosystem: "npm"},
				{Name: "b", Version: "2.0.0", Ecosystem: "npm", Dev: true},
			},
		},
		{
			name: "go.mod requires, indirect, replace and local replace",
			typ:  "go",
			content: `module example.com/app

go 1.22
toolchain go1.22.1

require github.com/Foo/Bar v1.2.3
require (
	golang.org/x/text v0.14.0 // indirect
	example.com/old v1.0.0
	example.com/local v0.0.0
	github.com/pseudo/x v0.0.0-20240101000000-abcdef123456
	example.com/rep v1.0.0 // pinned
)
exclude example.com/old v1.0.0
retract v1.0.0
replace example.com/old v1.0.0 => example.net/fork v1.0.1
replace example.com/local => ../local
replace (
	example.com/rep => example.org/rep2 v2.0.0
)
`,
			want: []model.Package{
				{Name: "example.com/local", Version: "v0.0.0", Ecosystem: "go"},
				{Name: "example.net/fork", Version: "v1.0.1", Ecosystem: "go"},
				{Name: "example.org/rep2", Version: "v2.0.0", Ecosystem: "go"},
				{Name: "github.com/foo/bar", Version: "v1.2.3", Ecosystem: "go"},
				{Name: "github.com/pseudo/x", Version: "v0.0.0-20240101000000-abcdef123456", Ecosystem: "go"},
				{Name: "golang.org/x/text", Version: "v0.14.0", Ecosystem: "go"},
			},
			wantSkipped: []string{"replace example.com/local => ../local is a local path"},
		},
		{
			name: "requirements pins, extras, markers, comments, continuations",
			typ:  "pip",
			content: `# comment
-r other.txt
--index-url https://example.com/simple
-e git+https://github.com/x/y.git#egg=y
Django==4.2.1
requests[security,socks]==2.31.0 ; python_version >= "3.8"  # trailing
Flask_Login===0.6.3 \
    --hash=sha256:aaa \
    --hash=sha256:bbb
numpy>=1.20
pandas
six==1.*
ruamel.yaml==0.18.5
`,
			want: []model.Package{
				{Name: "django", Version: "4.2.1", Ecosystem: "pypi"},
				{Name: "flask-login", Version: "0.6.3", Ecosystem: "pypi"},
				{Name: "requests", Version: "2.31.0", Ecosystem: "pypi"},
				{Name: "ruamel-yaml", Version: "0.18.5", Ecosystem: "pypi"},
			},
			wantSkipped: []string{`"-r other.txt"`, `"-e git+`, `"numpy>=1.20"`, `"pandas"`, `"six==1.*"`},
		},
		{
			name: "poetry 1.x category, poetry 2.x groups, optional kept",
			typ:  "poetry",
			content: `# generated
[[package]]
name = "Django"
version = "4.2.1"
optional = false
category = "main"

[package.dependencies]
name = "ignored"
version = "9.9.9"

[[package]]
name = "pytest"
version = "7.4.0"
category = "dev"
optional = true

[[package]]
name = "ruamel.yaml"
version = "0.18.5"
groups = ["dev"]

[[package]]
name = "tomli"
version = "2.0.1"
groups = ["main", "dev"]

[[package]]
name = "broken"
description = "no version"

[metadata]
lock-version = "2.0"
`,
			want: []model.Package{
				{Name: "django", Version: "4.2.1", Ecosystem: "pypi"},
				{Name: "pytest", Version: "7.4.0", Ecosystem: "pypi", Dev: true},
				{Name: "ruamel-yaml", Version: "0.18.5", Ecosystem: "pypi", Dev: true},
				{Name: "tomli", Version: "2.0.1", Ecosystem: "pypi"},
			},
			wantSkipped: []string{`"broken" has no version`},
		},
		{
			name: "pipfile default and develop",
			typ:  "pipfile",
			content: `{"_meta":{},"default":{"Requests":{"version":"==2.31.0"},"mylib":{"git":"https://x/y.git","ref":"abc"}},` +
				`"develop":{"pytest":{"version":"==7.4.0"},"requests":{"version":"==2.31.0"}}}`,
			want: []model.Package{
				{Name: "pytest", Version: "7.4.0", Ecosystem: "pypi", Dev: true},
				{Name: "requests", Version: "2.31.0", Ecosystem: "pypi"},
			},
			wantSkipped: []string{`"mylib" has no version`},
		},
		{
			name: "gradle lockfile",
			typ:  "gradle",
			content: `# This is a Gradle generated file for dependency locking.
org.springframework:spring-core:6.1.2=compileClasspath,runtimeClasspath
junit:junit:4.13.2=testCompileClasspath,TestRuntimeClasspath
org.mixed:lib:1.0=compileClasspath,testRuntimeClasspath
bad-line
empty=annotationProcessor,testAnnotationProcessor
`,
			want: []model.Package{
				{Name: "junit:junit", Version: "4.13.2", Ecosystem: "maven", Dev: true},
				{Name: "org.mixed:lib", Version: "1.0", Ecosystem: "maven"},
				{Name: "org.springframework:spring-core", Version: "6.1.2", Ecosystem: "maven"},
			},
			wantSkipped: []string{`"bad-line"`},
		},
		{
			name: "maven pom with namespace, properties and management",
			typ:  "maven",
			content: `<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <parent><groupId>com.acme</groupId><artifactId>parent</artifactId><version>3.0.0</version></parent>
  <artifactId>app</artifactId>
  <properties><jackson.version>2.15.2</jackson.version><alias>${jackson.version}</alias></properties>
  <dependencyManagement><dependencies>
    <dependency><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId><version>2.0.9</version></dependency>
  </dependencies></dependencyManagement>
  <dependencies>
    <dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId><version>${jackson.version}</version></dependency>
    <dependency><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId></dependency>
    <dependency><groupId>${project.groupId}</groupId><artifactId>sibling</artifactId><version>${project.version}</version></dependency>
    <dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.13.2</version><scope>test</scope></dependency>
    <dependency><groupId>com.example</groupId><artifactId>ranged</artifactId><version>[1.0,2.0)</version></dependency>
    <dependency><groupId>com.example</groupId><artifactId>unres</artifactId><version>${nope.version}</version></dependency>
    <dependency><groupId>com.example</groupId><artifactId>alias</artifactId><version>${alias}</version></dependency>
    <dependency><groupId>com.example</groupId><artifactId>exact</artifactId><version>[1.5]</version></dependency>
    <dependency><groupId>com.example</groupId><artifactId>noversion</artifactId></dependency>
  </dependencies>
</project>`,
			want: []model.Package{
				{Name: "com.acme:sibling", Version: "3.0.0", Ecosystem: "maven"},
				{Name: "com.example:alias", Version: "2.15.2", Ecosystem: "maven"},
				{Name: "com.example:exact", Version: "1.5", Ecosystem: "maven"},
				{Name: "com.fasterxml.jackson.core:jackson-databind", Version: "2.15.2", Ecosystem: "maven"},
				{Name: "junit:junit", Version: "4.13.2", Ecosystem: "maven", Dev: true},
				{Name: "org.slf4j:slf4j-api", Version: "2.0.9", Ecosystem: "maven"},
			},
			wantSkipped: []string{"com.example:ranged has a version range", "com.example:unres has an unresolved version", "com.example:noversion has no version"},
		},
		{
			name: "cyclonedx purls, nesting, scope",
			typ:  "cyclonedx",
			content: `{"bomFormat":"CycloneDX","components":[
 {"name":"x","purl":"pkg:npm/%40Scope/Name@1.2.3","scope":"required"},
 {"name":"g","purl":"pkg:golang/github.com/x/y@v1.0.0?type=module#sub"},
 {"name":"m","purl":"pkg:maven/org.apache/commons@1.0","scope":"excluded","components":[{"name":"nested","purl":"pkg:pypi/Django_Rest@1.0"}]},
 {"name":"c","purl":"pkg:composer/vendor/name@v1.0"},
 {"name":"deb","purl":"pkg:deb/debian/curl@7.0"},
 {"name":"nover","purl":"pkg:npm/nover"},
 {"name":"nopurl"}
]}`,
			want: []model.Package{
				{Name: "@scope/name", Version: "1.2.3", Ecosystem: "npm"},
				{Name: "django-rest", Version: "1.0", Ecosystem: "pypi"},
				{Name: "github.com/x/y", Version: "v1.0.0", Ecosystem: "go"},
				{Name: "org.apache:commons", Version: "1.0", Ecosystem: "maven", Dev: true},
				{Name: "vendor/name", Version: "1.0", Ecosystem: "composer"},
			},
			wantSkipped: []string{"unsupported package type", "has no version", `component "nopurl" has no purl`},
		},
		{
			name: "spdx purl external refs",
			typ:  "spdx",
			content: `{"spdxVersion":"SPDX-2.3","packages":[
 {"name":"a","externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":"pkg:npm/%40scope/a@2.0.0"}]},
 {"name":"b","externalRefs":[{"referenceType":"cpe23Type","referenceLocator":"cpe:2.3:a:x:b:1:*:*:*:*:*:*:*"},{"referenceType":"purl","referenceLocator":"pkg:maven/g/b@1.0"}]},
 {"name":"root"},
 {"name":"d","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:rpm/fedora/d@1.0"}]}
]}`,
			want: []model.Package{
				{Name: "@scope/a", Version: "2.0.0", Ecosystem: "npm"},
				{Name: "g:b", Version: "1.0", Ecosystem: "maven"},
			},
			wantSkipped: []string{`package "root" has no purl`, "unsupported package type"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := LoadResult(model.Lockfile{Type: tt.typ, Path: writeLock(t, tt.content)})
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(res.Packages, tt.want) {
				t.Errorf("packages:\n got %+v\nwant %+v", res.Packages, tt.want)
			}
			if len(res.Skipped) != len(tt.wantSkipped) {
				t.Fatalf("skipped = %q, want %d entries containing %q", res.Skipped, len(tt.wantSkipped), tt.wantSkipped)
			}
			for i, w := range tt.wantSkipped {
				if !strings.Contains(res.Skipped[i], w) {
					t.Errorf("skipped[%d] = %q, want containing %q", i, res.Skipped[i], w)
				}
			}
		})
	}
}

func TestSkippedCap(t *testing.T) {
	var b strings.Builder
	for i := range 60 {
		fmt.Fprintf(&b, "pkg%d>=1\n", i)
	}
	res, err := LoadResult(model.Lockfile{Type: "pip", Path: writeLock(t, b.String())})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Skipped) != 51 || res.Skipped[50] != "... and 10 more" {
		t.Errorf("got %d skipped, last %q", len(res.Skipped), res.Skipped[len(res.Skipped)-1])
	}
}

func TestLoadMatchesLoadResult(t *testing.T) {
	l := model.Lockfile{Type: "pip", Path: writeLock(t, "b==2\na==1\nb==2\nc>1\n")}
	got, err := Load(l)
	if err != nil {
		t.Fatal(err)
	}
	want := []model.Package{{Name: "a", Version: "1", Ecosystem: "pypi"}, {Name: "b", Version: "2", Ecosystem: "pypi"}}
	if !slices.Equal(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestTypes(t *testing.T) {
	want := []string{"composer", "cyclonedx", "go", "gradle", "maven", "npm", "pip", "pipfile", "poetry", "spdx"}
	if got := Types(); !slices.Equal(got, want) {
		t.Errorf("Types() = %v, want %v", got, want)
	}
}

func TestLoadSizeCap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "big.json")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxLockfile + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	_, err = Load(model.Lockfile{Type: "npm", Path: path})
	if err == nil || !strings.Contains(err.Error(), "larger than 64 MiB") {
		t.Fatalf("error = %v", err)
	}
}

func TestLoadErrorsNamePath(t *testing.T) {
	path := writeLock(t, "{not json")
	if _, err := Load(model.Lockfile{Type: "composer", Path: path}); err == nil || !strings.Contains(err.Error(), path) {
		t.Errorf("parse error = %v, want it to name %s", err, path)
	}
	missing := filepath.Join(t.TempDir(), "nope")
	if _, err := Load(model.Lockfile{Type: "go", Path: missing}); err == nil || !strings.Contains(err.Error(), missing) {
		t.Errorf("read error = %v, want it to name %s", err, missing)
	}
}

func TestDetectTypeCoversEveryReader(t *testing.T) {
	for name, want := range map[string]string{"composer.lock": "composer", "Package-Lock.JSON": "npm", "app.cdx.json": "cyclonedx",
		"release.spdx.json": "spdx", "go.mod": "go", "pom.xml": "maven", "README.md": ""} {
		got, ok := DetectType(name)
		if got != want || ok != (want != "") {
			t.Errorf("DetectType(%q) = %q %v, want %q", name, got, ok, want)
		}
	}
	for _, typ := range FileNames() {
		if got, _ := DetectType(typ); !slices.Contains(Types(), got) {
			t.Errorf("%s maps to %q, which has no parser", typ, got)
		}
	}
}
