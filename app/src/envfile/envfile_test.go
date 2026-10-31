package envfile

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func write(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func unset(t *testing.T, names ...string) {
	t.Helper()
	for _, n := range names {
		old, had := os.LookupEnv(n)
		os.Unsetenv(n)
		t.Cleanup(func() {
			if had {
				os.Setenv(n, old)
			} else {
				os.Unsetenv(n)
			}
		})
	}
}

func TestSyntax(t *testing.T) {
	unset(t, "EF_PLAIN", "EF_EXPORTED", "EF_SINGLE", "EF_DOUBLE", "EF_COMMENT", "EF_EMPTY", "EF_HASH", "EF_CRLF")
	dir := t.TempDir()
	body := "\ufeff# a comment\n\nEF_PLAIN=abc\nexport EF_EXPORTED = spaced value  \nEF_SINGLE='no $expansion \\n here'\n" +
		"EF_DOUBLE=\"line\\nbreak \\\"q\\\" \\$HOME\"  # trailing\nEF_COMMENT=value # a comment\nEF_EMPTY=\nEF_HASH=a#b\nEF_CRLF=x\r\n"
	p := write(t, dir, "x.env", body)
	if _, err := Apply([]string{p}); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"EF_PLAIN": "abc", "EF_EXPORTED": "spaced value", "EF_SINGLE": `no $expansion \n here`,
		"EF_DOUBLE": "line\nbreak \"q\" $HOME", "EF_COMMENT": "value", "EF_EMPTY": "", "EF_HASH": "a#b", "EF_CRLF": "x",
	}
	for k, v := range want {
		if got, ok := os.LookupEnv(k); !ok || got != v {
			t.Errorf("%s = %q, %v; want %q", k, got, ok, v)
		}
	}
}

func TestLaterFileWinsAndTheRealEnvironmentWinsOverAll(t *testing.T) {
	unset(t, "EF_A", "EF_B")
	t.Setenv("EF_REAL", "from the shell")
	dir := t.TempDir()
	one := write(t, dir, "one.env", "EF_A=one\nEF_B=one\nEF_REAL=file\n")
	two := write(t, dir, "two.env", "EF_B=two\n")
	res, err := Apply([]string{one, two})
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("EF_A") != "one" || os.Getenv("EF_B") != "two" || os.Getenv("EF_REAL") != "from the shell" {
		t.Fatalf("A=%q B=%q REAL=%q", os.Getenv("EF_A"), os.Getenv("EF_B"), os.Getenv("EF_REAL"))
	}
	if strings.Join(res.Set, ",") != "EF_A,EF_B" || len(res.Files) != 2 {
		t.Fatalf("result = %+v", res)
	}
}

func TestDefaultsAreReadFromEachFolderAndANamedFileReplacesThem(t *testing.T) {
	unset(t, "EF_ONE", "EF_TWO", "EF_NAMED")
	wd, root := t.TempDir(), t.TempDir()
	write(t, wd, ".env", "EF_ONE=wd\n")
	write(t, wd, ".env.local", "EF_ONE=local\nEF_TWO=wd-local\n")
	write(t, root, ".env", "EF_TWO=root\n")
	res, err := Apply(nil, wd, root, wd)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Files) != 3 {
		t.Fatalf("files = %v", res.Files)
	}
	if os.Getenv("EF_ONE") != "local" || os.Getenv("EF_TWO") != "root" {
		t.Fatalf("ONE=%q TWO=%q", os.Getenv("EF_ONE"), os.Getenv("EF_TWO"))
	}

	unset(t, "EF_ONE", "EF_TWO")
	named := write(t, t.TempDir(), "custom.env", "EF_NAMED=1\n")
	if res, err = Apply([]string{named}, wd, root); err != nil || len(res.Files) != 1 {
		t.Fatalf("named: %+v %v", res, err)
	}
	if _, ok := os.LookupEnv("EF_ONE"); ok {
		t.Error("a named file replaces the defaults")
	}
}

func TestNoDefaultsIsNotAnError(t *testing.T) {
	res, err := Apply(nil, t.TempDir())
	if err != nil || len(res.Files) != 0 {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestANamedFileThatIsMissingIsAnError(t *testing.T) {
	if _, err := Apply([]string{filepath.Join(t.TempDir(), "nope.env")}); err == nil {
		t.Fatal("expected an error")
	}
}

func TestErrorsNameTheLineNeverTheValue(t *testing.T) {
	dir := t.TempDir()
	for body, line := range map[string]string{
		"EF_OK=1\nnot a pair secret-token\n": "line 2",
		"EF_X=\"unterminated secret-token\n": "line 1",
		"1BAD=secret-token\n":                "line 1",
		"EF_Y='a' secret-token\n":            "line 1",
	} {
		p := write(t, dir, "bad.env", body)
		_, err := Apply([]string{p})
		if err == nil || !strings.Contains(err.Error(), line) || strings.Contains(err.Error(), "secret-token") {
			t.Errorf("%q: %v", body, err)
		}
	}
}

func TestLooseFilesAreReported(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits do not apply")
	}
	unset(t, "EF_L")
	p := write(t, t.TempDir(), "l.env", "EF_L=1\n")
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Apply([]string{p})
	if err != nil || len(res.Loose) != 1 {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestFilesFlag(t *testing.T) {
	var f Files
	if err := f.Set("a"); err != nil || f.Set("b") != nil || f.Set("") == nil || f.String() != "a,b" {
		t.Fatalf("%v", f)
	}
}
