package host

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "x.lock")
	unlock, err := Lock(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Lock(path); !errors.Is(err, ErrLocked) {
		t.Fatalf("second Lock = %v, want ErrLocked", err)
	}
	if err := unlock(); err != nil {
		t.Fatal(err)
	}
	unlock, err = Lock(path)
	if err != nil {
		t.Fatalf("Lock after unlock: %v", err)
	}
	unlock()
}

func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a", "f.json")
	for _, content := range []string{"one", "two, longer"} {
		if err := WriteFileAtomic(path, []byte(content)); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(path)
		if err != nil || string(got) != content {
			t.Fatalf("read = %q, %v; want %q", got, err, content)
		}
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatalf("want only the target file, got %v", entries)
	}
	if Private() {
		fi, _ := os.Stat(path)
		if m := fi.Mode().Perm(); m != 0o600 {
			t.Errorf("file mode = %o, want 600", m)
		}
		di, _ := os.Stat(filepath.Dir(path))
		if m := di.Mode().Perm(); m != 0o700 {
			t.Errorf("dir mode = %o, want 700", m)
		}
	}
}

func TestWriteFileAtomicFailureLeavesNoTemp(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "t")
	if err := os.Mkdir(target, 0o700); err != nil { // renaming a file over a non-empty directory fails
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "keep"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(target, []byte("x")); err == nil {
		t.Fatal("want error")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("temp file left behind: %v", entries)
	}
}

func TestOpenAppend(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d", "log")
	for _, s := range []string{"a\n", "b\n"} {
		f, err := OpenAppend(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString(s); err != nil {
			t.Fatal(err)
		}
		f.Close()
	}
	got, _ := os.ReadFile(path)
	if string(got) != "a\nb\n" {
		t.Fatalf("got %q", got)
	}
	if Private() {
		if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
			t.Errorf("mode = %o, want 600", fi.Mode().Perm())
		}
	}
}

func TestCurrentUser(t *testing.T) {
	u := CurrentUser()
	if u == "" || strings.Contains(u, `\`) {
		t.Fatalf("CurrentUser = %q", u)
	}
}

func TestStopSignals(t *testing.T) {
	if len(StopSignals()) == 0 {
		t.Fatal("no stop signals")
	}
}
