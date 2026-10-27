// Package host isolates what differs between Linux, macOS and Windows:
// file locking, private file modes, atomic replace, user name and stop signals.
package host

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// ErrLocked is returned by Lock when another process holds the lock.
var ErrLocked = errors.New("locked by another process")

// Lock takes a non-blocking exclusive advisory lock on the lock file at path,
// creating it (and its parent directory) owner-only if needed. It returns
// ErrLocked (test with errors.Is) if another process holds it. unlock releases
// the lock and closes the file; the OS also releases it if the process dies.
// Unix uses flock(LOCK_EX|LOCK_NB); Windows uses LockFileEx with
// exclusive|fail-immediately.
func Lock(path string) (unlock func() error, err error) {
	if err := MkdirPrivate(filepath.Dir(path)); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := lockFile(f); err != nil {
		f.Close()
		if errors.Is(err, errWouldBlock) {
			return nil, fmt.Errorf("%s: %w", path, ErrLocked)
		}
		return nil, err
	}
	return func() error {
		err := unlockFile(f)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		return err
	}, nil
}

// WriteFileAtomic replaces path with data so readers never see a partial file.
// It writes and fsyncs a temp file in the same directory, sets it private, and
// renames it over the target; the parent directory is created private. On
// failure no temp file is left behind. On Windows the rename is retried for
// about 100ms, since an antivirus scanner or reader may briefly hold the target.
func WriteFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := MkdirPrivate(dir); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return err
	}
	tries := 1
	if runtime.GOOS == "windows" {
		tries = 6
	}
	for i := 1; ; i++ {
		if err = os.Rename(tmp.Name(), path); err == nil || i >= tries {
			return err
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// OpenAppend opens path for appending, creating it if needed. The parent
// directory is created private and a new file is owner-only (0600 on unix;
// see Private for Windows).
func OpenAppend(path string) (*os.File, error) {
	if err := MkdirPrivate(filepath.Dir(path)); err != nil {
		return nil, err
	}
	return os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
}

// MkdirPrivate creates dir and any parents, new directories being 0700 on unix.
// On Windows the mode is ignored and access follows the parent ACLs.
func MkdirPrivate(dir string) error { return os.MkdirAll(dir, 0o700) }

// CurrentUser returns the OS user name without any Windows DOMAIN\ prefix,
// or "unknown" if it cannot be determined.
func CurrentUser() string {
	if u, err := user.Current(); err == nil {
		if name := u.Username[strings.LastIndexByte(u.Username, '\\')+1:]; name != "" {
			return name
		}
	}
	return "unknown"
}
