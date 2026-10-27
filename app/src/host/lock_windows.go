//go:build windows

package host

import (
	"os"

	"golang.org/x/sys/windows"
)

var errWouldBlock = windows.ERROR_LOCK_VIOLATION

// The lock covers the first byte of the file.
func lockFile(f *os.File) error {
	return windows.LockFileEx(windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, new(windows.Overlapped))
}

func unlockFile(f *os.File) error {
	return windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, new(windows.Overlapped))
}
