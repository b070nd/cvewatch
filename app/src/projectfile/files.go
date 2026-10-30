package projectfile

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/b070nd/cvewatch/app/src/host"
)

// Write saves data to path atomically. If path already holds different
// content, the old content is first copied to
// backupDir/<name>-<20060102-150405>.yaml.
func Write(path string, data []byte, backupDir string, now time.Time) error {
	old, err := os.ReadFile(path)
	switch {
	case err == nil && bytes.Equal(old, data):
		return nil
	case err == nil:
		if _, err := backup(path, old, backupDir, now); err != nil {
			return err
		}
	case !errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("projectfile: %w", err)
	}
	if err := host.WriteFileAtomic(path, data); err != nil {
		return fmt.Errorf("projectfile: %w", err)
	}
	return nil
}

func backup(path string, old []byte, dir string, now time.Time) (string, error) {
	if err := host.MkdirPrivate(dir); err != nil {
		return "", fmt.Errorf("projectfile: %w", err)
	}
	target := BackupTarget(path, dir, now)
	if err := host.WriteFileAtomic(target, old); err != nil {
		return "", fmt.Errorf("projectfile: backup: %w", err)
	}
	return target, nil
}

// BackupTarget is where a backup of the file at path goes: backupDir/<name>-<timestamp>.yaml,
// with a counter when that name is taken.
func BackupTarget(path, dir string, now time.Time) string {
	base := strings.TrimSuffix(strings.TrimSuffix(filepath.Base(path), disabledExt), ".yaml")
	stamp := now.Format("20060102-150405")
	target := filepath.Join(dir, base+"-"+stamp+".yaml")
	for n := 2; ; n++ { // two saves in one second must not overwrite each other's backup
		if _, err := os.Stat(target); err != nil { // free, or the folder is not usable and the write will say so
			return target
		}
		target = filepath.Join(dir, fmt.Sprintf("%s-%s-%d.yaml", base, stamp, n))
	}
}

// Archive moves the file at path into backupDir instead of unlinking it, and
// returns where it went. The copy is written before the original is removed.
func Archive(path, backupDir string, now time.Time) (string, error) {
	old, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("projectfile: %w", err)
	}
	target, err := backup(path, old, backupDir, now)
	if err != nil {
		return "", err
	}
	if err := os.Remove(path); err != nil {
		return target, fmt.Errorf("projectfile: %w", err)
	}
	return target, nil
}

// disabledExt marks a project file the loader skips.
const disabledExt = ".disabled"

// DisabledPath returns dir/<name>.yaml.disabled, where a disabled project's file lives.
func DisabledPath(dir, name string) (string, error) {
	p, err := Path(dir, name)
	return p + disabledExt, err
}

// ListDisabled returns the names of the disabled projects in dir, sorted.
func ListDisabled(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return []string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("projectfile: %w", err)
	}
	names := []string{}
	for _, e := range entries {
		if n := e.Name(); !e.IsDir() && !strings.HasPrefix(n, ".") && strings.HasSuffix(n, ".yaml"+disabledExt) {
			names = append(names, strings.TrimSuffix(n, ".yaml"+disabledExt))
		}
	}
	slices.Sort(names)
	return names, nil
}

// Path returns dir/<name>.yaml. The name is checked like New's, which rules
// out path separators.
func Path(dir, name string) (string, error) {
	if err := checkName(name); err != nil {
		return "", err
	}
	return filepath.Join(dir, name+".yaml"), nil
}

// List returns the project names (file names without .yaml) in dir, sorted.
// A missing dir is empty; directories, dot files and other file types are skipped.
func List(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return []string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("projectfile: %w", err)
	}
	names := []string{}
	for _, e := range entries {
		n := e.Name()
		if !e.IsDir() && !strings.HasPrefix(n, ".") && strings.HasSuffix(n, ".yaml") {
			names = append(names, strings.TrimSuffix(n, ".yaml"))
		}
	}
	slices.Sort(names)
	return names, nil
}
