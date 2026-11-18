package inventory

import (
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"slices"

	"github.com/b070nd/cvewatch/app/src/config"
)

// FilesStamp names the state of the files the judgement depends on: the
// settings, the technologies, the project files and their lockfiles. It only
// looks at sizes and times, so it is cheap on every re-read.
func FilesStamp(cfg *config.Bundle) string {
	paths := []string{config.SettingsPath(cfg.Root), config.TechsPath(cfg.Root)}
	dir := config.ProjectsDir(cfg.Root)
	if ents, err := os.ReadDir(dir); err == nil {
		for _, e := range ents {
			if !e.IsDir() {
				paths = append(paths, filepath.Join(dir, e.Name()))
			}
		}
	}
	for _, p := range cfg.Projects {
		for _, l := range p.Lockfiles {
			paths = append(paths, l.Path)
		}
	}
	slices.Sort(paths)
	paths = slices.Compact(paths)
	h := fnv.New64a()
	for _, p := range paths {
		fmt.Fprintf(h, "%s|", p)
		if fi, err := os.Stat(p); err == nil {
			fmt.Fprintf(h, "%d|%d", fi.Size(), fi.ModTime().UnixNano())
		}
		fmt.Fprint(h, "\n")
	}
	return hex.EncodeToString(h.Sum(nil))
}
