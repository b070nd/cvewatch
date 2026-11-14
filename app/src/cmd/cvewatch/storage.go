package main

import (
	"errors"
	"flag"
	"fmt"

	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/ledger"
	"github.com/b070nd/cvewatch/app/src/store"
)

// storageCmd copies the state from the backend the configuration names into
// another one, so a switch of storage.backend keeps everything. It reads the
// source without a lock and never changes it.
func storageCmd(root string, args []string) error {
	if len(args) == 0 || args[0] != "copy" {
		return errors.New("usage: cvewatch storage copy -to file|sqlite|postgres [-force]")
	}
	fs := flag.NewFlagSet("storage copy", flag.ContinueOnError)
	to := fs.String("to", "", "the backend to copy to")
	force := fs.Bool("force", false, "replace what the target already holds")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	cfg, err := config.Load(root)
	if err != nil {
		return err
	}
	src, dst := cfg.Place(), cfg.Place()
	if dst.Backend = *to; !validBackend(dst.Backend) {
		return fmt.Errorf("-to must be one of %v", store.Backends())
	}
	if src.Backend == "" {
		src.Backend = "file"
	}
	if src == dst {
		return errors.New("the target is the backend already in use")
	}
	rd, err := store.OpenReader(src)
	if err != nil {
		return err
	}
	defer rd.Close()
	state, err := rd.Load()
	if err != nil {
		return err
	}
	out, err := store.Open(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	held, err := out.Load()
	if err != nil {
		return err
	}
	if !*force && (len(held.Vulns) > 0 || len(held.Findings) > 0 || held.Rev > 0) {
		return fmt.Errorf("the target already holds state (%d advisories, %d findings, rev %d); -force replaces it", len(held.Vulns), len(held.Findings), held.Rev)
	}
	if err := out.Save(state); err != nil {
		return err
	}
	back, err := out.Load()
	if err != nil {
		return err
	}
	if err := sameCounts(state, back); err != nil {
		return err
	}
	fmt.Printf("copied %d advisories, %d findings, %d feeds from %s to %s\n", len(back.Vulns), len(back.Findings), len(back.Feeds), src.Backend, dst.Backend)
	fmt.Printf("now set storage.backend: %s in config.yaml; the old state stays where it is until you delete it\n", dst.Backend)
	return nil
}

func validBackend(b string) bool {
	for _, k := range store.Backends() {
		if k == b {
			return true
		}
	}
	return false
}

// sameCounts is the check after a copy: what was read back is what was written.
func sameCounts(a, b ledger.State) error {
	if len(a.Vulns) != len(b.Vulns) || len(a.Findings) != len(b.Findings) || len(a.Feeds) != len(b.Feeds) || len(a.Cycles) != len(b.Cycles) {
		return fmt.Errorf("the copy does not match: %d/%d advisories, %d/%d findings", len(b.Vulns), len(a.Vulns), len(b.Findings), len(a.Findings))
	}
	return nil
}
