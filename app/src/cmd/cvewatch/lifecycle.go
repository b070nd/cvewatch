package main

import (
	"errors"
	"flag"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/b070nd/cvewatch/app/src/ops"
)

// lifecycleVerb reports whether args are "VERB NAME ...". A project may itself
// be called delete or enable, so a verb needs a name after it.
func lifecycleVerb(args []string) (ops.LifecycleVerb, bool) {
	if len(args) < 2 || strings.HasPrefix(args[1], "-") {
		return "", false
	}
	v := ops.LifecycleVerb(args[0])
	return v, slices.Contains(ops.LifecycleVerbs, v)
}

// intermixed parses flags that may come before, between or after the
// positional arguments, which Go's flag package alone does not.
func intermixed(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return pos, nil
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

// lifecycleCmd shows what a rename, duplicate, delete, disable or enable would
// do and, with -yes, does it.
func lifecycleCmd(s *ops.Session, verb ops.LifecycleVerb, args []string) error {
	fs := flag.NewFlagSet("project "+string(verb), flag.ContinueOnError)
	yes := fs.Bool("yes", false, "apply the change; without it only show the consequences")
	closeFindings := fs.Bool("close-findings", false, "delete only: mark the project's open findings ignored")
	asJSON := fs.Bool("json", false, "print JSON")
	pos, err := intermixed(fs, args)
	if err != nil {
		return err
	}
	needsNew := verb == ops.VerbRename || verb == ops.VerbDuplicate
	switch {
	case needsNew && len(pos) != 2:
		return fmt.Errorf("usage: cvewatch project %s NAME NEW_NAME [-yes]", verb)
	case !needsNew && len(pos) != 1:
		return fmt.Errorf("usage: cvewatch project %s NAME [-yes]", verb)
	}
	req := ops.LifecycleRequest{Verb: verb, Project: pos[0], CloseFindings: *closeFindings, Apply: *yes, Confirm: *yes}
	if needsNew {
		req.NewName = pos[1]
	}
	p, err := s.ProjectLifecycle(req)
	if err != nil {
		if !*asJSON && !errors.Is(err, ops.ErrConfirm) {
			printLifecycle(s.Cfg.Root, p) // what was planned helps to see why it failed
		}
		return err
	}
	if *asJSON {
		return printJSON(p)
	}
	printLifecycle(s.Cfg.Root, p)
	switch {
	case p.Applied:
		fmt.Printf("done: %s\n", describe(p))
		if p.Backup != "" {
			fmt.Println("old file kept in", relTo(s.Cfg.Root, p.Backup))
		}
	case p.RequiresConfirm:
		fmt.Println("not applied: this is destructive; add -yes to confirm")
	default:
		fmt.Println("not applied: add -yes to apply this change")
	}
	return nil
}

func describe(p ops.LifecyclePreview) string {
	if p.NewName != "" {
		return fmt.Sprintf("%s %s -> %s", p.Verb, p.Project, p.NewName)
	}
	return fmt.Sprintf("%s %s", p.Verb, p.Project)
}

func printLifecycle(root string, p ops.LifecyclePreview) {
	if p.Verb == "" {
		return // the request never got as far as a plan
	}
	fmt.Println(describe(p))
	f := p.Findings
	line := fmt.Sprintf("%d", f.Total)
	var parts []string
	for _, st := range slices.Sorted(maps.Keys(f.ByStatus)) {
		parts = append(parts, fmt.Sprintf("%s %d", st, f.ByStatus[st]))
	}
	if len(parts) > 0 {
		line += " (" + strings.Join(parts, ", ") + ")"
	}
	fmt.Println("  findings:", line)
	for _, a := range p.Access {
		left := "no project left"
		if len(a.Left) > 0 {
			left = "keeps " + strings.Join(a.Left, ", ")
		}
		fmt.Printf("  access:   %s: %s (%s)\n", a.Actor, a.Action, left)
	}
	for _, c := range p.Files {
		from, to := relTo(root, c.From), relTo(root, c.To)
		switch {
		case c.From == "":
			fmt.Printf("  file:     %s %s\n", c.Action, to)
		case c.To == "":
			fmt.Printf("  file:     %s %s\n", c.Action, from)
		default:
			fmt.Printf("  file:     %s %s -> %s\n", c.Action, from, to)
		}
	}
	for _, w := range p.Warnings {
		fmt.Println("  note:", w)
	}
}
