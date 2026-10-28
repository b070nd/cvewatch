package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/b070nd/cvewatch/app/src/discovery"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/ops"
	"github.com/b070nd/cvewatch/app/src/projectfile"
	"github.com/b070nd/cvewatch/app/src/status"
	"github.com/b070nd/cvewatch/app/src/wizard"
)

func statusCmd(s *ops.Session, args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rep, err := s.Status()
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(rep)
	}
	printStatus(rep)
	if rep.Level == status.Fail {
		return errors.New("status: something is failing") // a non-zero exit lets cron and CI notice
	}
	return nil
}

func printStatus(r status.Report) {
	fmt.Printf("Overall: %s\n\nDaemon:  %-8s %s\n", r.Level, r.Daemon.Level, r.Daemon.Message)
	fmt.Println("\nFeeds")
	for _, x := range r.Sources {
		fmt.Printf("  %-8s %-22s %s\n", x.Level, x.ID, detail(x.LastSuccess, x.Failures, x.LastError, x.Items))
	}
	fmt.Println("\nChannels")
	if len(r.Channels) == 0 {
		fmt.Println("  none active")
	}
	for _, x := range r.Channels {
		fmt.Printf("  %-8s %-22s %s\n", x.Level, x.Name, detail(x.LastSuccess, x.Failures, x.LastError, -1))
	}
	fmt.Println("\nRecent cycles")
	for i, c := range r.Cycles {
		if i == 5 {
			break
		}
		fmt.Printf("  %s  %d items, %d new, %d alerted, %d failed feeds\n", c.Started.Format("2006-01-02 15:04"), c.Items, c.New, c.Alerted, c.Failed)
	}
	for _, w := range r.Warnings {
		fmt.Println("warning:", w)
	}
}

func detail(last time.Time, failures int, lastErr string, items int) string {
	var parts []string
	if last.IsZero() {
		parts = append(parts, "never succeeded")
	} else {
		parts = append(parts, "ok "+last.Format("2006-01-02 15:04"))
	}
	if items >= 0 {
		parts = append(parts, fmt.Sprintf("%d items", items))
	}
	if failures > 0 {
		parts = append(parts, fmt.Sprintf("%d failed in a row: %s", failures, lastErr))
	}
	return strings.Join(parts, ", ")
}

func dashboardCmd(s *ops.Session, args []string) error {
	fs := flag.NewFlagSet("dashboard", flag.ContinueOnError)
	out := fs.String("out", "", "write here instead of the configured file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		path, err := s.WriteDashboard()
		if err != nil {
			return err
		}
		fmt.Println("dashboard written:", path)
		return nil
	}
	page, err := s.DashboardHTML()
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, []byte(page), 0o600); err != nil {
		return err
	}
	fmt.Println("dashboard written:", *out)
	return nil
}

func catalogCmd(s *ops.Session, args []string) error {
	fs := flag.NewFlagSet("catalog", flag.ContinueOnError)
	category := fs.String("category", "", "only this category")
	asJSON := fs.Bool("json", false, "print JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cat := s.Cfg.Catalog
	techs := cat.All()
	if q := strings.TrimSpace(strings.Join(fs.Args(), " ")); q != "" {
		techs = cat.Search(q)
	}
	var shown []model.Tech
	for _, t := range techs {
		if *category == "" || strings.EqualFold(t.Category, *category) {
			shown = append(shown, t)
		}
	}
	if *asJSON {
		out := []map[string]string{}
		for _, t := range shown {
			out = append(out, map[string]string{"name": t.Name, "title": t.Title, "category": t.Category, "vendor": t.Vendor, "source": t.Source})
		}
		return printJSON(out)
	}
	for _, t := range shown {
		fmt.Printf("%-18s %-14s %-7s %s\n", t.Name, t.Category, t.Source, t.Title)
	}
	fmt.Printf("%d of %d technologies. Categories: %s\n", len(shown), len(techs), strings.Join(cat.UsedCategories(), ", "))
	return nil
}

func discoverCmd(s *ops.Session, args []string) error {
	fs := flag.NewFlagSet("discover", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print JSON")
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return errors.New("usage: cvewatch discover DIR [-json]")
	}
	dir := args[0]
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	res, err := discovery.Scan(dir, s.Cfg.Catalog, discovery.Options{})
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(res)
	}
	printDiscovery(res)
	return nil
}

func printDiscovery(res discovery.Result) {
	fmt.Println("Looked at", res.Root)
	for _, t := range res.Techs {
		v := t.Version
		if v == "" {
			v = "version unknown"
		}
		fmt.Printf("  %-7s %-16s %s\n", t.Confidence, t.Tech, v)
		for _, e := range t.Evidence {
			fmt.Printf("            %s: %s\n", e.File, e.Detail)
		}
	}
	for _, l := range res.Lockfiles {
		fmt.Printf("  lockfile %-9s %s (%d packages)\n", l.Type, l.Path, l.Packages)
	}
	for _, n := range res.Notes {
		fmt.Println("  note:", n)
	}
	if len(res.Techs) == 0 && len(res.Lockfiles) == 0 {
		fmt.Println("  nothing recognised")
	}
}

// listFlag collects a repeated flag.
type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

// projectCmd lists projects or edits one without opening an editor. Without
// -save it only shows the diff.
func projectCmd(s *ops.Session, args []string) error {
	if len(args) == 0 || args[0] == "list" {
		names, err := s.ProjectNames()
		if err != nil {
			return err
		}
		for _, p := range s.Cfg.Projects {
			if !contains(names, p.Name) {
				continue
			}
			var techs []string
			for _, t := range p.Techs {
				techs = append(techs, strings.TrimSpace(t.Name+" "+t.Version))
			}
			fmt.Printf("%-18s %d lockfiles  %s\n", p.Name, len(p.Lockfiles), strings.Join(techs, ", "))
		}
		return nil
	}
	fs := flag.NewFlagSet("project", flag.ContinueOnError)
	var set, remove, lock, unlock listFlag
	fs.Var(&set, "set", "declare tech=version (version may be empty), repeatable")
	fs.Var(&remove, "remove", "stop declaring a tech, repeatable")
	fs.Var(&lock, "lock", "add a lockfile as type:path, repeatable")
	fs.Var(&unlock, "unlock", "remove a lockfile as type:path, repeatable")
	envs := fs.String("envs", "", "comma-separated environments (empty argument value \"all\" means every one)")
	save := fs.Bool("save", false, "write the change; without it only show the diff")
	name, err := idAndFlags(fs, args)
	if err != nil {
		return err
	}
	var changes []projectfile.Op
	for _, v := range set {
		t, ver, _ := strings.Cut(v, "=")
		changes = append(changes, projectfile.Op{Kind: "set_tech", Tech: t, Version: ver})
	}
	for _, t := range remove {
		changes = append(changes, projectfile.Op{Kind: "remove_tech", Tech: t})
	}
	for _, v := range lock {
		l, err := parseLock(v)
		if err != nil {
			return err
		}
		changes = append(changes, projectfile.Op{Kind: "add_lockfile", Lockfile: l})
	}
	for _, v := range unlock {
		l, err := parseLock(v)
		if err != nil {
			return err
		}
		changes = append(changes, projectfile.Op{Kind: "remove_lockfile", Lockfile: l})
	}
	if *envs != "" {
		op := projectfile.Op{Kind: "set_envs"}
		if *envs != "all" {
			for _, e := range strings.Split(*envs, ",") {
				op.Envs = append(op.Envs, model.Env(strings.TrimSpace(e)))
			}
		}
		changes = append(changes, op)
	}
	if len(changes) == 0 {
		return errors.New("nothing to change: use -set, -remove, -lock, -unlock or -envs")
	}
	return showProject(s, ops.ProjectChange{Project: name, Ops: changes, Save: *save})
}

func showProject(s *ops.Session, c ops.ProjectChange) error {
	p, err := s.EditProject(c)
	fmt.Print(p.Diff)
	for _, i := range p.Issues {
		fmt.Printf("%s: %s: %s\n", i.Level, i.Field, i.Message)
	}
	switch {
	case err != nil:
		return err
	case p.Saved:
		fmt.Println("saved", relTo(s.Cfg.Root, p.Path))
	case p.Diff == "":
		fmt.Println("no change")
	default:
		fmt.Println("not saved: add -save to write this change")
	}
	return nil
}

func parseLock(v string) (model.Lockfile, error) {
	typ, path, ok := strings.Cut(v, ":")
	if !ok || typ == "" || path == "" {
		return model.Lockfile{}, fmt.Errorf("%q must look like type:path, for example composer:../shop/composer.lock", v)
	}
	return model.Lockfile{Type: typ, Path: path}, nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func relTo(root, path string) string {
	if r, err := filepath.Rel(root, path); err == nil {
		return r
	}
	return path
}

// setupCmd runs the prompt wizard: with a folder it proposes a project from
// it, with -project it edits that project, and with neither it shows a menu.
func setupCmd(s *ops.Session, args []string) error {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	project := fs.String("project", "", "edit this existing project")
	dir := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		dir, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	io := wizard.IO{In: os.Stdin, Out: os.Stdout}
	if dir == "" && *project == "" {
		return wizard.Menu(io, s)
	}
	return wizard.Setup(io, s, dir, *project)
}

// tuiCmd starts the cvewatch-tui program that sits next to this executable
// or on the PATH. It is a separate program so the terminal library it needs
// is not linked into, and does not slow down, every other command.
func tuiCmd(ctx context.Context, root string, args []string) error {
	path, name := "", "cvewatch-tui"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	if self, err := os.Executable(); err == nil {
		if p := filepath.Join(filepath.Dir(self), name); fileExists(p) {
			path = p
		}
	}
	if path == "" {
		p, err := exec.LookPath(name)
		if err != nil {
			return errors.New("cvewatch-tui not found: it ships next to cvewatch in the release archives, or build it with `go build ./src/cmd/cvewatch-tui`")
		}
		path = p
	}
	cmd := exec.CommandContext(ctx, path, append([]string{"-root", root}, args...)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}
