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

	"github.com/b070nd/cvewatch/app/src/catalog"
	"github.com/b070nd/cvewatch/app/src/discovery"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/ops"
	"github.com/b070nd/cvewatch/app/src/projectfile"
	"github.com/b070nd/cvewatch/app/src/projectflow"
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
	q := strings.TrimSpace(strings.Join(fs.Args(), " "))
	if q != "" {
		techs = cat.Search(q)
		if len(techs) == 0 && !*asJSON {
			fmt.Printf("%q is not in the catalog.", q)
			if close := cat.Suggest(q, 5); len(close) > 0 {
				var names []string
				for _, t := range close {
					names = append(names, t.Name)
				}
				fmt.Printf(" Did you mean: %s?", strings.Join(names, ", "))
			}
			fmt.Printf(" To match it anyway, add it as your own keyword: cvewatch tech add %s\n", catalog.Slug(q))
			return nil
		}
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
	all := fs.Bool("all", false, "also look at paths .gitignore ignores")
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return errors.New("usage: cvewatch discover DIR|FILE [-json] [-all] (FILE is a Dockerfile, compose file or Kubernetes manifest; paths .gitignore ignores are left out unless -all)")
	}
	typed := args[0]
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	src, err := projectflow.ResolveSource(typed)
	if err != nil {
		return err
	}
	res, err := projectflow.ScanSourceWith(src, s.Cfg.Catalog, discovery.Options{IncludeIgnored: *all})
	if errors.Is(err, discovery.ErrIgnored) {
		return fmt.Errorf("%w (use -all to read it anyway)", err)
	}
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
	looked := res.Root
	if res.File != "" {
		looked = res.File
	}
	fmt.Println("Looked at", looked)
	for _, t := range res.Techs {
		v := t.Version
		if v == "" {
			v = "version unknown"
		}
		if res.File != "" && t.Infra && t.Category != "" {
			v += " (" + t.Category + ")" // a file scan is mostly infrastructure: say what kind
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
		return listProjects(s)
	}
	e, err := parseProjectEdit(args)
	if err != nil {
		return err
	}
	return showProject(s, ops.ProjectChange{Project: e.name, Ops: e.ops, Save: e.save})
}

func listProjects(s *ops.Session) error {
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
	off, err := s.DisabledProjects()
	if err != nil {
		return err
	}
	for _, n := range off {
		fmt.Printf("%-18s disabled\n", n)
	}
	return nil
}

// optFlag is a string flag that knows whether it was given, so -since "" can clear.
type optFlag struct {
	val string
	set bool
}

func (o *optFlag) String() string     { return o.val }
func (o *optFlag) Set(v string) error { o.val, o.set = v, true; return nil }

type projectEdit struct {
	name string
	ops  []projectfile.Op
	save bool
}

// parseProjectEdit turns "NAME -flag ..." into ops. The flags are the ones
// projectfile.OpTable lists; its parity test runs every row through here.
func parseProjectEdit(args []string) (projectEdit, error) {
	fs := flag.NewFlagSet("project", flag.ContinueOnError)
	var set, remove, lock, unlock, lockDev, lockNoDev, envSet, envUnset, envAdd, envRemove, envRename, envExclude, envInclude, techEnvs, image listFlag
	var since optFlag
	fs.Var(&set, "set", "declare tech=version (version may be empty), repeatable")
	fs.Var(&remove, "remove", "stop declaring a tech, repeatable")
	fs.Var(&lock, "lock", "add a lockfile as type:path[:env][:dev], repeatable")
	fs.Var(&unlock, "unlock", "remove a lockfile as type:path[:env], repeatable")
	fs.Var(&lockDev, "lock-dev", "count a lockfile's dev-only packages everywhere: type:path[:env], repeatable")
	fs.Var(&lockNoDev, "lock-nodev", "stop counting a lockfile's dev-only packages outside dev-like environments: type:path[:env], repeatable")
	fs.Var(&envSet, "env-set", "set the version deployed in one environment as env:tech=version, repeatable")
	fs.Var(&envUnset, "env-unset", "drop a per-environment version as env:tech, repeatable")
	fs.Var(&envAdd, "env-add", "add an environment to the project (any lowercase name), repeatable")
	fs.Var(&envRemove, "env-remove", "remove an environment from the project's list, repeatable")
	fs.Var(&envRename, "env-rename", "rename an environment as old=new, also in its versions and lockfiles, repeatable")
	fs.Var(&envExclude, "env-exclude", "a generic tech does not run in one environment as env:tech, repeatable")
	fs.Var(&envInclude, "env-include", "undo -env-exclude as env:tech, repeatable")
	fs.Var(&techEnvs, "tech-envs", "limit a generic tech to some environments as tech=env,env (tech= lifts the limit), repeatable")
	fs.Var(&image, "image", "set the image of an environment as env=tag (empty tag clears), repeatable")
	fs.Var(&since, "since", "date advisories count from, YYYY-MM-DD (empty clears)")
	envs := fs.String("envs", "", "comma-separated environments, any names (\"all\" means the old default dev,int,staging,prod)")
	migrate := fs.Bool("migrate-envs", false, "rewrite the old environments: map as when@ENV blocks (same meaning)")
	save := fs.Bool("save", false, "write the change; without it only show the diff")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "usage: cvewatch project NAME [flags]\n\nEdit flags (diff only without -save):\n%s\nOther: -save writes the change.\n", projectfile.FlagHelp("  "))
	}
	name, err := idAndFlags(fs, args)
	if err != nil {
		return projectEdit{}, err
	}
	var changes []projectfile.Op
	for _, v := range set {
		t, ver, _ := strings.Cut(v, "=")
		changes = append(changes, projectfile.Op{Kind: "set_tech", Tech: t, Version: ver})
	}
	for _, t := range remove {
		changes = append(changes, projectfile.Op{Kind: "remove_tech", Tech: t})
	}
	lockOps := func(list listFlag, kind string, dev *bool) error {
		for _, v := range list {
			l, err := parseLock(v)
			if err != nil {
				return err
			}
			if dev != nil {
				l.Dev = *dev
			}
			changes = append(changes, projectfile.Op{Kind: kind, Lockfile: l})
		}
		return nil
	}
	yes, no := true, false
	for _, err := range []error{lockOps(lock, "add_lockfile", nil), lockOps(unlock, "remove_lockfile", nil)} {
		if err != nil {
			return projectEdit{}, err
		}
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
	for _, err := range []error{lockOps(lockDev, "set_lockfile_dev", &yes), lockOps(lockNoDev, "set_lockfile_dev", &no)} {
		if err != nil {
			return projectEdit{}, err
		}
	}
	if since.set {
		changes = append(changes, projectfile.Op{Kind: "set_since", Since: since.val})
	}
	for _, v := range envSet {
		env, rest, ok := strings.Cut(v, ":")
		tech, ver, ok2 := strings.Cut(rest, "=")
		if !ok || !ok2 || env == "" || tech == "" {
			return projectEdit{}, fmt.Errorf("%q must look like env:tech=version, for example prod:php=8.3", v)
		}
		changes = append(changes, projectfile.Op{Kind: "set_env_tech", Env: model.Env(env), Tech: tech, Version: ver})
	}
	for _, v := range envUnset {
		env, tech, ok := strings.Cut(v, ":")
		if !ok || env == "" || tech == "" {
			return projectEdit{}, fmt.Errorf("%q must look like env:tech, for example prod:php", v)
		}
		changes = append(changes, projectfile.Op{Kind: "remove_env_tech", Env: model.Env(env), Tech: tech})
	}
	for _, e := range envAdd {
		changes = append(changes, projectfile.Op{Kind: "add_env", Env: model.Env(e)})
	}
	for _, e := range envRemove {
		changes = append(changes, projectfile.Op{Kind: "remove_env", Env: model.Env(e)})
	}
	for _, v := range envRename {
		from, to, ok := strings.Cut(v, "=")
		if !ok || from == "" || to == "" {
			return projectEdit{}, fmt.Errorf("%q must look like old=new, for example staging=stage", v)
		}
		changes = append(changes, projectfile.Op{Kind: "rename_env", Env: model.Env(from), To: model.Env(to)})
	}
	for kind, list := range map[string]listFlag{"exclude_env_tech": envExclude, "include_env_tech": envInclude} {
		for _, v := range list {
			env, tech, ok := strings.Cut(v, ":")
			if !ok || env == "" || tech == "" {
				return projectEdit{}, fmt.Errorf("%q must look like env:tech, for example local:xdebug", v)
			}
			changes = append(changes, projectfile.Op{Kind: kind, Env: model.Env(env), Tech: tech})
		}
	}
	for _, v := range techEnvs {
		tech, list, ok := strings.Cut(v, "=")
		if !ok || tech == "" {
			return projectEdit{}, fmt.Errorf("%q must look like tech=env,env, for example xdebug=local,dev (tech= lifts the limit)", v)
		}
		op := projectfile.Op{Kind: "set_tech_envs", Tech: tech}
		for _, e := range strings.Split(list, ",") {
			if e = strings.TrimSpace(e); e != "" {
				op.Envs = append(op.Envs, model.Env(e))
			}
		}
		changes = append(changes, op)
	}
	if *migrate {
		changes = append(changes, projectfile.Op{Kind: "migrate_envs"})
	}
	for _, v := range image {
		env, img, ok := strings.Cut(v, "=")
		if !ok || env == "" {
			return projectEdit{}, fmt.Errorf("%q must look like env=tag, for example prod=shop:1.4.2 (env= clears)", v)
		}
		changes = append(changes, projectfile.Op{Kind: "set_image", Env: model.Env(env), Image: img})
	}
	if len(changes) == 0 {
		return projectEdit{}, errors.New("nothing to change: use -set, -remove, -env-set, -env-unset, -image, -lock, -unlock, -lock-dev, -lock-nodev, -since, -envs, -env-add, -env-remove, -env-rename, -env-exclude, -env-include, -tech-envs or -migrate-envs (cvewatch project NAME -h lists them)")
	}
	return projectEdit{name: name, ops: changes, save: *save}, nil
}

func showProject(s *ops.Session, c ops.ProjectChange) error {
	p, err := s.EditProject(c)
	fmt.Print(p.Diff)
	covered := map[string]bool{} // a hint says more than the warning on the same field
	for _, h := range p.Hints {
		covered[h.Field] = true
	}
	for _, i := range p.Issues {
		if i.Level == "error" || !covered[i.Field] {
			fmt.Printf("%s: %s: %s\n", i.Level, i.Field, i.Message)
		}
	}
	for _, h := range p.Hints {
		fmt.Printf("%s: %s: %s\n", h.Level, h.Field, h.Message)
		if h.Keyword != "" {
			fmt.Printf("  to add it as your own keyword: cvewatch tech add %s -yes\n", catalog.Slug(h.Keyword))
		}
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

// parseLock reads type:path, with an optional :env and :dev after the path.
// Only a trailing word that is exactly dev or an environment name counts, so a
// path with colons (C:\repo\composer.lock) stays whole.
func parseLock(v string) (model.Lockfile, error) {
	typ, rest, ok := strings.Cut(v, ":")
	if !ok || typ == "" || rest == "" {
		return model.Lockfile{}, fmt.Errorf("%q must look like type:path[:env][:dev], for example composer:../shop/composer.lock:prod", v)
	}
	l := model.Lockfile{Type: typ}
	parts := strings.Split(rest, ":")
	if n := len(parts); n > 1 && parts[n-1] == "dev" {
		l.Dev, parts = true, parts[:n-1]
	}
	// a single letter before it is a drive (C:data), so the last part is part of the path
	if n := len(parts); n > 1 && model.Env(parts[n-1]).Valid() && !(n == 2 && len(parts[0]) == 1) {
		l.Env, parts = model.Env(parts[n-1]), parts[:n-1]
	}
	l.Path = strings.Join(parts, ":")
	return l, nil
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

// setupCmd runs the prompt wizard: with a folder, or a Dockerfile or compose
// file, it proposes a project from it, with -project it edits that project, and with neither it shows a menu.
func setupCmd(s *ops.Session, args []string) error {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	project := fs.String("project", "", "edit this existing project")
	all := fs.Bool("all", false, "also scan paths .gitignore ignores")
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
	return wizard.SetupWith(io, s, dir, *project, *all)
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
