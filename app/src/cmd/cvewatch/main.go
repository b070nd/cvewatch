// Command cvewatch watches public vulnerability feeds and reports what
// matters to our projects. This file only parses arguments and prints; all
// behaviour lives in package ops.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/b070nd/cvewatch/app/src/audit"
	"github.com/b070nd/cvewatch/app/src/calendar"
	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/host"
	"github.com/b070nd/cvewatch/app/src/mcpserver"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/ops"
	"github.com/b070nd/cvewatch/app/src/query"
	"github.com/b070nd/cvewatch/app/src/report"
)

// version is set at build time: -ldflags "-X main.version=v1.2.3".
var version = "dev"

const usage = `usage: cvewatch [-root DIR] [-v] <command>

  update [-min S] [-project P] [-all] [-json]   refresh all sources now, then show open findings
                                                (run is the same; new items are marked NEW)
  daemon                                        refresh every configured interval
  list   [-min S] [-project P] [-all] [-json]   open findings, most severe first
  show   ID [-json]                             description, fix, articles, status and plan
  why    ID [-json]                             why it matched, judged again with today's config
  rescan [-apply]                               re-judge old items against today's config (dry run unless -apply)
  calendar [-month YYYY-MM] [-text] [-min S] [-project P] [-all]
                                                month overview; writes an HTML page unless -text
  fix    ID -project P [-env E] [-note N]       mark a fix as applied
  ignore ID -project P [-env E] [-note N]       mark as not applicable
  reopen ID -project P [-env E] [-note N]       put a finding back to open
  mcp    [-allow-write]                         MCP server on stdio; read-only unless -allow-write
  check                                         validate configuration
  audit                                         verify the audit log chain
  version                                       print the version

S is low, medium, high or critical. -all also lists versions known to be unaffected.
-root is the app directory holding config/ and sources/ (default ".").`

func main() {
	root := flag.String("root", ".", "app directory")
	verbose := flag.Bool("v", false, "debug logging")
	flag.Usage = func() { fmt.Fprintln(os.Stderr, usage) }
	flag.Parse()
	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(2)
	}

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	ctx, stop := signal.NotifyContext(context.Background(), host.StopSignals()...)
	defer stop()

	if err := dispatch(ctx, *root, log, flag.Args()); err != nil {
		log.Error("failed", "err", err)
		os.Exit(1)
	}
}

func dispatch(ctx context.Context, root string, log *slog.Logger, args []string) error {
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "run", "update":
		o, err := parseList(cmd, rest)
		if err != nil {
			return err
		}
		return withSession(root, log, func(s *ops.Session) error { return refresh(ctx, s, o) })
	case "daemon":
		return daemon(ctx, root, log)
	case "list":
		o, err := parseList(cmd, rest)
		if err != nil {
			return err
		}
		return withSession(root, log, func(s *ops.Session) error { return printOpen(s, o, nil) })
	case "show":
		return withSession(root, log, func(s *ops.Session) error { return show(s, rest) })
	case "why":
		return withSession(root, log, func(s *ops.Session) error { return why(s, rest) })
	case "rescan":
		return withSession(root, log, func(s *ops.Session) error { return rescan(s, rest) })
	case "calendar":
		return withSession(root, log, func(s *ops.Session) error { return showCalendar(s, rest) })
	case "fix":
		return withSession(root, log, func(s *ops.Session) error { return resolve(s, rest, model.StatusFixed) })
	case "ignore":
		return withSession(root, log, func(s *ops.Session) error { return resolve(s, rest, model.StatusIgnored) })
	case "reopen":
		return withSession(root, log, func(s *ops.Session) error { return resolve(s, rest, model.StatusOpen) })
	case "mcp":
		fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
		write := fs.Bool("allow-write", false, "also expose set_status and refresh")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		return mcpserver.Serve(ctx, root, log, *write)
	case "check":
		return check(root)
	case "audit":
		return verifyAudit(root)
	case "version":
		fmt.Println("cvewatch", version)
		return nil
	}
	return fmt.Errorf("unknown command %q\n%s", cmd, usage)
}

// withSession opens, runs and always closes, releasing the data lock.
func withSession(root string, log *slog.Logger, fn func(*ops.Session) error) error {
	s, err := ops.Open(root, log)
	if err != nil {
		return err
	}
	defer s.Close()
	return fn(s)
}

type listOpts struct {
	query.Filter
	JSON bool
}

// parseList reads the flags shared by update, run and list.
func parseList(name string, args []string) (listOpts, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	min := fs.String("min", "", "lowest severity to show: low, medium, high, critical")
	project := fs.String("project", "", "only this project")
	all := fs.Bool("all", false, "include versions known to be unaffected")
	asJSON := fs.Bool("json", false, "print JSON instead of text")
	if err := fs.Parse(args); err != nil {
		return listOpts{}, err
	}
	f, err := ops.ParseFilter(*min, *project)
	f.All = *all
	return listOpts{Filter: f, JSON: *asJSON}, err
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func printOpen(s *ops.Session, o listOpts, fresh map[string]bool) error {
	issues, err := s.List(o.Filter)
	if err != nil {
		return err
	}
	if o.JSON {
		return printJSON(issues)
	}
	fmt.Print(report.Digest(issues, fresh))
	return nil
}

func refresh(ctx context.Context, s *ops.Session, o listOpts) error {
	res, err := s.Refresh(ctx)
	s.Log.Info("cycle done", "items", res.Items, "new", res.New, "merged", res.Merged, "pruned", res.Pruned,
		"findings", res.Findings, "alerted", res.Alerted, "failed_sources", len(res.Failed))
	if perr := printOpen(s, o, res.Fresh); perr != nil {
		return perr
	}
	return err
}

func daemon(ctx context.Context, root string, log *slog.Logger) error {
	for {
		err := withSession(root, log, func(s *ops.Session) error { return refresh(ctx, s, listOpts{}) })
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return nil
			}
			log.Error("cycle failed", "err", err) // keep going: the next cycle may succeed
		}
		wait := 4 * time.Hour
		if cfg, err := config.Load(root); err == nil {
			wait = cfg.Interval
		}
		log.Info("sleeping", "for", wait)
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return nil
		}
	}
}

// idAndFlags splits "ID -flag ..." because Go's flag package stops at the first non-flag.
func idAndFlags(fs *flag.FlagSet, args []string) (string, error) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return "", errors.New("missing vulnerability id")
	}
	return args[0], fs.Parse(args[1:])
}

func show(s *ops.Session, args []string) error {
	fs := flag.NewFlagSet("show", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print JSON instead of markdown")
	id, err := idAndFlags(fs, args)
	if err != nil {
		return err
	}
	is, md, err := s.Show(id)
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(is)
	}
	fmt.Print(md)
	return nil
}

func why(s *ops.Session, args []string) error {
	fs := flag.NewFlagSet("why", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print JSON")
	id, err := idAndFlags(fs, args)
	if err != nil {
		return err
	}
	ex, err := s.Explain(id)
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(ex)
	}
	fmt.Printf("%s\n\nDecided when first seen:\n", ex.ID)
	for _, t := range ex.Stored {
		fmt.Printf("  %s/%s [%s] %s\n", t.Project, t.Env, t.Applies, strings.Join(t.Reasons, "; "))
	}
	fmt.Printf("\nJudged again with today's config (relevant: %v):\n", ex.Relevant)
	for _, l := range ex.Today {
		fmt.Printf("  %s\n", l)
	}
	for _, n := range ex.Notes {
		fmt.Printf("  not matched: %s\n", n)
	}
	return nil
}

func rescan(s *ops.Session, args []string) error {
	fs := flag.NewFlagSet("rescan", flag.ContinueOnError)
	apply := fs.Bool("apply", false, "create the findings; without it only report them")
	if err := fs.Parse(args); err != nil {
		return err
	}
	r, err := s.Rescan(*apply)
	if err != nil {
		return err
	}
	for _, c := range r.Candidates {
		fmt.Printf("%-18s %-30s %s\n", c.ID, strings.Join(c.Projects, ","), c.Title)
	}
	switch {
	case len(r.Candidates) == 0:
		fmt.Println("Nothing new would match.")
	case r.Applied:
		fmt.Printf("%d issue(s) now have findings.\n", len(r.Candidates))
	default:
		fmt.Printf("%d issue(s) would get findings. Run again with -apply to create them.\n", len(r.Candidates))
	}
	return nil
}

func showCalendar(s *ops.Session, args []string) error {
	fs := flag.NewFlagSet("calendar", flag.ContinueOnError)
	monthFlag := fs.String("month", "", "month as YYYY-MM (default: this month)")
	text := fs.Bool("text", false, "print to the terminal instead of writing an HTML page")
	min := fs.String("min", "", "lowest severity to show")
	project := fs.String("project", "", "only this project")
	all := fs.Bool("all", false, "include versions known to be unaffected")
	if err := fs.Parse(args); err != nil {
		return err
	}
	f, err := ops.ParseFilter(*min, *project)
	if err != nil {
		return err
	}
	f.All = *all
	month := time.Date(s.Now().Year(), s.Now().Month(), 1, 0, 0, 0, 0, s.Now().Location())
	if *monthFlag != "" {
		if month, err = time.ParseInLocation("2006-01", *monthFlag, s.Now().Location()); err != nil {
			return fmt.Errorf("month must look like 2026-10: %w", err)
		}
	}
	if *text {
		entries, err := s.Calendar(month, f)
		if err != nil {
			return err
		}
		fmt.Print(calendar.Text(entries, month))
		return nil
	}
	path, err := s.WriteCalendar(month, f)
	if err != nil {
		return err
	}
	fmt.Println("calendar written:", path)
	return nil
}

func resolve(s *ops.Session, args []string, st model.Status) error {
	fs := flag.NewFlagSet("resolve", flag.ContinueOnError)
	project := fs.String("project", "", "project name (required)")
	env := fs.String("env", "", "environment; empty means all of the project's environments")
	note := fs.String("note", "", "free text, e.g. ticket or version")
	id, err := idAndFlags(fs, args)
	if err != nil {
		return err
	}
	n, err := s.Resolve(ops.Change{ID: id, Project: *project, Env: model.Env(*env), Status: st, Note: *note})
	if err != nil {
		return err
	}
	fmt.Printf("%d finding(s) set to %s\n", n, st)
	return nil
}

func check(root string) error {
	cfg, err := config.Load(root)
	if err != nil {
		return err
	}
	for _, w := range cfg.Warnings {
		fmt.Println("warning:", w)
	}
	fmt.Printf("ok: %d techs, %d projects, %d sources, interval %s\n",
		len(cfg.Techs), len(cfg.Projects), len(cfg.Sources), cfg.Interval)
	if len(cfg.Access) > 0 {
		fmt.Printf("access rules: %d actor(s); acting as %q\n", len(cfg.Access), audit.Actor())
	}
	return nil
}

func verifyAudit(root string) error {
	cfg, err := config.Load(root)
	if err != nil {
		return err
	}
	n, err := audit.Open(cfg.DataDir).Verify()
	if err != nil {
		return fmt.Errorf("audit log damaged: %w", err)
	}
	fmt.Printf("audit log ok: %d records, chain intact\n", n)
	return nil
}
