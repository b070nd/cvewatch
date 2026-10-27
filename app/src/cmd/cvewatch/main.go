// Command cvewatch watches public vulnerability feeds and reports what
// matters to our projects.
//
//	cvewatch update [-min S] [-project P]   refresh all sources now, then list (alias: run)
//	cvewatch daemon                 cycle every `interval` until stopped
//	cvewatch list [-min S] [-project P] [-json]   open findings by severity
//	cvewatch show ID [-json]        one vulnerability: description, links, status, plan
//	cvewatch mcp [-allow-write]     MCP server on stdio for agents and IDEs
//	cvewatch check                  validate config
//	cvewatch fix|ignore|reopen ID --project P [--env E] [--note N]
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
	"syscall"
	"time"

	"cvewatch/src/audit"
	"cvewatch/src/config"
	"cvewatch/src/mcpserver"
	"cvewatch/src/model"
	"cvewatch/src/pipeline"
	"cvewatch/src/query"
	"cvewatch/src/report"
	"cvewatch/src/store"
)

const usage = `usage: cvewatch [-root DIR] [-v] <command>

  update [-min S] [-project P]   refresh all sources now, then show open findings
                                 (run is the same; new items are marked NEW)
  daemon                         run a cycle every configured interval
  list   [-min S] [-project P]   show open findings, most severe first
                                 S is low, medium, high or critical;
                                 add -json for machine-readable output
  show   ID [-json]              one vulnerability with plan and per-environment status
  mcp    [-allow-write]          serve MCP on stdio; read-only unless -allow-write
  check                          validate configuration
  audit                          verify the audit log chain
  version                        print the version
  fix    ID -project P [-env E] [-note N]   mark a fix as applied
  ignore ID -project P [-env E] [-note N]   mark as not applicable
  reopen ID -project P [-env E] [-note N]   put a finding back to open

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
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := dispatch(ctx, *root, log, flag.Args()); err != nil {
		log.Error("failed", "err", err)
		os.Exit(1)
	}
}

func dispatch(ctx context.Context, root string, log *slog.Logger, args []string) error {
	switch cmd := args[0]; cmd {
	case "run", "update":
		o, err := parseOpts(cmd, args[1:])
		if err != nil {
			return err
		}
		return cycle(ctx, root, log, o)
	case "daemon":
		return daemon(ctx, root, log)
	case "list":
		o, err := parseOpts(cmd, args[1:])
		if err != nil {
			return err
		}
		return list(root, o)
	case "show":
		return show(root, args[1:])
	case "mcp":
		return serveMCP(ctx, root, log, args[1:])
	case "check":
		return check(root)
	case "version":
		fmt.Println("cvewatch", version)
		return nil
	case "audit":
		return verifyAudit(root)
	case "fix":
		return resolve(root, args[1:], model.StatusFixed)
	case "ignore":
		return resolve(root, args[1:], model.StatusIgnored)
	case "reopen":
		return resolve(root, args[1:], model.StatusOpen)
	default:
		return fmt.Errorf("unknown command %q\n%s", cmd, usage)
	}
}

type listOpts struct {
	query.Filter
	JSON bool
}

// parseOpts reads the flags shared by update, run and list.
func parseOpts(name string, args []string) (listOpts, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	min := fs.String("min", "", "lowest severity to show: low, medium, high, critical")
	project := fs.String("project", "", "only this project")
	asJSON := fs.Bool("json", false, "print JSON instead of text")
	if err := fs.Parse(args); err != nil {
		return listOpts{}, err
	}
	o := listOpts{Filter: query.Filter{Project: *project}, JSON: *asJSON}
	if *min != "" {
		if o.Min = model.ParseSeverity(*min); o.Min == model.SevUnknown {
			return o, fmt.Errorf("unknown severity %q (use low, medium, high or critical)", *min)
		}
	}
	return o, nil
}

// printIssues writes the open list as text, or as JSON for tools and agents.
func printIssues(st *store.Store, o listOpts, fresh map[string]bool) error {
	issues := query.Open(st, o.Filter)
	if !o.JSON {
		fmt.Print(report.Digest(issues, fresh))
		return nil
	}
	return printJSON(issues)
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// cycle loads config from disk every time, so edits apply on the next run.
func cycle(ctx context.Context, root string, log *slog.Logger, o listOpts) error {
	cfg, err := config.Load(root)
	if err != nil {
		return err
	}
	for _, w := range cfg.Warnings {
		log.Warn(w)
	}
	st, err := store.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	defer st.Close()

	runner, err := pipeline.NewRunner(cfg, st, log)
	if err != nil {
		return err
	}
	res, err := runner.Run(ctx)
	log.Info("cycle done", "items", res.Items, "new", res.New, "merged", res.Merged, "pruned", res.Pruned, "findings", res.Findings,
		"alerted", res.Alerted, "failed_sources", len(res.Failed))
	if perr := printIssues(st, o, res.Fresh); perr != nil {
		return perr
	}
	return err
}

func daemon(ctx context.Context, root string, log *slog.Logger) error {
	for {
		if err := cycle(ctx, root, log, listOpts{}); err != nil {
			if errors.Is(err, context.Canceled) {
				return nil
			}
			log.Error("cycle failed", "err", err) // keep going: the next cycle may succeed
		}
		cfg, err := config.Load(root)
		wait := 4 * time.Hour
		if err == nil {
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

func list(root string, o listOpts) error {
	cfg, err := config.Load(root)
	if err != nil {
		return err
	}
	st, err := store.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	defer st.Close()
	return printIssues(st, o, nil)
}

func show(root string, args []string) error {
	if len(args) == 0 {
		return errors.New("missing vulnerability id")
	}
	fs := flag.NewFlagSet("show", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print JSON instead of markdown")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	cfg, err := config.Load(root)
	if err != nil {
		return err
	}
	st, err := store.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	defer st.Close()

	is, err := query.One(st, args[0])
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(is)
	}
	fmt.Print(report.Render(st.Vuln(is.ID), st.FindingsOf(is.ID)))
	return nil
}

func serveMCP(ctx context.Context, root string, log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	write := fs.Bool("allow-write", false, "also expose set_status and refresh")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return mcpserver.Serve(ctx, root, log, *write)
}

// version is set at build time: -ldflags "-X main.version=v1.2.3".
var version = "dev"

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
	return nil
}

func resolve(root string, args []string, st model.Status) error {
	if len(args) == 0 {
		return errors.New("missing vulnerability id")
	}
	fs := flag.NewFlagSet("resolve", flag.ContinueOnError)
	project := fs.String("project", "", "project name (required)")
	env := fs.String("env", "", "environment; empty means all of the project's environments")
	note := fs.String("note", "", "free text, e.g. ticket or version")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *project == "" {
		return errors.New("-project is required")
	}
	if e := model.Env(*env); *env != "" && !e.Valid() {
		return fmt.Errorf("unknown env %q", *env)
	}

	cfg, err := config.Load(root)
	if err != nil {
		return err
	}
	s, err := store.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	defer s.Close()
	c := pipeline.Change{ID: args[0], Project: *project, Env: model.Env(*env), Status: st, Note: *note}
	n, err := pipeline.Resolve(s, cfg.AlertsDir, audit.Open(cfg.DataDir), audit.Actor(), c, time.Now())
	if err != nil {
		return err
	}
	fmt.Printf("%d finding(s) set to %s\n", n, st)
	return nil
}
