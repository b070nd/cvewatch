// Command cvewatch watches public vulnerability feeds and reports what
// matters to our projects. This file only parses arguments and prints; all
// behaviour lives in package ops, doctor and the modules behind them.
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
	"github.com/b070nd/cvewatch/app/src/daemon"
	"github.com/b070nd/cvewatch/app/src/doctor"
	"github.com/b070nd/cvewatch/app/src/export"
	"github.com/b070nd/cvewatch/app/src/host"
	"github.com/b070nd/cvewatch/app/src/mcpserver"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/notify"
	"github.com/b070nd/cvewatch/app/src/ops"
	"github.com/b070nd/cvewatch/app/src/query"
	"github.com/b070nd/cvewatch/app/src/report"
)

// version is set at build time: -ldflags "-X main.version=v1.2.3".
var version = "dev"

const usage = `usage: cvewatch [-root DIR] [-v] <command>

Getting started
  init [-repo PATH] [-project NAME] [-force]   write a starter configuration; -repo detects lockfiles and techs
  doctor [-online] [-json]                     check configuration, lockfiles, state, channels; -online also checks CPE names and feeds

Everyday
  update [-min S] [-project P] [-env E] [-all] [-json] [-fail-on S]   refresh all sources now, then show open findings (run is the same)
  list   [-min S] [-project P] [-env E] [-all] [-json] [-fail-on S]   open findings, most urgent first; -fail-on exits 1 for a CI gate
  show   ID [-json]                            description, fix, articles, status and plan
  why    ID [-json]                            why it matched, judged again with today's config
  search [-open] [-min S] [-project P] [-env E] [-json] QUERY...   find issues by id, words or fields such as severity:high; for a query starting with -, put -- before it
  daemon                                       refresh every configured interval
  status [-json]                               is it working: daemon, feeds, channels, recent cycles
  dashboard [-out FILE]                        write the static status page now

Projects and technologies
  catalog [-category C] [-json] [WORDS]        the technologies cvewatch knows (open and closed source)
  discover DIR [-json]                         what a repository uses, with evidence; changes nothing
  tui [-dir REPO]                              full-screen findings, projects, setup and status (starts cvewatch-tui)
  setup [DIR] [-project NAME]                  guided setup or edit of a project, with the evidence for every guess
  project [list]                               the monitored projects
  project NAME [-set T=V] [-remove T] [-lock TYPE:PATH] [-unlock TYPE:PATH] [-envs E,E] [-save]   edit a project file (diff only without -save)

Tracking
  fix    ID -project P [-env E] [-note N]      mark a fix as applied
  ignore ID -project P [-env E] [-note N]      accepted or not applicable
  not-affected ID -project P [-env E] -note WHY   assert it does not apply here (reason required)
  reopen ID -project P [-env E] [-note N]      put a finding back to open
  assign ID -project P [-env E] [-owner O] [-due YYYY-MM-DD] [-ticket T]   owner, deadline, ticket ("-" clears)
  evidence ID [-json]                          evidence pack: timeline, per-environment status, audit trail
  evidence add ID -project P [-env E] [-note N] [-url U]   attach a note and link as evidence

Reports
  export [-format json|csv|md|sarif] [-min S] [-project P] [-env E] [-all]   open findings with every environment's status
  policy                                       findings that break a policy rule or their due date
  digest [-send]                               the "still open" summary, shown or sent now
  inventory [-project P]                       what the tool believes runs in each environment
  calendar [-month YYYY-MM] [-text] [-min S] [-project P] [-all]   month overview, HTML page unless -text
  rescan [-apply]                              re-judge old items against today's config (dry run unless -apply)

Other
  mcp [-allow-write]                           MCP server on stdio; read-only unless -allow-write
  check                                        validate configuration (doctor does more)
  audit                                        verify the audit log chain
  version                                      print the version

S is low, medium, high or critical. -all also lists versions known to be unaffected.
-root is the folder holding config/ and sources/ (default "."); cvewatch init creates it.`

func main() {
	root := flag.String("root", ".", "configuration folder")
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
	with := func(fn func(*ops.Session) error) error { return withSession(root, log, fn) }
	read := func(fn func(*ops.Session) error) error { return withReadSession(root, log, fn) }
	switch cmd {
	case "init":
		return initCmd(root, rest)
	case "doctor":
		return doctorCmd(ctx, root, rest)
	case "run", "update":
		o, err := parseList(cmd, rest)
		if err != nil {
			return err
		}
		return with(func(s *ops.Session) error { return refresh(ctx, s, o) })
	case "daemon":
		return daemon.Run(ctx, root, log)
	case "list":
		o, err := parseList(cmd, rest)
		if err != nil {
			return err
		}
		return read(func(s *ops.Session) error { return printOpen(s, o, nil) })
	case "show":
		return read(func(s *ops.Session) error { return show(s, rest) })
	case "search":
		return read(func(s *ops.Session) error { return searchCmd(s, rest) })
	case "why":
		return read(func(s *ops.Session) error { return why(s, rest) })
	case "rescan":
		return with(func(s *ops.Session) error { return rescan(s, rest) })
	case "calendar":
		return read(func(s *ops.Session) error { return showCalendar(s, rest) })
	case "fix":
		return with(func(s *ops.Session) error { return resolve(s, cmd, rest, model.StatusFixed) })
	case "ignore":
		return with(func(s *ops.Session) error { return resolve(s, cmd, rest, model.StatusIgnored) })
	case "not-affected":
		return with(func(s *ops.Session) error { return resolve(s, cmd, rest, model.StatusNotAffected) })
	case "reopen":
		return with(func(s *ops.Session) error { return resolve(s, cmd, rest, model.StatusOpen) })
	case "assign":
		return with(func(s *ops.Session) error { return assign(s, rest) })
	case "evidence":
		if len(rest) > 0 && rest[0] == "add" {
			return with(func(s *ops.Session) error { return evidenceCmd(s, rest) })
		}
		return read(func(s *ops.Session) error { return evidenceCmd(s, rest) })
	case "status":
		return read(func(s *ops.Session) error { return statusCmd(s, rest) })
	case "dashboard":
		return read(func(s *ops.Session) error { return dashboardCmd(s, rest) })
	case "catalog":
		return read(func(s *ops.Session) error { return catalogCmd(s, rest) })
	case "discover":
		return read(func(s *ops.Session) error { return discoverCmd(s, rest) })
	case "tui":
		return tuiCmd(ctx, root, rest)
	case "setup":
		return with(func(s *ops.Session) error { return setupCmd(s, rest) })
	case "project":
		if len(rest) == 0 || rest[0] == "list" {
			return read(func(s *ops.Session) error { return projectCmd(s, rest) })
		}
		return with(func(s *ops.Session) error { return projectCmd(s, rest) })
	case "export":
		return read(func(s *ops.Session) error { return exportCmd(s, rest) })
	case "policy":
		return read(func(s *ops.Session) error { return policy(s) })
	case "digest":
		return with(func(s *ops.Session) error { return digest(ctx, s, rest) })
	case "inventory":
		return read(func(s *ops.Session) error { return inventoryCmd(s, rest) })
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

// withReadSession is withSession without the data lock, for commands that
// only read, so they never wait for the daemon.
func withReadSession(root string, log *slog.Logger, fn func(*ops.Session) error) error {
	s, err := ops.OpenReadOnly(root, log)
	if err != nil {
		return err
	}
	defer s.Close()
	return fn(s)
}

type listOpts struct {
	query.Filter
	JSON   bool
	FailOn model.Severity // exit non-zero when an open finding is at least this severe
}

// parseList reads the flags shared by update, run and list.
func parseList(name string, args []string) (listOpts, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	min := fs.String("min", "", "lowest severity to show: low, medium, high, critical")
	project := fs.String("project", "", "only this project")
	env := fs.String("env", "", "only this environment")
	all := fs.Bool("all", false, "include versions known to be unaffected")
	asJSON := fs.Bool("json", false, "print JSON instead of text")
	failOn := fs.String("fail-on", "", "exit non-zero when an open finding is at least this severe (for CI gates)")
	if err := fs.Parse(args); err != nil {
		return listOpts{}, err
	}
	f, err := ops.ParseFilter(*min, *project, *env)
	f.All = *all
	o := listOpts{Filter: f, JSON: *asJSON}
	if *failOn != "" {
		if o.FailOn = model.ParseSeverity(*failOn); o.FailOn == model.SevUnknown {
			return o, fmt.Errorf("unknown severity %q for -fail-on (use low, medium, high or critical)", *failOn)
		}
	}
	return o, err
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
		err = export.New(issues, s.Now()).WriteJSON(os.Stdout)
	} else {
		fmt.Print(report.Digest(issues, fresh))
	}
	if err != nil {
		return err
	}
	return failGate(issues, o.FailOn)
}

// failGate is the CI gate behind -fail-on: no level set means no gate.
func failGate(issues []query.Issue, level model.Severity) error {
	if level == "" {
		return nil
	}
	n := 0
	for _, is := range issues {
		if is.Severity.AtLeast(level) {
			n++
		}
	}
	if n > 0 {
		return fmt.Errorf("%d open finding(s) at or above %s", n, level)
	}
	return nil
}

func refresh(ctx context.Context, s *ops.Session, o listOpts) error {
	res, err := s.Refresh(ctx)
	s.Log.Info("cycle done", "items", res.Items, "new", res.New, "merged", res.Merged, "pruned", res.Pruned,
		"findings", res.Findings, "reconciled", res.Reconciled, "enriched", res.Enriched,
		"alerted", res.Alerted, "digests", res.Digests, "failed_sources", len(res.Failed))
	if perr := printOpen(s, o, res.Fresh); perr != nil {
		return perr
	}
	return err
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
		return withSuggestions(s, id, err)
	}
	if *asJSON {
		return export.New([]query.Issue{is}, s.Now()).WriteJSON(os.Stdout)
	}
	fmt.Print(md)
	return nil
}

func withSuggestions(s *ops.Session, id string, err error) error {
	if !strings.HasPrefix(err.Error(), "unknown vulnerability") {
		return err
	}
	found, serr := s.Search(id, query.Filter{}, false)
	if serr != nil || len(found) == 0 {
		return err
	}
	var ids []string
	for _, is := range found[:min(len(found), 5)] {
		ids = append(ids, is.ID)
	}
	return fmt.Errorf("%w; did you mean: %s", err, strings.Join(ids, ", "))
}

func searchCmd(s *ops.Session, args []string) error {
	fs := flag.NewFlagSet("search", flag.ContinueOnError)
	openOnly := fs.Bool("open", false, "only findings that are still open")
	min := fs.String("min", "", "lowest severity to show: low, medium, high, critical")
	project := fs.String("project", "", "only this project")
	env := fs.String("env", "", "only this environment")
	asJSON := fs.Bool("json", false, "print JSON instead of text")
	if err := fs.Parse(args); err != nil {
		return err
	}
	text := strings.Join(fs.Args(), " ")
	if strings.TrimSpace(text) == "" {
		return errors.New("give a search text, for example: cvewatch search cve-2026-1234")
	}
	f, err := ops.ParseFilter(*min, *project, *env)
	if err != nil {
		return err
	}
	issues, err := s.Search(text, f, *openOnly)
	if err != nil {
		return err
	}
	if *asJSON {
		return export.New(issues, s.Now()).WriteJSON(os.Stdout)
	}
	if len(issues) == 0 {
		fmt.Printf("No issue matches %q.\n", text)
		return nil
	}
	fmt.Print(report.Matches(issues))
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
	f, err := ops.ParseFilter(*min, *project, "")
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

func resolve(s *ops.Session, name string, args []string, st model.Status) error {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	project := fs.String("project", "", "project name (required)")
	env := fs.String("env", "", "environment; empty means all of the project's environments")
	note := fs.String("note", "", "reason, ticket or version")
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

func assign(s *ops.Session, args []string) error {
	fs := flag.NewFlagSet("assign", flag.ContinueOnError)
	project := fs.String("project", "", "project name (required)")
	env := fs.String("env", "", "environment; empty means all of the project's environments")
	owner := fs.String("owner", "", `who handles it ("-" clears)`)
	due := fs.String("due", "", `deadline YYYY-MM-DD ("none" clears)`)
	ticket := fs.String("ticket", "", `ticket or merge request link ("-" clears)`)
	id, err := idAndFlags(fs, args)
	if err != nil {
		return err
	}
	n, err := s.Assign(ops.Assignment{ID: id, Project: *project, Env: model.Env(*env), Owner: *owner, Due: *due, Ticket: *ticket})
	if err != nil {
		return err
	}
	fmt.Printf("%d finding(s) updated\n", n)
	return nil
}

func evidenceCmd(s *ops.Session, args []string) error {
	if len(args) > 0 && args[0] == "add" {
		fs := flag.NewFlagSet("evidence add", flag.ContinueOnError)
		project := fs.String("project", "", "project name (required)")
		env := fs.String("env", "", "environment; empty means all of the project's environments")
		note := fs.String("note", "", "what the evidence shows")
		link := fs.String("url", "", "advisory, merge request, change ticket or deployment record")
		id, err := idAndFlags(fs, args[1:])
		if err != nil {
			return err
		}
		n, err := s.Attach(ops.Attachment{ID: id, Project: *project, Env: model.Env(*env), Note: *note, URL: *link})
		if err != nil {
			return err
		}
		fmt.Printf("evidence attached to %d finding(s)\n", n)
		return nil
	}
	fs := flag.NewFlagSet("evidence", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print JSON instead of markdown")
	id, err := idAndFlags(fs, args)
	if err != nil {
		return err
	}
	pack, err := s.Evidence(id)
	if err != nil {
		return err
	}
	if *asJSON {
		return pack.WriteJSON(os.Stdout)
	}
	return pack.WriteMarkdown(os.Stdout)
}

func exportCmd(s *ops.Session, args []string) error {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	format := fs.String("format", "json", "one of: "+strings.Join(export.Formats(), ", "))
	min := fs.String("min", "", "lowest severity to include")
	project := fs.String("project", "", "only this project")
	env := fs.String("env", "", "only this environment")
	all := fs.Bool("all", false, "include versions known to be unaffected")
	if err := fs.Parse(args); err != nil {
		return err
	}
	f, err := ops.ParseFilter(*min, *project, *env)
	if err != nil {
		return err
	}
	f.All = *all
	doc, err := s.Export(f)
	if err != nil {
		return err
	}
	return export.Write(os.Stdout, *format, doc)
}

func policy(s *ops.Session) error {
	vs, err := s.Violations()
	if err != nil {
		return err
	}
	if len(vs) == 0 {
		fmt.Println("No policy violations.")
		return nil
	}
	fmt.Printf("Policy violations: %d\n\n", len(vs))
	for _, v := range vs {
		fmt.Printf("  %-18s %s/%s  %s  [%s, %s late]\n      %s\n", v.Subject.VulnID, v.Subject.Project, v.Subject.Env,
			v.Reason, v.Rule, v.Late.Round(time.Hour), v.Subject.Title)
	}
	return errors.New("policy violations found") // a non-zero exit lets CI and cron notice
}

func digest(ctx context.Context, s *ops.Session, args []string) error {
	fs := flag.NewFlagSet("digest", flag.ContinueOnError)
	send := fs.Bool("send", false, "send it to the active channels now")
	if err := fs.Parse(args); err != nil {
		return err
	}
	d, err := s.Digest()
	if err != nil {
		return err
	}
	if *send {
		n, err := s.SendDigest(ctx)
		if err != nil {
			return err
		}
		fmt.Printf("digest sent to %d channel(s)\n", n)
		return nil
	}
	fmt.Println(notify.FormatDigest(d))
	return nil
}

func inventoryCmd(s *ops.Session, args []string) error {
	fs := flag.NewFlagSet("inventory", flag.ContinueOnError)
	project := fs.String("project", "", "only this project")
	if err := fs.Parse(args); err != nil {
		return err
	}
	v, err := s.Inventory(*project)
	if err != nil {
		return err
	}
	for _, t := range v.Targets {
		image := ""
		if t.Image != "" {
			image = "  image " + t.Image
		}
		var techs []string
		for _, pt := range t.Techs {
			techs = append(techs, strings.TrimSpace(pt.Name+" "+pt.Version))
		}
		fmt.Printf("%-16s %-8s %d packages  techs: %s%s\n", t.Project, t.Env, len(t.Packages), strings.Join(techs, ", "), image)
	}
	for _, src := range v.Sources {
		env := string(src.Env)
		if env == "" {
			env = "all"
		}
		fmt.Printf("  source %-10s %s (%s): %d packages\n", src.Type, src.Path, env, src.Packages)
	}
	for _, p := range v.Problems {
		fmt.Println("  problem:", p.String())
	}
	return nil
}

func initCmd(root string, args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	repo := fs.String("repo", "", "repository to detect lockfiles and runtime versions in")
	project := fs.String("project", "", "project name (default: the repository folder)")
	force := fs.Bool("force", false, "overwrite files that already exist")
	if err := fs.Parse(args); err != nil {
		return err
	}
	res, err := doctor.Init(root, doctor.InitOptions{Force: *force, Repo: *repo, Project: *project})
	if err != nil {
		return err
	}
	for _, p := range res.Written {
		fmt.Println("wrote  ", p)
	}
	for _, p := range res.Skipped {
		fmt.Println("kept   ", p, "(exists; use -force to overwrite)")
	}
	for _, n := range res.Notes {
		fmt.Println(n)
	}
	return nil
}

func doctorCmd(ctx context.Context, root string, args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	online := fs.Bool("online", false, "also check CPE names against NVD and fetch every feed once")
	asJSON := fs.Bool("json", false, "print JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rep := doctor.Run(ctx, root, doctor.Options{Online: *online})
	var err error
	if *asJSON {
		err = rep.WriteJSON(os.Stdout)
	} else {
		rep.WriteText(os.Stdout)
	}
	if err != nil {
		return err
	}
	if rep.Failed() {
		return errors.New("doctor found failures")
	}
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
