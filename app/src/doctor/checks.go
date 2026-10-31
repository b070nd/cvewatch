package doctor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/b070nd/cvewatch/app/src/audit"
	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/feeds"
	"github.com/b070nd/cvewatch/app/src/host"
	"github.com/b070nd/cvewatch/app/src/httpx"
	"github.com/b070nd/cvewatch/app/src/inventory"
	"github.com/b070nd/cvewatch/app/src/ledger"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/notify"
	"github.com/b070nd/cvewatch/app/src/store"
)

// Options controls a doctor run.
type Options struct {
	// Online also asks NVD whether each CPE name exists and fetches every
	// enabled feed once. Without it nothing leaves the machine.
	Online bool
	// Getter performs those requests. Nil builds an HTTP client from the
	// configuration's http settings.
	Getter feeds.Getter
}

const (
	gConfig    = "config"
	gTechs     = "techs"
	gSources   = "sources"
	gInventory = "inventory"
	gState     = "state"
	gAudit     = "audit"
	gNotify    = "notify"
	gPolicy    = "policy"

	nvdCPEs = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
)

// Run checks the folder at root. It never changes configuration or state; the
// only writes are a short-lived probe file in the data and alerts directories.
func Run(ctx context.Context, root string, o Options) Report {
	r := Report{Root: root}
	cfg, err := config.Load(root)
	if err != nil {
		r.add(gConfig, "loads", Fail, "%s", err)
		return r
	}
	r.add(gConfig, "loads", OK, "%d techs, %d sources, %d projects", len(cfg.Techs), len(cfg.Sources), len(cfg.Projects))
	for _, w := range cfg.Warnings {
		r.add(gConfig, "warning", Warn, "%s", w)
	}
	r.add(gConfig, "techs come from", OK, "%s", pick(cfg.DefaultTechs, "shipped defaults", "config/techs.yaml"))
	r.add(gConfig, "sources come from", OK, "%s", pick(cfg.DefaultSources, "shipped defaults", "sources/*.yaml"))

	var getter feeds.Getter
	if o.Online {
		getter = o.Getter
		if getter == nil {
			getter = newClient(cfg)
		}
	}
	checkTechs(ctx, &r, cfg, getter)
	checkSources(ctx, &r, cfg, getter)
	checkInventory(&r, cfg)
	checkState(&r, cfg)
	checkAudit(&r, cfg)
	checkNotify(&r, cfg)
	checkPolicy(&r, cfg)
	checkUpdates(&r, cfg)
	return r
}

func pick(first bool, a, b string) string {
	if first {
		return a
	}
	return b
}

func newClient(cfg *config.Bundle) *httpx.Client { return cfg.HTTP.Client() }

// cpeName is a lowercase vendor:product pair as NVD spells it.
var cpeName = regexp.MustCompile(`^[a-z0-9._+~\-]+:[a-z0-9._+~\-]+$`)

// declaredTechs lists, sorted, the technologies any project or environment
// declares. Only these are judged, so only these are worth checking: the
// shipped catalog is verified by the project's own tests.
func declaredTechs(cfg *config.Bundle) []model.Tech {
	seen := map[string]bool{}
	for _, p := range cfg.Projects {
		for _, t := range p.Techs {
			seen[strings.ToLower(t.Name)] = true
		}
		for _, ec := range p.Environments {
			for name := range ec.Techs {
				seen[strings.ToLower(name)] = true
			}
		}
	}
	var out []model.Tech
	for _, t := range cfg.Techs {
		if seen[strings.ToLower(t.Name)] {
			out = append(out, t)
		}
	}
	return out
}

func checkTechs(ctx context.Context, r *Report, cfg *config.Bundle, g feeds.Getter) {
	if len(cfg.Techs) == 0 {
		r.add(gTechs, "techs", Warn, "no techs are configured, so nothing can match")
		return
	}
	bad, names := 0, 0
	for _, t := range cfg.Techs {
		for _, c := range t.CPE {
			names++
			if !cpeName.MatchString(c) {
				bad++
				r.add(gTechs, t.Name, Fail, "cpe %q must look like vendor:product, lowercase, with no wildcards", c)
			}
		}
	}
	if bad == 0 {
		r.add(gTechs, "names", OK, "%d techs, %d cpe names are well formed", len(cfg.Techs), names)
	}
	declared := declaredTechs(cfg)
	if len(declared) == 0 {
		r.add(gTechs, "declared", Warn, "no project declares a technology, so only package lockfiles can match")
	}
	var textOnly, distinct []string
	for _, t := range declared {
		if len(t.CPE) == 0 {
			textOnly = append(textOnly, t.Name)
		}
		for _, c := range t.CPE {
			if cpeName.MatchString(c) && !slices.Contains(distinct, c) {
				distinct = append(distinct, c)
			}
		}
	}
	if len(textOnly) > 0 {
		r.add(gTechs, "text-only techs", Skip, "declared techs with no cpe names, matched by words only: %s", strings.Join(textOnly, ", "))
	}
	if g == nil {
		r.add(gTechs, "NVD product names", Skip, "not checked in an offline run")
		return
	}
	for _, c := range distinct {
		checkCPE(ctx, r, g, c)
	}
}

// checkCPE asks the NVD CPE dictionary whether vendor:product exists. Network
// trouble is only a warning: it says nothing about the name.
func checkCPE(ctx context.Context, r *Report, g feeds.Getter, c string) {
	vendor, product, _ := strings.Cut(c, ":")
	u := fmt.Sprintf("%s?cpeMatchString=cpe:2.3:a:%s:%s:*:*:*:*:*:*:*:*&resultsPerPage=1",
		nvdCPEs, url.QueryEscape(vendor), url.QueryEscape(product))
	resp, err := g.Get(ctx, u, model.Validators{}, map[string]string{"Accept": "application/json"})
	if err != nil {
		r.add(gTechs, c, Warn, "could not check: %s", err)
		return
	}
	var body struct {
		Total *int `json:"totalResults"`
	}
	if err := json.Unmarshal(resp.Body, &body); err != nil || body.Total == nil {
		r.add(gTechs, c, Warn, "could not check: unexpected answer from NVD")
		return
	}
	if *body.Total == 0 {
		r.add(gTechs, c, Fail, "NVD has no product %s (a wrong name hides real advisories)", c)
		return
	}
	r.add(gTechs, c, OK, "known to NVD")
}

func checkSources(ctx context.Context, r *Report, cfg *config.Bundle, g feeds.Getter) {
	types := feeds.Types()
	for _, s := range cfg.Sources {
		switch {
		case !slices.Contains(types, s.Type):
			r.add(gSources, s.ID, Fail, "unknown type %q (use %s)", s.Type, strings.Join(types, ", "))
		case s.Disabled:
			r.add(gSources, s.ID, Skip, "disabled")
		case g == nil:
			r.add(gSources, s.ID, OK, "type %s%s", s.Type, tokenHint(s))
		default:
			items, _, err := feeds.Fetch(ctx, g, s, model.FeedState{}, time.Now(), cfg.Lookback)
			if err != nil {
				r.add(gSources, s.ID, Warn, "fetch failed: %s%s", err, tokenHint(s))
				continue
			}
			r.add(gSources, s.ID, OK, "fetched, %d items in the last %s%s", len(items), cfg.Lookback, tokenHint(s))
		}
	}
}

// tokenHint says whether the variable named by auth_env is set, never its value.
func tokenHint(s model.Source) string {
	switch {
	case s.AuthEnv == "":
		return ""
	case strings.TrimSpace(os.Getenv(s.AuthEnv)) != "":
		return "; " + s.AuthEnv + " set"
	case s.Type == "ghsa":
		return "; " + s.AuthEnv + " not set: GitHub allows 60 requests an hour without a token, 5000 with one"
	}
	return "; " + s.AuthEnv + " not set"
}

func checkInventory(r *Report, cfg *config.Bundle) {
	if len(cfg.Projects) == 0 {
		r.add(gInventory, "projects", Warn, "no projects: add config/projects/<name>.yaml so there is something to match")
		return
	}
	inv := inventory.Load(cfg)
	for _, p := range inv.Problems() {
		switch {
		case p.Err != "":
			r.add(gInventory, "lockfile", Fail, "%s", p)
		default:
			first := p.Skipped[:min(3, len(p.Skipped))]
			r.add(gInventory, "skipped entries", Warn, "%s: %s", p, strings.Join(first, "; "))
		}
	}
	empty := map[string]bool{}
	for _, p := range cfg.Projects {
		hasTechs := len(p.Techs) > 0
		for _, ec := range p.Environments {
			hasTechs = hasTechs || len(ec.Techs) > 0
		}
		if len(p.Lockfiles) == 0 && !hasTechs {
			empty[p.Name] = true
			r.add(gInventory, p.Name, Warn, "nothing to match: no lockfiles and no techs")
		}
	}
	for _, t := range inv.Targets() {
		if empty[t.Project] {
			continue
		}
		r.add(gInventory, fmt.Sprintf("%s/%s", t.Project, t.Env), OK, "%d techs, %d packages", len(t.Techs), len(t.Packages))
	}
}

func checkState(r *Report, cfg *config.Bundle) {
	for _, d := range []struct{ name, dir string }{{"data directory", cfg.DataDir}, {"alerts directory", cfg.AlertsDir}} {
		if err := writable(d.dir); err != nil {
			r.add(gState, d.name, Fail, "%s is not writable: %s", d.dir, err)
		} else {
			r.add(gState, d.name, OK, "%s", d.dir)
		}
	}
	st, err := store.Open(cfg.Storage.Backend, cfg.DataDir)
	if errors.Is(err, store.ErrBusy) {
		r.add(gState, "state", Warn, "another cvewatch process holds the data (is the daemon running?)")
		return
	}
	if err != nil {
		r.add(gState, "state", Fail, "cannot open the %s store: %s", pick(cfg.Storage.Backend == "", "file", cfg.Storage.Backend), err)
		return
	}
	defer st.Close()
	s, err := st.Load()
	if err != nil {
		r.add(gState, "state", Fail, "cannot read the state: %s", err)
		return
	}
	version := s.SchemaVersion
	if version == 0 && len(s.Vulns)+len(s.Findings) == 0 {
		version = ledger.SchemaVersion // nothing stored yet
	}
	switch {
	case version > ledger.SchemaVersion:
		r.add(gState, "state", Fail, "schema version %d is newer than this cvewatch understands (%d)", version, ledger.SchemaVersion)
	default:
		r.add(gState, "state", OK, "%d vulnerabilities, %d findings, schema version %d", len(s.Vulns), len(s.Findings), version)
	}
}

// writable creates dir if needed and proves a file can be written there.
func writable(dir string) error {
	if err := host.MkdirPrivate(dir); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".doctor-*")
	if err != nil {
		return err
	}
	name := f.Name()
	_, werr := f.WriteString("ok")
	cerr := f.Close()
	rerr := os.Remove(name)
	return errors.Join(werr, cerr, rerr)
}

func checkAudit(r *Report, cfg *config.Bundle) {
	n, err := audit.Open(cfg.DataDir).Verify()
	switch {
	case err != nil:
		r.add(gAudit, "log", Fail, "audit log damaged: %s", err)
	case n == 0:
		r.add(gAudit, "log", OK, "empty")
	default:
		r.add(gAudit, "log", OK, "%d records, chain intact", n)
	}
}

func checkNotify(r *Report, cfg *config.Bundle) {
	active := 0
	for _, e := range notify.FromConfig(cfg) {
		switch {
		case !e.Configured:
			r.add(gNotify, e.Name, Skip, "not configured%s", e.Hint)
		case e.Err != nil:
			r.add(gNotify, e.Name, Fail, "%s", e.Err)
		default:
			active++
			r.add(gNotify, e.Name, OK, "active")
		}
	}

	if active == 0 {
		r.add(gNotify, "channels", Warn, "no notification channel is active: findings are only listed, nobody is alerted")
		if at := cfg.Notify.Digest.DailyAt; at != "" {
			r.add(gNotify, "digest", Warn, "a digest is set for %s but no channel is active to send it", at)
		}
	}
}

func checkPolicy(r *Report, cfg *config.Bundle) {
	if len(cfg.Policy.Rules) == 0 {
		r.add(gPolicy, "rules", Skip, "no policy rules")
		return
	}
	for _, p := range cfg.Policy.Rules {
		parts := []string{"every environment"}
		if p.Env != "" {
			parts[0] = "environment " + string(p.Env)
		}
		if p.KEV {
			parts = append(parts, "CISA KEV only")
		}
		if p.MinSeverity != "" {
			parts = append(parts, "severity "+string(p.MinSeverity)+" or worse")
		}
		if p.OwnerWithin > 0 {
			parts = append(parts, "owner within "+p.OwnerWithin.String())
		}
		if p.FixWithin > 0 {
			parts = append(parts, "fixed within "+p.FixWithin.String())
		}
		r.add(gPolicy, p.Name, OK, "%s", strings.Join(parts, ", "))
	}
}

// checkUpdates says how the projects are kept up to date, and warns when the
// schedule leaves some of them out.
func checkUpdates(r *Report, cfg *config.Bundle) {
	if len(cfg.Projects) == 0 {
		return
	}
	if !cfg.Update.Auto {
		r.add(gConfig, "updates", Warn, "update.auto is off: nothing is refreshed by itself; run cvewatch update or press u in the TUI")
		return
	}
	var paused []string
	for _, p := range cfg.Projects {
		if !p.AutoUpdate() {
			paused = append(paused, p.Name)
		}
	}
	if len(paused) > 0 {
		r.add(gConfig, "updates", Warn, "scheduled runs skip %s (update.auto: false in the project file); run cvewatch update or press u in the TUI to refresh them", strings.Join(paused, ", "))
		return
	}
	r.add(gConfig, "updates", OK, "%d projects refreshed on their own schedule, by default every %s", len(cfg.Projects), model.Span(cfg.Interval))
}
