package pipeline_test

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/pipeline"
	"github.com/b070nd/cvewatch/app/src/testkit"
)

const (
	phpProject   = "name: shop\nenvs: [prod]\ntechs: [{name: php, version: '8.2'}]\n"
	redisTechs   = "techs:\n  - name: php\n  - name: redis\n"
	phpAndRedis  = "name: shop\nenvs: [prod]\ntechs: [{name: php, version: '8.2'}, {name: redis}]\n"
	phpSince2024 = "name: shop\nenvs: [prod]\nsince: 2024-01-01\ntechs: [{name: php, version: '8.2'}]\n"
)

func quiet(t *testing.T, project, techs string) *testkit.Rig {
	t.Helper()
	return rig(t, techs, map[string]string{"shop": project}, nil)
}

// seed stores a record the way a cycle leaves it, as a tracked or an irrelevant one.
func seed(g *testkit.Rig, id, title string, published time.Time, status model.Status) {
	v := g.Ledger.Create(model.Item{Title: title, URL: "https://ex.test/" + id, IDs: []string{id}, Published: published,
		SourceID: "feed", SourceType: "rss"}, g.Now, nil)
	if status != "" {
		g.Ledger.AddFinding(model.Finding{VulnID: v.ID, Project: "shop", Env: model.EnvProd, Status: status, Applies: model.AppUnknown,
			Installed: []model.Installed{{Name: "php", Version: "8.2", Via: "tech"}}, Matched: []string{"php@8.2"}})
	}
}

var (
	oldDay = time.Date(2023, 6, 1, 0, 0, 0, 0, time.UTC)
	newDay = time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC)
)

func revalidate(t *testing.T, g *testkit.Rig, apply bool) pipeline.Revalidation {
	t.Helper()
	rv, err := g.Runner.Revalidate(apply)
	if err != nil {
		t.Fatal(err)
	}
	return rv
}

func TestRevalidateCreatesFindingsForANewTech(t *testing.T) {
	g := quiet(t, phpProject, redisTechs)
	seed(g, "CVE-2026-5001", "Redis Lua sandbox escape", newDay, "") // stored irrelevant while nobody ran redis
	seed(g, "CVE-2026-5002", "Pasta recipes", newDay, "")
	if rv := revalidate(t, g, true); rv.NewFindings != 0 || !rv.Applied {
		t.Fatalf("nothing runs redis yet: %+v", rv)
	}

	g.Write("config/projects/shop.yaml", phpAndRedis)
	g.Reload()
	pre := revalidate(t, g, false)
	if pre.Applied || pre.NewFindings != 1 || len(pre.Changes) != 1 || pre.Changes[0].ID != "CVE-2026-5001" || pre.Changes[0].Action != "new" {
		t.Fatalf("preview: %+v", pre)
	}
	if len(g.Findings("CVE-2026-5001")) != 0 || g.Ledger.Judged().Hash == "" {
		t.Fatal("a preview must not change anything")
	}
	if g.Ledger.Judged().Projects["shop"].Techs[len(g.Ledger.Judged().Projects["shop"].Techs)-1] == "redis" {
		t.Fatal("a preview must not record the new judging")
	}

	done := revalidate(t, g, true)
	if done.NewFindings != 1 || done.Unchanged != 0 || len(g.Findings("CVE-2026-5001")) != 1 {
		t.Fatalf("apply: %+v", done)
	}
	if v := g.Ledger.Vuln("CVE-2026-5001"); len(v.Techs) != 1 || v.Techs[0] != "redis" {
		t.Errorf("techs = %v", v.Techs)
	}
	if again := revalidate(t, g, true); again.NewFindings+again.Closed+again.Reopened+again.Reconciled != 0 || again.Unchanged != 1 {
		t.Fatalf("a second run changes nothing: %+v", again)
	}
	n, err := g.Runner.Audit.Verify()
	if err != nil || n != 4 { // three applied runs, one event each, and the finding the second one created; the preview wrote none
		t.Fatalf("audit n=%d err=%v", n, err)
	}
}

func TestRevalidateAppliesSinceToExistingFindingsAndUndoesOnlyItsOwn(t *testing.T) {
	g := quiet(t, phpProject, redisTechs)
	seed(g, "CVE-2023-1", "PHP-FPM overflow", oldDay, model.StatusOpen)
	seed(g, "CVE-2023-2", "PHP stream bug", oldDay, model.StatusFixed)
	seed(g, "CVE-2023-3", "PHP parser bug", oldDay, model.StatusOpen)
	seed(g, "CVE-2025-1", "PHP-FPM newer bug", newDay, model.StatusOpen)
	g.Ledger.SetStatus("CVE-2023-3", "shop", model.EnvProd, model.StatusIgnored, "accepted", g.Now) // a person decided
	revalidate(t, g, true)

	g.Write("config/projects/shop.yaml", phpSince2024)
	g.Reload()
	pre := revalidate(t, g, false)
	if pre.Closed != 1 || pre.Changes[0].Action != "closed" || pre.Changes[0].ID != "CVE-2023-1" {
		t.Fatalf("preview: %+v", pre)
	}
	if g.Findings("CVE-2023-1")[0].Status != model.StatusOpen {
		t.Fatal("a preview must not close anything")
	}

	rv := revalidate(t, g, true)
	if rv.Closed != 1 || rv.Unchanged != 3 {
		t.Fatalf("apply: %+v", rv)
	}
	f := g.Findings("CVE-2023-1")[0]
	if f.Status != model.StatusNotAffected || !f.Auto || f.Note != "published before this project's since date (2024-01-01); closed automatically" {
		t.Fatalf("auto-closed finding: %+v", f)
	}
	if h := f.History[len(f.History)-1]; h.Actor != "cvewatch" || h.Status != model.StatusNotAffected {
		t.Errorf("history = %+v", h)
	}
	for id, want := range map[string]model.Status{"CVE-2023-2": model.StatusFixed, "CVE-2023-3": model.StatusIgnored, "CVE-2025-1": model.StatusOpen} {
		if got := g.Findings(id)[0]; got.Status != want || got.Auto {
			t.Errorf("%s: %+v, want %s untouched", id, got, want)
		}
	}
	if again := revalidate(t, g, true); again.Closed != 0 || again.Unchanged != 4 {
		t.Fatalf("idempotent: %+v", again)
	}

	// A person takes over the closed finding: the date moving later must not reopen it.
	g.Ledger.SetStatus("CVE-2023-1", "shop", model.EnvProd, model.StatusNotAffected, "checked: not exposed", g.Now)
	if g.Findings("CVE-2023-1")[0].Auto {
		t.Fatal("a person's status clears the automatic marker")
	}
	g.Write("config/projects/shop.yaml", phpProject)
	g.Reload()
	if rv := revalidate(t, g, true); rv.Reopened != 0 || g.Findings("CVE-2023-1")[0].Status != model.StatusNotAffected {
		t.Fatalf("a manual status is never touched: %+v", rv)
	}
}

func TestRevalidateReopensWhatSinceClosedWhenTheDateMovesEarlier(t *testing.T) {
	g := quiet(t, phpSince2024, redisTechs)
	seed(g, "CVE-2023-1", "PHP-FPM overflow", oldDay, model.StatusOpen)
	seed(g, "CVE-2023-2", "PHP stream bug", oldDay, model.StatusOpen)
	revalidate(t, g, true)
	if g.Findings("CVE-2023-1")[0].Status != model.StatusNotAffected {
		t.Fatal("setup: not closed")
	}

	g.Write("config/projects/shop.yaml", strings.Replace(phpSince2024, "2024-01-01", "2023-01-01", 1))
	g.Reload()
	rv := revalidate(t, g, true)
	if rv.Reopened != 2 || rv.Closed != 0 {
		t.Fatalf("both predate 2024 and follow 2023: %+v", rv)
	}
	f := g.Findings("CVE-2023-1")[0]
	if f.Status != model.StatusOpen || f.Auto || f.Note != "" {
		t.Fatalf("reopened finding: %+v", f)
	}

	g.Write("config/projects/shop.yaml", phpSince2024)
	g.Reload()
	if rv := revalidate(t, g, true); rv.Closed != 2 {
		t.Fatalf("closing again: %+v", rv)
	}
	g.Write("config/projects/shop.yaml", phpProject) // since removed
	g.Reload()
	if rv := revalidate(t, g, true); rv.Reopened != 2 {
		t.Fatalf("since removed: %+v", rv)
	}
}

func TestRevalidateRechecksAfterATechIsRemoved(t *testing.T) {
	g := quiet(t, phpAndRedis, redisTechs)
	seed(g, "CVE-2026-1", "PHP-FPM overflow", newDay, model.StatusOpen)
	revalidate(t, g, true)

	g.Write("config/projects/shop.yaml", "name: shop\nenvs: [prod]\ntechs: [{name: redis}]\n")
	g.Reload()
	rv := revalidate(t, g, true)
	f := g.Findings("CVE-2026-1")[0]
	if rv.Reconciled != 1 || f.Applies != model.AppNotAffected || f.Status != model.StatusOpen || len(f.History) == 0 {
		t.Fatalf("%+v %+v", rv, f)
	}
}

func TestCycleRevalidatesWhenTheConfigChangesAndNotForAComment(t *testing.T) {
	g := quiet(t, phpProject, redisTechs)
	seed(g, "CVE-2026-5001", "Redis Lua sandbox escape", newDay, "")
	if res := g.Run(); res.Revalidation == nil || res.Revalidation.NewFindings != 0 {
		t.Fatalf("the first cycle records what it judged: %+v", res.Revalidation)
	}
	if res := g.Run(); res.Revalidation != nil {
		t.Fatalf("nothing changed: %+v", res.Revalidation)
	}

	g.Write("config/projects/shop.yaml", "# redis too, soon\n"+phpProject)
	g.Reload()
	if res := g.Run(); res.Revalidation != nil {
		t.Fatalf("a comment is not a change: %+v", res.Revalidation)
	}

	g.Write("config/projects/shop.yaml", phpAndRedis)
	g.Reload()
	res := g.Run()
	if res.Revalidation == nil || res.Revalidation.NewFindings != 1 || res.Findings != 1 || res.Items != 0 {
		t.Fatalf("an edited project is re-judged without new items: %+v", res)
	}
	if len(g.Findings("CVE-2026-5001")) != 1 {
		t.Fatal("finding missing")
	}
	if res.Alerted != 1 {
		t.Errorf("the new finding is alerted in the same cycle: %+v", res)
	}
}

func TestIrrelevantRecordsKeepWhatARevalidationNeeds(t *testing.T) {
	g := rig(t, "techs:\n  - name: php\n  - name: redis\n    cpe: [redislabs:redis]\n", map[string]string{"shop": phpProject},
		map[string]string{nvdURL: nvdBody("CVE-2026-7001", "Redis Lua flaw. "+strings.Repeat("filler ", 300), "redislabs:redis", "7.2.5")})
	res := g.Run()
	v := g.Ledger.Vuln("CVE-2026-7001")
	if res.New != 1 || v == nil || len(g.Findings("CVE-2026-7001")) != 0 {
		t.Fatalf("irrelevant at first: %+v %+v", res, v)
	}
	if len(v.Affected) == 0 || v.Summary == "" || len([]rune(v.Summary)) > 400 {
		t.Fatalf("an irrelevant record keeps its product data and a short summary: %q %+v", v.Summary, v.Affected)
	}

	g.Write("config/projects/shop.yaml", "name: shop\nenvs: [prod]\ntechs: [{name: php, version: '8.2'}, {name: redis, version: '7.2.1'}]\n")
	g.Reload()
	res = g.Run()
	fs := g.Findings("CVE-2026-7001")
	if res.Revalidation == nil || len(fs) != 1 || fs[0].Applies != model.AppAffected {
		t.Fatalf("version 7.2.1 is below 7.2.5 and must be flagged from the stored product data: %+v %+v", res.Revalidation, fs)
	}
}

const nvdWindowed = "sources:\n  - {id: feed, type: rss, url: '" + feedURL + "'}\n  - {id: nvd, type: nvd, url: 'https://ex.test/nvd?s={since}&e={now}'}\n  - {id: kev, type: kev, url: '" + kevURL + "'}\n"

func TestBackfillReachesBackToTheSinceDateOnce(t *testing.T) {
	g := testkit.NewRig(t, map[string]string{
		"config/techs.yaml":          redisTechs,
		"sources/s.yaml":             nvdWindowed,
		"config/projects/shop.yaml":  phpSince2024,
		"config/projects/shop2.yaml": "name: shop2\nenvs: [prod]\ntechs: [{name: php}]\n",
	}, map[string]string{feedURL: rss})
	var chunks []pipeline.Progress
	g.Runner.Progress = func(p pipeline.Progress) {
		if p.Chunk > 0 {
			chunks = append(chunks, p)
		}
	}
	res := g.Run()
	// 2024-01-01 to 2026-10-27 is 1030 days: nine NVD windows of at most 119 days.
	var nvdAsked int
	for _, u := range g.Getter.Asked {
		if strings.HasPrefix(u, "https://ex.test/nvd?") {
			nvdAsked++
		}
	}
	if nvdAsked != 9 || len(chunks) != 9 || chunks[8].Chunk != 9 || chunks[8].Chunks != 9 || chunks[0].Source != "nvd" {
		t.Fatalf("nvd requests = %d, progress = %+v", nvdAsked, chunks)
	}
	if !strings.Contains(strings.Join(res.Backfilled, ","), "nvd") || !strings.Contains(strings.Join(res.Backfilled, ","), "feed") {
		t.Fatalf("backfilled = %v", res.Backfilled)
	}
	if len(res.Notes) != 1 || !strings.Contains(res.Notes[0], "cannot go back for") || !strings.Contains(res.Notes[0], "feed") || len(res.Failed) != 0 {
		t.Fatalf("an rss feed is informational, not an error: notes=%v failed=%v", res.Notes, res.Failed)
	}
	st := g.Ledger.Feed("nvd")
	if !st.Backfill.IsZero() || !st.Covered.Equal(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("feed state after the back-fill: %+v", st)
	}

	g.Getter.Asked = nil
	res = g.Run()
	nvdAsked = 0
	for _, u := range g.Getter.Asked {
		if strings.HasPrefix(u, "https://ex.test/nvd?") {
			nvdAsked++
		}
	}
	if len(res.Backfilled) != 0 || len(res.Notes) != 0 || nvdAsked != 1 {
		t.Fatalf("the second cycle reaches back no more: %+v notes=%v nvd requests=%d", res.Backfilled, res.Notes, nvdAsked)
	}
}

func TestBackfillOnlyPollsTheSourcesThatOweOne(t *testing.T) {
	g := testkit.NewRig(t, map[string]string{
		"config/techs.yaml": redisTechs, "sources/s.yaml": nvdWindowed, "config/projects/shop.yaml": phpProject,
	}, map[string]string{feedURL: rss})
	g.Run()
	g.Getter.Asked = nil
	g.Runner.BackfillOnly = true
	if res, err := g.Runner.Run(context.Background()); err != nil || res.Items != 0 || len(g.Getter.Asked) != 0 {
		t.Fatalf("nothing owed: %+v asked=%v err=%v", res, g.Getter.Asked, err)
	}

	st := g.Ledger.Feed("kev")
	st.Backfill = g.Now.AddDate(0, 0, -400)
	g.Ledger.SetFeed("kev", st)
	res, err := g.Runner.Run(context.Background())
	if err != nil || len(g.Getter.Asked) != 1 || g.Getter.Asked[0] != kevURL || len(res.Backfilled) != 1 {
		t.Fatalf("only kev is owed: %+v asked=%v err=%v", res, g.Getter.Asked, err)
	}
	if !g.Ledger.Feed("kev").Backfill.IsZero() {
		t.Error("a successful fetch clears the back-fill")
	}
}

func TestFailedBackfillStaysOwed(t *testing.T) {
	g := testkit.NewRig(t, map[string]string{
		"config/techs.yaml": redisTechs, "sources/s.yaml": nvdWindowed, "config/projects/shop.yaml": phpSince2024,
	}, map[string]string{feedURL: rss})
	g.Getter.Errs = map[string]error{kevURL: context.DeadlineExceeded}
	res := g.Run()
	if len(res.Failed) != 1 || g.Ledger.Feed("kev").Backfill.IsZero() {
		t.Fatalf("kev failed and must keep owing its back-fill: %+v %+v", res.Failed, g.Ledger.Feed("kev"))
	}
	delete(g.Getter.Errs, kevURL)
	g.Run()
	if !g.Ledger.Feed("kev").Backfill.IsZero() {
		t.Error("the retry clears it")
	}
}

func TestStoppedBackfillKeepsFinishedWindowsAndResumes(t *testing.T) {
	files := map[string]string{
		"config/techs.yaml": redisTechs, "sources/s.yaml": nvdWindowed, "config/projects/shop.yaml": phpSince2024,
	}
	nvdURLs := func(g *testkit.Rig) []string {
		var out []string
		for _, u := range g.Getter.Asked {
			if strings.HasPrefix(u, "https://ex.test/nvd?") {
				out = append(out, u)
			}
		}
		return out
	}
	probe := testkit.NewRig(t, files, map[string]string{feedURL: rss})
	probe.Run()
	windows := nvdURLs(probe)
	if len(windows) != 9 {
		t.Fatalf("windows = %d", len(windows))
	}

	g := testkit.NewRig(t, files, map[string]string{feedURL: rss})
	g.Getter.Errs = map[string]error{windows[4]: context.Canceled}
	res := g.Run()
	st := g.Ledger.Feed("nvd")
	if len(res.Failed) != 1 {
		t.Fatalf("nvd stopped: failed=%v", res.Failed)
	}
	// the cursor moved to the window that failed: the four before it are not fetched again
	if want := "s=" + st.LastRun.UTC().Format("2006-01-02"); !st.Backfill.IsZero() || !strings.Contains(windows[4], want) {
		t.Fatalf("it resumes at the window that failed: %s in %s, state=%+v", want, windows[4], st)
	}

	delete(g.Getter.Errs, windows[4])
	g.Getter.Asked = nil
	res = g.Run()
	if got := len(nvdURLs(g)); got != 5 || len(res.Failed) != 0 || !g.Ledger.Feed("nvd").Backfill.IsZero() {
		t.Fatalf("the next run fetches the 5 windows left, not 9: asked=%d failed=%v state=%+v", got, res.Failed, g.Ledger.Feed("nvd"))
	}
}

func TestRevalidateSaysWhatItIsDoing(t *testing.T) {
	g := quiet(t, phpProject, redisTechs)
	for _, id := range []string{"CVE-2026-6001", "CVE-2026-6002", "CVE-2026-6003"} {
		seed(g, id, "Pasta recipes "+id, newDay, "")
	}
	var buf bytes.Buffer
	g.Runner.Log = slog.New(slog.NewTextHandler(&buf, nil))
	defer pipeline.SetHeartbeat(0)()
	revalidate(t, g, false)
	out := buf.String()
	for _, want := range []string{"msg=revalidating", "advisories=3", "msg=\"still judging stored advisories\"", " of=3", "msg=revalidated", "elapsed="} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
}
