package ledger

import (
	"testing"
	"time"

	"github.com/b070nd/cvewatch/app/src/model"
)

var day = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

func item(title, url, src string, ids ...string) model.Item {
	return model.Item{SourceID: src, SourceType: "rss", Title: title, URL: url, IDs: ids, Published: day, Severity: model.SevUnknown}
}

func TestStatusSurvivesAddFinding(t *testing.T) {
	l := New(State{})
	v := l.Create(item("PHP bug", "https://a.test/1", "s", "CVE-2026-1", "GHSA-AAAA-BBBB-CCCC"), day, []string{"php"})
	f := model.Finding{VulnID: v.ID, Project: "shop", Env: model.EnvProd, Status: model.StatusOpen}
	if !l.AddFinding(f) || l.AddFinding(f) {
		t.Fatal("AddFinding must insert once")
	}
	if _, err := l.SetStatus(v.ID, "shop", model.EnvProd, model.StatusFixed, "patched", day); err != nil {
		t.Fatal(err)
	}
	re := New(l.State()) // a reload keeps aliases and status
	if re.Lookup([]string{"GHSA-AAAA-BBBB-CCCC"}) == nil || re.AddFinding(f) || re.Findings()[0].Status != model.StatusFixed {
		t.Fatal("state lost across reload")
	}
	if _, err := re.SetStatus("CVE-nope", "shop", "", model.StatusFixed, "", day); err == nil {
		t.Fatal("unknown finding must error")
	}
}

func TestAdvisoryBridgingGHSAAndCVEUnifies(t *testing.T) {
	l := New(State{})
	a := l.Create(item("GHSA only advisory", "https://a.test/g", "ghsa", "GHSA-AAAA-BBBB-CCCC"), day, nil)
	b := l.Create(item("CVE only record", "https://a.test/c", "nvd", "CVE-2026-9999"), day.Add(time.Hour), nil)
	l.AddFinding(model.Finding{VulnID: b.ID, Project: "shop", Env: model.EnvProd, Status: model.StatusOpen})

	bridge := item("GHSA names its CVE", "https://a.test/n", "ghsa", "CVE-2026-9999", "GHSA-AAAA-BBBB-CCCC")
	bridge.SourceType = "ghsa"
	got, gone, _ := l.Identify(bridge, false)
	if got != a || len(gone) != 1 || gone[0] != b {
		t.Fatalf("an advisory naming both ids must unify into the older record: %v %v", got, gone)
	}
	if l.Vuln(b.ID) != nil || l.Lookup([]string{"CVE-2026-9999"}) != a {
		t.Fatal("ids must now resolve to the surviving record")
	}
	if fs := l.FindingsOf(a.ID); len(fs) != 1 || fs[0].VulnID != a.ID {
		t.Fatalf("findings must move to the survivor: %+v", fs)
	}
}

func TestRoundupArticleLinksButNeverMerges(t *testing.T) {
	l := New(State{})
	a := l.Create(item("PHP memory corruption", "https://a.test/1", "kev", "CVE-2026-1001"), day, nil)
	b := l.Create(item("PHP stale request state", "https://a.test/2", "kev", "CVE-2026-1002"), day, nil)
	roundup := item("Two PHP flaws exploited", "https://news.test/two", "hn", "CVE-2026-1001", "CVE-2026-1002")
	got, gone, linked := l.Identify(roundup, true)
	if got != a || len(gone) != 0 || len(linked) != 1 || linked[0] != b {
		t.Fatalf("a roundup must not unify: %v %v %v", got, gone, linked)
	}
	if l.Vuln(b.ID) == nil || len(b.Refs) != 2 {
		t.Fatalf("both records must stay and both must list the article: %+v", b.Refs)
	}
}

func TestSimilarOnlyMergesRelevantIntoRelevant(t *testing.T) {
	l := New(State{})
	base := l.Create(item("PHP-FPM remote code execution lets attackers run arbitrary code", "https://a.test/1", "nvd", "CVE-2026-3"), day, []string{"php"})
	l.AddFinding(model.Finding{VulnID: base.ID, Project: "shop", Env: model.EnvProd, Status: model.StatusOpen})

	news := item("Critical PHP-FPM remote code execution flaw lets attackers run arbitrary code", "https://b.test/2", "hn")
	if v, _, _ := l.Identify(news, false); v != nil {
		t.Fatal("irrelevant items must never merge")
	}
	if v, _, _ := l.Identify(news, true); v != base {
		t.Fatal("relevant news must join the tracked issue")
	}
	old := news
	old.Published = day.AddDate(0, 0, -30)
	if v, _, _ := l.Identify(old, true); v != nil {
		t.Fatal("reports a month apart are not the same issue")
	}
}

func TestAbsorbCollectsArticlesRangesAndFixes(t *testing.T) {
	l := New(State{})
	v := l.Create(item("PHP bug", "https://a.test/1", "hn", "CVE-2026-5"), day, nil)

	adv := item("CVE-2026-5: PHP bug", "https://nvd.test/5", "nvd", "CVE-2026-5")
	adv.SourceType = "nvd"
	adv.Severity = model.SevHigh
	adv.Affected = []model.Affected{{Ecosystem: "cpe", Name: "php:php", Ranges: []model.Range{{Max: "8.2.30", MaxExcl: true}}}}
	adv.Fixes = []model.Fix{{Kind: model.FixVersion, Detail: "8.2.30", Source: "nvd", Official: true}}
	if c := l.Absorb(v, adv); !c.Any || !c.Evidence || v.Severity != model.SevHigh || len(v.Affected) != 1 || len(v.Fixes) != 1 || len(v.Refs) != 2 {
		t.Fatalf("absorb lost data: %+v", v)
	}
	if c := l.Absorb(v, adv); c.Any || c.Evidence {
		t.Fatal("absorbing the same item twice must change nothing")
	}
	if v.Refs[0].Kind != model.RefArticle || v.Refs[1].Kind != model.RefAdvisory {
		t.Fatalf("ref kinds: %+v", v.Refs)
	}
}

func TestPruneKeepsFindingsAndDropsOldNoise(t *testing.T) {
	l := New(State{})
	now := time.Now()
	l.Create(item("old noise", "https://a.test/1", "s", "CVE-2026-1001"), now.AddDate(0, 0, -400), nil)
	l.Create(item("new noise", "https://a.test/2", "s", "CVE-2026-1002"), now, nil)
	l.Create(item("old real", "https://a.test/3", "s", "CVE-2026-1003"), now.AddDate(0, 0, -400), nil)
	l.AddFinding(model.Finding{VulnID: "CVE-2026-1003", Project: "p", Env: model.EnvProd, Status: model.StatusOpen})
	if n := l.Prune(now.AddDate(0, 0, -180)); n != 1 {
		t.Fatalf("pruned %d", n)
	}
	if l.Vuln("CVE-2026-1001") != nil || l.Lookup([]string{"CVE-2026-1001"}) != nil || l.Vuln("CVE-2026-1003") == nil || l.Vuln("CVE-2026-1002") == nil {
		t.Fatal("wrong records pruned")
	}
}

func TestSimilar(t *testing.T) {
	same := [][2]string{
		{"CVE-2026-1: launch-editor allows users to open files with line numbers outside the project",
			"CVE-2026-2: launch-editor allows users to open files with line numbers outside the project root"},
		{"Critical PHP flaw lets attackers run code remotely", "PHP flaw lets remote attackers run code, critical"},
	}
	for _, c := range same {
		if !Similar(c[0], c[1]) {
			t.Errorf("should merge: %q / %q", c[0], c[1])
		}
	}
	diff := [][2]string{
		{"ApostropheCMS content management stored XSS in media library", "ApostropheCMS content management SQL injection in search endpoint"},
		{"PHP RCE", "PHP RCE"},
		{"PHP2Shell exploitation attempts continue amid suspected hackers", "PHP warns of another unpatched RCE risk after emergency patch"},
	}
	for _, c := range diff {
		if Similar(c[0], c[1]) {
			t.Errorf("should stay apart: %q / %q", c[0], c[1])
		}
	}
}

func TestRenameProjectMovesFindingsAndRefusesCollisions(t *testing.T) {
	l := New(State{})
	v := l.Create(item("PHP bug", "https://a.test/1", "s", "CVE-2026-1"), day, []string{"php"})
	for _, p := range []string{"shop", "other"} {
		for _, e := range []model.Env{model.EnvDev, model.EnvProd} {
			l.AddFinding(model.Finding{VulnID: v.ID, Project: p, Env: e, Status: model.StatusOpen})
		}
	}
	if _, err := l.RenameProject("shop", "other"); err == nil {
		t.Fatal("a rename onto findings with the same keys must fail")
	}
	if n := len(l.Findings()); n != 4 || l.Findings()[3].Project != "shop" {
		t.Fatalf("a failed rename changed something: %+v", l.Findings())
	}
	if _, err := l.SetStatus(v.ID, "shop", model.EnvProd, model.StatusFixed, "done", day); err != nil {
		t.Fatal(err)
	}
	n, err := l.RenameProject("shop", "webshop")
	if err != nil || n != 2 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	var got []string
	for _, f := range l.Findings() {
		got = append(got, f.Project+"/"+string(f.Env)+"/"+string(f.Status))
	}
	if len(got) != 4 || got[2] != "webshop/dev/open" || got[3] != "webshop/prod/fixed" {
		t.Fatalf("got %v", got)
	}
	if n, err := New(l.State()).RenameProject("shop", "x"); err != nil || n != 0 {
		t.Fatalf("nothing left under the old name: %d %v", n, err)
	}
}

func TestRenameEnvMovesFindingsAndRefusesCollisions(t *testing.T) {
	l := New(State{})
	v := l.Create(item("PHP bug", "https://a.test/1", "s", "CVE-2026-1"), day, []string{"php"})
	for _, p := range []string{"shop", "other"} {
		for _, e := range []model.Env{model.EnvDev, model.EnvProd, "qa"} {
			l.AddFinding(model.Finding{VulnID: v.ID, Project: p, Env: e, Status: model.StatusOpen})
		}
	}
	if _, err := l.SetStatus(v.ID, "shop", "qa", model.StatusFixed, "done", day); err != nil {
		t.Fatal(err)
	}
	if n, err := l.EnvMove("shop", "qa", "prod"); err == nil || n != 0 {
		t.Fatalf("the check should find prod in the way: %d %v", n, err)
	}
	if _, err := l.RenameEnv("shop", "qa", "prod"); err == nil {
		t.Fatal("a rename onto an environment with the same finding must fail")
	}
	n, err := l.RenameEnv("shop", "qa", "uat")
	if err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	var got []string
	for _, f := range l.Findings() {
		got = append(got, f.Project+"/"+string(f.Env)+"/"+string(f.Status))
	}
	// the suggested names sort first, the others after them by name
	want := []string{"other/dev/open", "other/prod/open", "other/qa/open", "shop/dev/open", "shop/prod/open", "shop/uat/fixed"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	if l.Findings()[5].Env != "uat" || l.Lookup([]string{"CVE-2026-1"}) == nil {
		t.Error("state inconsistent")
	}
}
