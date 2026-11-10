package pipeline_test

import (
	"strings"
	"testing"

	"github.com/b070nd/cvewatch/app/src/model"
)

const (
	phpCPETechs = "techs:\n  - name: php\n    cpe: [php:php]\n  - name: redis\n"
	twoTechs    = "name: shop\nenvs: [prod]\ntechs: [{name: php, version: '8.2'}, {name: redis, version: '7.2'}]\n"
)

func cpe(name string) model.Affected { return model.Affected{Ecosystem: model.EcoCPE, Name: name} }

func only(t *testing.T, fs []model.Finding) model.Finding {
	t.Helper()
	if len(fs) != 1 {
		t.Fatalf("want one finding, got %+v", fs)
	}
	return fs[0]
}

// A text match is retired when the advisory's own product data arrives and
// names something else, and comes back when that data names the tech after all.
func TestADisprovedMatchIsRetiredAndComesBack(t *testing.T) {
	g := quiet(t, phpProject, phpCPETechs)
	seed(g, "CVE-2026-7001", "PHP code injection in a gallery", newDay, "")
	if rv := revalidate(t, g, true); rv.NewFindings != 1 {
		t.Fatalf("the title names PHP: %+v", rv)
	}
	f := only(t, g.Findings("CVE-2026-7001"))
	if len(f.Installed) != 1 || len(f.Installed[0].Basis) != 1 || f.Installed[0].Basis[0] != model.BasisTitle || !f.WeakOnly() {
		t.Fatalf("the match must say it rests on the title: %+v", f.Installed)
	}
	g.Ledger.Mutate(f.Key(), func(m *model.Finding) { m.Owner, m.Ticket = "alice", "T-1" })

	v := g.Ledger.Vuln("CVE-2026-7001")
	v.Affected = []model.Affected{cpe("moodle:moodle")} // NVD analysed it: it is about Moodle
	rv := revalidate(t, g, true)
	f = only(t, g.Findings("CVE-2026-7001"))
	if rv.Retired != 1 || f.Retired != model.RetiredUnmatched || f.Status != model.StatusOpen || len(f.Installed) != 0 ||
		f.Applies != model.AppNotAffected || !strings.HasPrefix(f.Reasons[0], "no longer matched: php@8.2") {
		t.Fatalf("retired on proof: %+v %+v", rv, f)
	}
	if f.Owner != "alice" || f.Ticket != "T-1" {
		t.Fatalf("what a person set must stay: %+v", f)
	}
	history := len(f.History)
	if rv := revalidate(t, g, true); rv.Retired != 0 || rv.Reconciled != 0 || len(only(t, g.Findings("CVE-2026-7001")).History) != history {
		t.Fatalf("a second run has nothing to do: %+v", rv)
	}

	v.Affected = append(v.Affected, cpe("php:php"))
	revalidate(t, g, true)
	f = only(t, g.Findings("CVE-2026-7001"))
	if f.Retired != "" || len(f.Installed) != 1 || f.Installed[0].Basis[0] != model.BasisCPE || f.Applies != model.AppUnknown ||
		!strings.HasPrefix(f.History[len(f.History)-1].Note, "matches again: php@8.2") {
		t.Fatalf("the match is back, now on product data: %+v", f)
	}
}

// Silence proves nothing: a record that merely does not reproduce a match
// leaves the finding alone, and so does a decision a person took.
func TestOnlyProofRetires(t *testing.T) {
	g := quiet(t, twoTechs, phpCPETechs)
	// Matched once on an article about Redis; the stored title does not say so.
	seed(g, "CVE-2026-7002", "Cache server sandbox escape", newDay, "")
	g.Ledger.AddFinding(model.Finding{VulnID: "CVE-2026-7002", Project: "shop", Env: model.EnvProd, Status: model.StatusOpen, Applies: model.AppUnknown,
		Installed: []model.Installed{{Name: "redis", Version: "7.2", Via: "tech"}}, Matched: []string{"redis@7.2"}})
	g.Ledger.Vuln("CVE-2026-7002").Affected = []model.Affected{cpe("acme:cache")} // redis has no CPE names: this rules nothing out
	// A person ignored this one; proof against it arrives later.
	seed(g, "CVE-2026-7003", "PHP flaw", newDay, model.StatusIgnored)
	g.Ledger.Vuln("CVE-2026-7003").Affected = []model.Affected{cpe("moodle:moodle")}

	if rv := revalidate(t, g, true); rv.Retired != 0 {
		t.Fatalf("nothing is proven: %+v", rv)
	}
	if f := only(t, g.Findings("CVE-2026-7002")); f.Retired != "" || len(f.Installed) != 1 {
		t.Fatalf("an unreproduced match stays: %+v", f)
	}
	if f := only(t, g.Findings("CVE-2026-7003")); f.Status != model.StatusIgnored || f.Retired != "" || len(f.Installed) != 1 {
		t.Fatalf("a person's decision stays as it was: %+v", f)
	}

	// The advisory's product names do bound every tech, with or without CPE names.
	g.Ledger.Vuln("CVE-2026-7002").Products = []model.Product{{Vendor: "Acme", Name: "Cache"}}
	if rv := revalidate(t, g, true); rv.Retired != 1 || only(t, g.Findings("CVE-2026-7002")).Retired != model.RetiredUnmatched {
		t.Fatalf("named products are proof: %+v", rv)
	}
}

// The strict profile takes only the advisory's own product data; switching to
// it retires text matches, switching back restores them.
func TestStrictProfileNeedsProductData(t *testing.T) {
	g := quiet(t, phpProject, phpCPETechs)
	seed(g, "CVE-2026-7004", "PHP stream wrapper flaw", newDay, "")
	seed(g, "CVE-2026-7005", "Interpreter flaw", newDay, "")
	g.Ledger.Vuln("CVE-2026-7005").Affected = []model.Affected{cpe("php:php")}
	if rv := revalidate(t, g, true); rv.NewFindings != 2 {
		t.Fatalf("balanced takes both: %+v", rv)
	}

	g.Write("config/projects/shop.yaml", phpProject+"profile: strict\n")
	g.Reload()
	rv := revalidate(t, g, true)
	text, data := only(t, g.Findings("CVE-2026-7004")), only(t, g.Findings("CVE-2026-7005"))
	if rv.Retired != 1 || text.Retired != model.RetiredUnmatched || !strings.Contains(text.Reasons[0], "strict profile") || data.Retired != "" || len(data.Installed) != 1 {
		t.Fatalf("strict keeps product data only: %+v\n%+v\n%+v", rv, text, data)
	}

	g.Write("config/projects/shop.yaml", phpProject)
	g.Reload()
	revalidate(t, g, true)
	if f := only(t, g.Findings("CVE-2026-7004")); f.Retired != "" || len(f.Installed) != 1 {
		t.Fatalf("balanced takes the text match back: %+v", f)
	}
}

// The discovery profile records text matches without paging anyone for them.
func TestDiscoveryRecordsTextMatchesWithoutAlerting(t *testing.T) {
	g := quiet(t, phpProject+"profile: discovery\n", phpCPETechs)
	seed(g, "CVE-2026-7006", "PHP flaw in the text only", g.Now, "")
	seed(g, "CVE-2026-7007", "Interpreter flaw", g.Now, "")
	g.Ledger.Vuln("CVE-2026-7007").Affected = []model.Affected{cpe("php:php")}
	g.Run()
	if len(g.Findings("CVE-2026-7006")) != 1 || len(g.Findings("CVE-2026-7007")) != 1 {
		t.Fatal("both are recorded")
	}
	if n := g.Channel.Alerts(); n != 1 {
		t.Fatalf("only the match on product data alerts, got %d", n)
	}
}

// With retire: manual an update leaves a disproved match as it is and says
// how many there are; asking for a revalidation retires them.
func TestManualRetirementWaitsForAPerson(t *testing.T) {
	g := rig(t, phpCPETechs, map[string]string{"shop": phpProject}, nil)
	g.Write("config/config.yaml", "retire: manual\n")
	g.Reload()
	seed(g, "CVE-2026-7008", "PHP code injection in a gallery", g.Now, model.StatusOpen)
	g.Ledger.Vuln("CVE-2026-7008").Affected = []model.Affected{cpe("moodle:moodle")}

	res := g.Run()
	if f := only(t, g.Findings("CVE-2026-7008")); res.Retirable != 1 || res.Retired != 0 || f.Retired != "" || len(f.Installed) != 1 {
		t.Fatalf("an update only counts it: %+v %+v", res, f)
	}
	if rv := revalidate(t, g, false); rv.Retired != 1 {
		t.Fatalf("the preview says what would be retired: %+v", rv)
	}
	if rv := revalidate(t, g, true); rv.Retired != 1 || only(t, g.Findings("CVE-2026-7008")).Retired != model.RetiredUnmatched {
		t.Fatalf("asking for it retires it: %+v", rv)
	}
}
