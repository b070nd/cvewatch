package golden

import (
	"strings"
	"testing"

	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/projectfile"
	"github.com/b070nd/cvewatch/app/src/testkit"
)

// A person who writes "ubuntu kernel 6.12.85+" is told the catalog name, and
// once they use it the kernel advisory for their version creates a finding.
func TestKernelProjectEndToEnd(t *testing.T) {
	const project = "name: edge\nenvs: [prod]\ntechs:\n  - {name: ubuntu kernel, version: \"6.12.85+\"}\n"
	g := testkit.NewRig(t, map[string]string{"sources/s.yaml": sources, "config/projects/edge.yaml": project}, map[string]string{
		nvdURL: nvd("CVE-2099-0100", "Linux kernel TCP use-after-free allows remote code execution.", "linux:linux_kernel", "6.12.86"),
	})

	f, err := projectfile.Parse([]byte(project))
	if err != nil {
		t.Fatal(err)
	}
	var fix *projectfile.Fix
	for _, is := range f.ValidateCatalog(g.Runner.Cfg.Catalog) {
		if is.Field == "techs[0]" && len(is.Fixes) == 1 {
			fix = &is.Fixes[0]
		}
	}
	if fix == nil || fix.Label != `use technology name "linux-kernel" instead of "ubuntu kernel"` {
		t.Fatalf("the project problems should offer the catalog name: %+v", fix)
	}
	if err := f.Apply(fix.Ops...); err != nil {
		t.Fatal(err)
	}

	g.Run()
	if got := g.Findings("CVE-2099-0100"); len(got) != 0 {
		t.Fatalf("an unknown technology matches nothing, got %+v", got)
	}

	fixed, err := f.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(fixed), "linux-kernel") {
		t.Fatalf("fixed file: %s", fixed)
	}
	g.Write("config/projects/edge.yaml", string(fixed))
	g.Reload()
	g.Serve(nvdURL, nvd("CVE-2099-0101", "Netfilter nf_tables double free in the Linux kernel allows privilege escalation.", "linux:linux_kernel", "6.12.86"))
	g.Run()
	// the advisory stored before the fix is judged again with the corrected project
	for _, id := range []string{"CVE-2099-0100", "CVE-2099-0101"} {
		got := g.Findings(id)
		if len(got) != 1 || got[0].Applies != model.AppAffected || got[0].Project != "edge" {
			t.Fatalf("%s: 6.12.85+ is below 6.12.86 and must be affected: %+v", id, got)
		}
	}

	g.Serve(nvdURL, nvd("CVE-2099-0102", "Bluetooth l2cap use-after-free in the Linux kernel fixed in 6.12.85.", "linux:linux_kernel", "6.12.85"))
	g.Run()
	if got := g.Findings("CVE-2099-0102"); len(got) != 1 || got[0].Applies != model.AppNotAffected {
		t.Fatalf("6.12.85+ is not below 6.12.85: %+v", got)
	}
}
