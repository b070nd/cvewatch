package tui

import (
	"strings"
	"testing"

	"github.com/b070nd/cvewatch/app/src/model"
)

// openIssue puts the cursor of the findings list on the issue of a project and opens its page.
func openIssueOf(t *testing.T, d *driver, project, id string) {
	t.Helper()
	d.screen("findings")
	a := d.app()
	i := a.visibleIssue(project, id)
	if i < 0 {
		t.Fatalf("%s is not listed in %s", id, project)
	}
	a.fnd.vp.to(i)
	d.press("enter")
	if a.fnd.det == nil || a.fnd.det.project != project {
		t.Fatalf("the page of %s in %s is not open: %+v", id, project, a.fnd.det)
	}
}

func wantNoPageOf(t *testing.T, d *driver, project string) {
	t.Helper()
	a := d.app()
	if det := a.fnd.det; det != nil {
		t.Fatalf("the page of %s in %s is still open under the context %q", det.id, det.project, a.tenantLabel())
	}
	d.wantNot(project + ":prod")
}

func TestSwitchingProjectOnProjectsClosesTheIssuePageOfTheOldOne(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	openIssueOf(t, d, "shop", "CVE-2026-1")
	d.want("Findings › CVE-2026-1 › shop:prod")

	d.screen("projects")
	d.press("down", "enter") // mw
	if got := d.app().tenant; got != (tenant{project: "mw"}) {
		t.Fatalf("context %+v", got)
	}
	d.screen("findings")
	d.want("context: mw", "1 of 1 open issues")
	wantNoPageOf(t, d, "shop")

	d.press("a")
	if d.app().prm != nil {
		t.Fatalf("no prompt for an issue of the old context: %+v", d.app().prm)
	}
	d.wantNot("Assign CVE-2026-1 in shop")

	d.press("r")
	wantNoPageOf(t, d, "shop")
	d.press("enter")
	d.want("Findings › CVE-2026-1 › mw:prod")
	d.press("a")
	d.want("Assign CVE-2026-1 in mw/prod")
}

func TestContextPickerRouteClosesTheIssuePage(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	openIssueOf(t, d, "shop", "CVE-2026-1")
	d.press("C", "down", "down", "enter") // all projects, shop, mw
	if got := d.app().tenant; got != (tenant{project: "mw"}) {
		t.Fatalf("context %+v", got)
	}
	d.screen("findings")
	wantNoPageOf(t, d, "shop")
	d.press("esc") // nothing is open: nothing to go back to
	d.wantNot("shop:prod")
}

func TestPageOfAProjectStaysWhenTheContextBecomesAllProjects(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	openIssueOf(t, d, "shop", "CVE-2026-1")
	d.app().setTenant(tenant{}, false)
	if det := d.app().fnd.det; det == nil || det.project != "shop" {
		t.Fatalf("shop is one of all projects: %+v", det)
	}
}

func TestVendorContextRouteClosesTheIssuePageOfAnotherVendor(t *testing.T) {
	d := startIn(t, vendorFake(t), Options{}, tenant{project: "mw"})
	openIssueOf(t, d, "mw", "CVE-2026-1")
	d.press("C", "up", "up", "up", "up", "enter") // acme > all projects, from mw
	if got := d.app().tenant; got != (tenant{vendor: "acme"}) {
		t.Fatalf("context %+v", got)
	}
	d.screen("findings")
	wantNoPageOf(t, d, "mw")
}

func TestPageOfAProjectInsideTheNewVendorContextStays(t *testing.T) {
	d := startIn(t, vendorFake(t), Options{}, tenant{project: "shop"})
	openIssueOf(t, d, "shop", "CVE-2026-1")
	d.app().setTenant(tenant{vendor: "acme"}, false)
	if det := d.app().fnd.det; det == nil || det.project != "shop" {
		t.Fatalf("shop is one of the projects of acme: %+v", det)
	}
}

func TestOpenPromptIsCancelledByAContextChange(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	openIssueOf(t, d, "shop", "CVE-2026-1")
	d.press("a")
	d.want("Assign CVE-2026-1 in shop/")
	if d.app().prm == nil {
		t.Fatal("the prompt is open")
	}
	d.app().setTenant(tenant{project: "mw"}, false)
	if d.app().prm != nil {
		t.Fatalf("the prompt of the old context is still open: %+v", d.app().prm)
	}
	d.wantNot("Assign CVE-2026-1 in shop")
}

func TestBulkPromptAndMarksDoNotSurviveAContextChange(t *testing.T) {
	d := startAll(t, newFake(t, nil), Options{})
	d.screen("findings")
	d.press(" ")
	a := d.app()
	if len(a.fnd.sel) == 0 {
		t.Fatalf("an issue is marked: %v", a.fnd.sel)
	}
	a.startBulk(model.StatusFixed)
	if a.prm == nil {
		t.Fatal("the bulk prompt is open")
	}
	a.setTenant(tenant{project: "mw"}, false)
	if a.prm != nil {
		t.Fatalf("the prompt of the old context is open: %+v", a.prm)
	}
	for key := range a.fnd.sel {
		if !strings.HasPrefix(key, "mw\x00") {
			t.Fatalf("a mark outside the context: %q", key)
		}
	}
}

func TestBackNavigationDoesNotBringTheOldPageBack(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	openIssueOf(t, d, "shop", "CVE-2026-1")
	d.app().setTenant(tenant{project: "mw"}, false)
	d.screen("findings")
	for i := 0; i < 3; i++ {
		d.press("esc")
		wantNoPageOf(t, d, "shop")
	}
	if d.app().ret != nil {
		t.Fatalf("a way back to the old context is kept: %+v", d.app().ret)
	}
}

func TestReturnPointOfTheOldContextIsDropped(t *testing.T) {
	d := startAll(t, newFake(t, nil), Options{})
	a := d.app()
	a.ret = &returnPoint{to: issueIn("shop", "CVE-2026-1", true), dest: scrFindings, level: lvDetail}
	a.setTenant(tenant{project: "mw"}, true)
	if a.ret != nil {
		t.Fatalf("the way back to shop survived: %+v", a.ret)
	}
	a.ret = &returnPoint{to: issueIn("mw", "CVE-2026-1", true), dest: scrFindings, level: lvDetail}
	a.setTenant(tenant{project: "mw"}, true)
	if a.ret == nil {
		t.Fatal("an unchanged context keeps its way back")
	}
}

func TestAReadStartedForTheOldContextDoesNotFillTheNewPage(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	a := d.app()
	openIssueOf(t, d, "shop", "CVE-2026-1")
	old := a.fnd.det
	a.setTenant(tenant{project: "mw"}, true)
	d.screen("findings")
	d.press("enter") // CVE-2026-1 in mw
	if a.fnd.det == nil || a.fnd.det == old {
		t.Fatalf("page %+v", a.fnd.det)
	}
	a.detailLoaded(detailMsg{id: "CVE-2026-1", page: old, is: old.is})
	if a.fnd.det.project != "mw" {
		t.Fatal("the new page is for mw")
	}
	for _, tg := range a.fnd.det.is.Targets {
		if tg.Project == "shop" {
			t.Fatalf("a read of shop filled the page of mw: %+v", a.fnd.det.is.Targets)
		}
	}
}

func TestStartingAnActionOnAFindingOutsideTheContextIsRefused(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	openIssueOf(t, d, "shop", "CVE-2026-1")
	a := d.app()
	a.tenant = tenant{project: "mw"} // as if a path had changed the context without the setter
	d.press("a")
	if a.prm != nil {
		t.Fatalf("prompt %+v", a.prm)
	}
	d.want("that issue belongs to shop; choose its project with C")
	for _, k := range []string{"+", "r"} {
		d.press(k)
		if a.prm != nil {
			t.Fatalf("%s opened a prompt", k)
		}
	}
	// a prompt that was open when the guard looks is closed at submit
	a.tenant = tenant{project: "shop"}
	d.press("a")
	if a.prm == nil {
		t.Fatal("the prompt opens inside the context")
	}
	a.tenant = tenant{project: "mw"}
	d.press("enter", "enter", "enter")
	if a.prm != nil || a.pend.count() != 0 {
		t.Fatalf("a write for shop started under mw: prompt %+v, pending %d", a.prm, a.pend.count())
	}
	if !strings.Contains(d.view(), "belongs to shop") {
		t.Fatal("the refusal is shown")
	}
}

func TestAnIssueTargetOutsideTheContextOpensInItsOwnProject(t *testing.T) {
	d := start(t, newFake(t, nil), Options{})
	d.app().goTo(issueIn("mw", "CVE-2026-1", true))
	if got := d.app().tenant; got != (tenant{project: "mw"}) {
		t.Fatalf("context %+v", got)
	}
	if det := d.app().fnd.det; det == nil || det.project != "mw" {
		t.Fatalf("page %+v", det)
	}
}
