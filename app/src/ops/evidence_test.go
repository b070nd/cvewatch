package ops

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/b070nd/cvewatch/app/src/audit"
	"github.com/b070nd/cvewatch/app/src/config"
	"github.com/b070nd/cvewatch/app/src/evidence"
)

func auditAt(h int, e audit.Event) audit.Event {
	e.Time = day.Add(time.Duration(h) * time.Hour)
	e.Vuln = "CVE-2026-1"
	return e
}

func seedAudit(t *testing.T, dir string, events ...audit.Event) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := audit.Open(dir).Append(events...); err != nil {
		t.Fatal(err)
	}
}

func timelineOf(p evidence.Pack, source string) []evidence.Entry {
	var out []evidence.Entry
	for _, e := range p.Timeline {
		if e.Source == source {
			out = append(out, e)
		}
	}
	return out
}

func TestEvidenceTimelineShowsLaterDetectionsAndAutomaticChanges(t *testing.T) {
	cfg, st := bundle(t, nil), seeded(t)
	seedAudit(t, cfg.DataDir,
		auditAt(1, audit.Event{Actor: "cvewatch", Action: "detected", Project: "shop", Env: "prod"}),
		auditAt(5, audit.Event{Actor: "cvewatch", Action: "detected", Project: "mw", Env: "prod", Note: "matched an advisory already stored"}),
		auditAt(9, audit.Event{Actor: "cvewatch", Action: "status", Project: "mw", Env: "prod", Status: "ignored", Note: "environment removed from project"}),
		auditAt(7, audit.Event{Actor: "ann", Action: "status", Project: "shop", Env: "prod", Status: "fixed", Note: "MR 3"}),
	)
	p, err := open(t, cfg, st, "alice").Evidence("CVE-2026-1")
	if err != nil || !p.AuditIntact || p.AuditNote != "" {
		t.Fatalf("pack: intact=%v note=%q err=%v", p.AuditIntact, p.AuditNote, err)
	}
	got := timelineOf(p, evidence.SourceAudit)
	if len(got) != 4 {
		t.Fatalf("audit entries: %+v", got)
	}
	for i, want := range []string{"shop/prod detected", "mw/prod detected: matched an advisory already stored", "shop/prod set to fixed: MR 3", "mw/prod set to ignored: environment removed from project"} {
		if got[i].Detail != want {
			t.Errorf("entry %d = %q, want %q", i, got[i].Detail, want)
		}
	}
	if got[1].Project != "mw" || got[1].Env != "prod" || got[1].Actor != "cvewatch" {
		t.Errorf("a later detection names actor, project and env: %+v", got[1])
	}
	var md bytes.Buffer
	if err := p.WriteMarkdown(&md); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(md.String(), "environment removed from project (by cvewatch (automatic))") {
		t.Fatalf("an automatic change is labelled in the report:\n%s", md.String())
	}
}

func TestEvidenceForARestrictedReader(t *testing.T) {
	access := map[string]config.Grant{"carol": {Projects: []string{"mw"}}}

	t.Run("sees its own projects and global events, verified", func(t *testing.T) {
		cfg, st := bundle(t, access), seeded(t)
		seedAudit(t, cfg.DataDir,
			auditAt(1, audit.Event{Actor: "cvewatch", Action: "detected", Project: "shop", Env: "prod"}),
			auditAt(2, audit.Event{Actor: "cvewatch", Action: "detected", Project: "mw", Env: "prod"}),
			auditAt(3, audit.Event{Actor: "cvewatch", Action: "alerted", Note: "console"}),
			auditAt(4, audit.Event{Actor: "ann", Action: "status", Project: "shop", Env: "prod", Status: "fixed", Note: "secret shop note"}),
			auditAt(5, audit.Event{Actor: "cvewatch", Action: "status", Project: "mw", Env: "prod", Status: "ignored", Note: "environment removed from project"}),
		)
		p, err := open(t, cfg, st, "carol").Evidence("CVE-2026-1")
		if err != nil || !p.AuditIntact || p.AuditNote != "" {
			t.Fatalf("intact=%v note=%q err=%v", p.AuditIntact, p.AuditNote, err)
		}
		var kinds []string
		for _, e := range timelineOf(p, evidence.SourceAudit) {
			kinds = append(kinds, e.Kind+":"+e.Project)
			if strings.Contains(e.Detail, "shop") || strings.Contains(e.Detail, "secret") {
				t.Fatalf("another project's record is visible: %+v", e)
			}
		}
		if strings.Join(kinds, " ") != "detected:mw alerted: status:mw" {
			t.Fatalf("kinds = %v", kinds)
		}
		d, err := open(t, cfg, st, "carol").IssueDetail("CVE-2026-1")
		if err != nil {
			t.Fatal(err)
		}
		for _, h := range d.History {
			if strings.Contains(h.Detail, "shop") {
				t.Fatalf("the issue page history leaks another project: %+v", h)
			}
		}
	})

	t.Run("no records visible is not an integrity failure", func(t *testing.T) {
		cfg, st := bundle(t, access), seeded(t)
		seedAudit(t, cfg.DataDir, auditAt(4, audit.Event{Actor: "ann", Action: "status", Project: "shop", Env: "prod", Status: "fixed", Note: "secret shop note"}))
		p, err := open(t, cfg, st, "carol").Evidence("CVE-2026-1")
		if err != nil {
			t.Fatal(err)
		}
		if !p.AuditIntact || !strings.Contains(p.AuditNote, "no audit records visible to you") {
			t.Fatalf("intact=%v note=%q", p.AuditIntact, p.AuditNote)
		}
		if len(timelineOf(p, evidence.SourceAudit)) != 0 {
			t.Fatalf("nothing from the audit log is visible: %+v", p.Timeline)
		}
	})

	t.Run("a broken chain is still reported", func(t *testing.T) {
		cfg, st := bundle(t, access), seeded(t)
		seedAudit(t, cfg.DataDir,
			auditAt(1, audit.Event{Actor: "cvewatch", Action: "detected", Project: "mw", Env: "prod"}),
			auditAt(2, audit.Event{Actor: "cvewatch", Action: "detected", Project: "shop", Env: "prod"}),
			auditAt(3, audit.Event{Actor: "cvewatch", Action: "alerted", Note: "console"}),
		)
		path := filepath.Join(cfg.DataDir, "audit.log")
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.SplitAfter(string(raw), "\n")
		if err := os.WriteFile(path, []byte(lines[0]+lines[2]), 0o600); err != nil {
			t.Fatal(err)
		}
		p, err := open(t, cfg, st, "carol").Evidence("CVE-2026-1")
		if err != nil {
			t.Fatal(err)
		}
		if p.AuditIntact || !strings.Contains(p.AuditNote, "chain broken") {
			t.Fatalf("intact=%v note=%q", p.AuditIntact, p.AuditNote)
		}
	})

	t.Run("no audit log at all for an administrator says so plainly", func(t *testing.T) {
		cfg, st := bundle(t, nil), seeded(t)
		p, err := open(t, cfg, st, "alice").Evidence("CVE-2026-1")
		if err != nil {
			t.Fatal(err)
		}
		if p.AuditIntact || !strings.Contains(p.AuditNote, "no audit records found") {
			t.Fatalf("intact=%v note=%q", p.AuditIntact, p.AuditNote)
		}
	})
}
