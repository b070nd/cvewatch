package notify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/b070nd/cvewatch/app/src/model"
)

var testNow = time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)

func sample() []Alert {
	return []Alert{{
		Vuln: &model.Vulnerability{ID: "CVE-2026-1", Title: "RCE <in> PHP", Severity: model.SevCritical,
			Techs: []string{"php"}, Refs: []model.Ref{{Source: "kev", URL: "https://x.test/1"}}},
		Findings: []model.Finding{
			{Project: "shop", Env: model.EnvDev, Matched: []string{"php@8.2"}},
			{Project: "shop", Env: model.EnvProd},
		},
	}}
}

func TestFormat(t *testing.T) {
	got := Format(sample(), testNow)
	for _, want := range []string{"1 new vulnerability", "*CRITICAL* <https://x.test/1|CVE-2026-1>", "RCE &lt;in&gt; PHP", "shop: dev, prod (php@8.2)", "1 article", "no fix known"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

func TestSlackRetriesThenSucceeds(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls++; calls < 3 {
			w.WriteHeader(http.StatusBadGateway)
		}
	}))
	defer srv.Close()
	s := &Slack{URL: srv.URL, Client: srv.Client(), Delay: time.Millisecond}
	if err := s.Send(context.Background(), sample(), testNow); err != nil || calls != 3 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
}

func TestSlackBadWebhookFailsFast(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	s := &Slack{URL: srv.URL, Client: srv.Client(), Delay: time.Millisecond}
	if err := s.Send(context.Background(), sample(), testNow); err == nil || calls != 1 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
}

func TestWebhookIsValidatedAndNeverLeaks(t *testing.T) {
	for _, bad := range []string{"http://hooks.example/T/B/X", "not a url", "https://"} {
		if _, err := NewSlack(bad); err == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
	s, err := NewSlack("https://127.0.0.1:1/services/T000/B000/SECRETTOKEN")
	if err != nil {
		t.Fatal(err)
	}
	s.Delay = time.Millisecond
	s.Client.Timeout = 200 * time.Millisecond
	err = s.Send(context.Background(), sample(), testNow)
	if err == nil || strings.Contains(err.Error(), "SECRETTOKEN") {
		t.Fatalf("transport error must not contain the webhook: %v", err)
	}
}

func TestSlackImplementsChannel(t *testing.T) {
	var c Channel = &Slack{}
	if c.Name() != "slack" {
		t.Fatal(c.Name())
	}
}

func TestFormatKEVAndEPSS(t *testing.T) {
	al := sample()
	al[0].Vuln.KEV = &model.KEV{DueDate: time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC)}
	al[0].Vuln.EPSS = &model.EPSS{Score: 0.43, Percentile: 0.98}
	got := Format(al, testNow)
	for _, want := range []string{"KEV, remediation due 2026-10-24", "EPSS 43%"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	al[0].Vuln.KEV = &model.KEV{}
	al[0].Vuln.EPSS = &model.EPSS{Score: 0.043}
	got = Format(al, testNow)
	if !strings.Contains(got, "*KEV · EPSS 4.3%*") {
		t.Errorf("no due date or low EPSS rendered wrongly:\n%s", got)
	}
	if plain := Format(sample(), testNow); strings.Contains(plain, "KEV") || strings.Contains(plain, "EPSS") {
		t.Errorf("badges must be absent without data:\n%s", plain)
	}
}

func TestFormatLinkCannotBreakOut(t *testing.T) {
	al := sample()
	al[0].Vuln.Refs[0].URL = "https://x.test/a|b>c <d>"
	got := Format(al, testNow)
	if strings.Contains(got, "a|b") || strings.Contains(got, ">c") {
		t.Errorf("URL must be encoded inside the link:\n%s", got)
	}
}

func sampleDigest() Digest {
	return Digest{
		Env: model.EnvProd, Open: 12, Overdue: 2,
		BySeverity: map[model.Severity]int{model.SevCritical: 2, model.SevHigh: 4, model.SevLow: 6},
		Items: []DigestItem{
			{ID: "CVE-2026-1", Title: "RCE <in> PHP", Severity: model.SevCritical, Projects: []string{"shop", "blog"},
				Age: "3d 4h", KEV: true, Overdue: true, Owner: "alice", URL: "https://x.test/1"},
			{ID: "CVE-2026-2", Title: "XSS", Severity: model.SevHigh},
		},
		Truncated: 10,
	}
}

func TestFormatDigest(t *testing.T) {
	got := FormatDigest(sampleDigest())
	for _, want := range []string{
		"*cvewatch digest* · prod", "12 open · 2 overdue", "critical 2 · high 4 · low 6",
		"*CRITICAL* <https://x.test/1|CVE-2026-1> — RCE &lt;in&gt; PHP", "*KEV, overdue*",
		"shop, blog · age 3d 4h · owner alice", "*HIGH* CVE-2026-2 — XSS", "…and 10 more not shown",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "medium") {
		t.Errorf("zero counts must be left out:\n%s", got)
	}
	all := FormatDigest(Digest{Open: 0})
	if strings.Contains(all, "·  ") || strings.Contains(all, "more not shown") || !strings.Contains(all, "0 open · 0 overdue") {
		t.Errorf("empty digest:\n%s", all)
	}
}
