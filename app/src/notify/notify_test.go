package notify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"cvewatch/src/model"
)

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
	got := Format(sample())
	for _, want := range []string{"1 new vulnerability", "*CRITICAL* <https://x.test/1|CVE-2026-1>", "RCE &lt;in&gt; PHP", "shop: dev, prod (php@8.2)"} {
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
	if err := s.Send(context.Background(), sample()); err != nil || calls != 3 {
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
	if err := s.Send(context.Background(), sample()); err == nil || calls != 1 {
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
	err = s.Send(context.Background(), sample())
	if err == nil || strings.Contains(err.Error(), "SECRETTOKEN") {
		t.Fatalf("transport error must not contain the webhook: %v", err)
	}
}
