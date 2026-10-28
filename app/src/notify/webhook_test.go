package notify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/b070nd/cvewatch/app/src/model"
)

type capture struct {
	mu   sync.Mutex
	body []byte
	hdr  http.Header
}

func (c *capture) handler(status func(n int) int) (http.Handler, *int) {
	n := new(int)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		defer c.mu.Unlock()
		*n++
		c.body, _ = io.ReadAll(r.Body)
		c.hdr = r.Header.Clone()
		w.WriteHeader(status(*n))
	}), n
}

func TestWebhookPostsSignedJSON(t *testing.T) {
	var c capture
	h, _ := c.handler(func(int) int { return 200 })
	srv := httptest.NewServer(h)
	defer srv.Close()
	w, err := NewWebhook(srv.URL+"/hook/TOKEN", "s3cret", true)
	if err != nil {
		t.Fatal(err)
	}
	al := sample()
	al[0].Vuln.KEV = &model.KEV{}
	al[0].Vuln.Fixes = []model.Fix{{Kind: model.FixVersion, Official: true}}
	al[0].Findings[0].Applies = model.AppAffected
	if err := w.Send(context.Background(), al, testNow); err != nil {
		t.Fatal(err)
	}

	if got := c.hdr.Get("Content-Type"); got != "application/json" {
		t.Errorf("content type %q", got)
	}
	if got := c.hdr.Get("User-Agent"); got != "cvewatch" {
		t.Errorf("user agent %q", got)
	}
	m := hmac.New(sha256.New, []byte("s3cret"))
	m.Write(c.body)
	if want := "sha256=" + hex.EncodeToString(m.Sum(nil)); c.hdr.Get("X-Cvewatch-Signature") != want {
		t.Errorf("signature %q, want %q", c.hdr.Get("X-Cvewatch-Signature"), want)
	}

	var doc struct {
		SchemaVersion int             `json:"schema_version"`
		Type          string          `json:"type"`
		GeneratedAt   string          `json:"generated_at"`
		Alerts        []jsonAlert     `json:"alerts"`
		Digest        json.RawMessage `json:"digest"`
	}
	if err := json.Unmarshal(c.body, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.SchemaVersion != 1 || doc.Type != "alerts" || doc.GeneratedAt != "2026-10-03T00:00:00Z" || doc.Digest != nil {
		t.Errorf("envelope: %+v", doc)
	}
	if len(doc.Alerts) != 1 {
		t.Fatalf("alerts: %+v", doc.Alerts)
	}
	a := doc.Alerts[0]
	if a.ID != "CVE-2026-1" || a.Severity != "critical" || a.Title != "RCE <in> PHP" || a.URL != "https://x.test/1" ||
		a.Articles != 1 || a.Fix != "official" || !a.KEV || len(a.Techs) != 1 || len(a.Targets) != 2 {
		t.Errorf("alert: %+v", a)
	}
	if a.Targets[0] != (jsonTarget{"shop", "dev", "affected"}) || a.Targets[1] != (jsonTarget{"shop", "prod", "unknown"}) {
		t.Errorf("targets: %+v", a.Targets)
	}
}

func TestWebhookDigestAndNoSecretNoSignature(t *testing.T) {
	var c capture
	h, _ := c.handler(func(int) int { return 204 }) // any 2xx is success
	srv := httptest.NewServer(h)
	defer srv.Close()
	w, _ := NewWebhook(srv.URL, "", true)
	if err := w.SendDigest(context.Background(), sampleDigest(), testNow); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.hdr["X-Cvewatch-Signature"]; ok {
		t.Error("no secret, no signature")
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(c.body, &doc); err != nil {
		t.Fatal(err)
	}
	if _, ok := doc["alerts"]; ok {
		t.Error("digest must not carry alerts")
	}
	var d jsonDigest
	if err := json.Unmarshal(doc["digest"], &d); err != nil {
		t.Fatal(err)
	}
	if string(doc["type"]) != `"digest"` || d.Env != "prod" || d.Open != 12 || d.Overdue != 2 || d.Truncated != 10 ||
		d.BySeverity["high"] != 4 || len(d.Items) != 2 || !d.Items[0].Overdue || d.Items[1].Projects == nil {
		t.Errorf("digest: %s", c.body)
	}
}

func TestWebhookRetriesThenSucceeds(t *testing.T) {
	var c capture
	h, n := c.handler(func(n int) int {
		if n < 3 {
			return http.StatusBadGateway
		}
		return 200
	})
	srv := httptest.NewServer(h)
	defer srv.Close()
	w, _ := NewWebhook(srv.URL, "k", true)
	w.Delay = time.Millisecond
	if err := w.Send(context.Background(), sample(), testNow); err != nil || *n != 3 {
		t.Fatalf("err=%v calls=%d", err, *n)
	}
}

func TestWebhookClientErrorNotRetriedAndRedirectNotFollowed(t *testing.T) {
	for _, code := range []int{http.StatusBadRequest, http.StatusFound} {
		var c capture
		h, n := c.handler(func(int) int { return code })
		srv := httptest.NewServer(h)
		w, _ := NewWebhook(srv.URL+"/TOKEN", "", true)
		w.Delay = time.Millisecond
		err := w.Send(context.Background(), sample(), testNow)
		srv.Close()
		if err == nil || *n != 1 || strings.Contains(err.Error(), "TOKEN") {
			t.Errorf("code %d: err=%v calls=%d", code, err, *n)
		}
	}
}

func TestWebhookRateLimitHonoursContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	w, _ := NewWebhook(srv.URL, "", true)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := w.Send(ctx, sample(), testNow); err == nil || time.Since(start) > 5*time.Second {
		t.Fatalf("err=%v after %v", err, time.Since(start))
	}
}

func TestNewWebhookSchemeAndAddressRules(t *testing.T) {
	for _, bad := range []string{"", "not a url", "https://", "ftp://x.test/h", "http://hooks.example/h"} {
		if _, err := NewWebhook(bad, "", false); err == nil {
			t.Errorf("%q must be refused", bad)
		} else if bad != "" && strings.Contains(err.Error(), bad) {
			t.Errorf("error echoes the URL: %v", err)
		}
	}
	if _, err := NewWebhook("http://10.0.0.5/hook", "", true); err != nil {
		t.Errorf("allowPrivate permits http: %v", err)
	}
	if _, err := NewWebhook("ftp://x.test/h", "", true); err == nil {
		t.Error("allowPrivate does not permit other schemes")
	}
}

func TestWebhookBlocksPrivateAddressesByDefault(t *testing.T) {
	hit := false
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit = true }))
	defer srv.Close()
	w, err := NewWebhook(srv.URL+"/SECRETTOKEN", "topsecret", false)
	if err != nil {
		t.Fatal(err)
	}
	w.Delay = time.Millisecond
	err = w.Send(context.Background(), sample(), testNow)
	if err == nil || hit {
		t.Fatalf("loopback must be refused: err=%v hit=%v", err, hit)
	}
	for _, leak := range []string{"SECRETTOKEN", "topsecret", srv.URL} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("error leaks %q: %v", leak, err)
		}
	}
	// allowPrivate lifts the block (the test server's certificate needs its own client).
	w, _ = NewWebhook(srv.URL, "", true)
	w.Client = srv.Client()
	if err := w.Send(context.Background(), sample(), testNow); err != nil || !hit {
		t.Fatalf("allowPrivate: err=%v hit=%v", err, hit)
	}
}

func TestNonPublicAddresses(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1": true, "10.1.2.3": true, "192.168.0.1": true, "172.16.0.1": true, "169.254.169.254": true,
		"100.64.0.1": true, "0.0.0.0": true, "::1": true, "fe80::1": true, "fd00::1": true, "::ffff:127.0.0.1": true,
		"93.184.216.34": false, "2606:4700::1111": false,
	} {
		if err := publicOnly("tcp", "["+addr+"]:443", nil); (err != nil) != want {
			t.Errorf("%s: blocked=%v want %v", addr, err != nil, want)
		}
	}
}

func TestWebhookErrorNeverContainsSecrets(t *testing.T) {
	w, err := NewWebhook("https://127.0.0.1:1/hook/SECRETTOKEN", "topsecret", true)
	if err != nil {
		t.Fatal(err)
	}
	w.Delay = time.Millisecond
	w.Client.Timeout = 200 * time.Millisecond
	err = w.Send(context.Background(), sample(), testNow)
	if err == nil || strings.Contains(err.Error(), "SECRETTOKEN") || strings.Contains(err.Error(), "topsecret") {
		t.Fatalf("transport error must not contain secrets: %v", err)
	}
}

func TestSignMatchesKnownVector(t *testing.T) {
	// RFC 4231 test case 2.
	got := Sign("Jefe", []byte("what do ya want for nothing?"))
	if want := "sha256=5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"; got != want {
		t.Errorf("got %s", got)
	}
}
