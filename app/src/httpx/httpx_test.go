package httpx

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"cvewatch/src/model"
)

// serve starts a test server and counts the requests it receives.
func serve(t *testing.T, h func(n int, w http.ResponseWriter, r *http.Request)) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h(int(calls.Add(1)), w, r)
	}))
	t.Cleanup(ts.Close)
	return ts, &calls
}

// fast shortens retry waits and allows the loopback test servers.
func fast(o Options) Options {
	o.AllowPrivate = true
	if o.RetryDelay == 0 {
		o.RetryDelay = time.Millisecond
	}
	return o
}

func TestRetryThenSuccess(t *testing.T) {
	ts, calls := serve(t, func(n int, w http.ResponseWriter, r *http.Request) {
		if n < 3 {
			http.Error(w, "busy", http.StatusServiceUnavailable)
			return
		}
		if got := r.Header.Get("User-Agent"); got != "test-agent" {
			t.Errorf("User-Agent = %q", got)
		}
		if got := r.Header.Get("X-Extra"); got != "1" {
			t.Errorf("X-Extra = %q", got)
		}
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("Last-Modified", "Mon, 02 Jan 2006 15:04:05 GMT")
		w.Write([]byte("hello"))
	})
	c := New(fast(Options{UserAgent: "test-agent", Retries: 3}))
	res, err := c.Get(context.Background(), ts.URL, model.Validators{}, map[string]string{"X-Extra": "1"})
	if err != nil {
		t.Fatal(err)
	}
	if string(res.Body) != "hello" || res.NotModified {
		t.Fatalf("unexpected response %+v", res)
	}
	if res.Validators.ETag != `"v1"` || res.Validators.LastModified == "" {
		t.Fatalf("validators not captured: %+v", res.Validators)
	}
	if calls.Load() != 3 {
		t.Fatalf("calls = %d, want 3", calls.Load())
	}
}

func TestRetriesExhausted(t *testing.T) {
	ts, calls := serve(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	_, err := New(fast(Options{Retries: 2})).Get(context.Background(), ts.URL, model.Validators{}, nil)
	var se *StatusError
	if !errors.As(err, &se) || se.Code != 500 {
		t.Fatalf("err = %v, want StatusError 500", err)
	}
	if calls.Load() != 3 {
		t.Fatalf("calls = %d, want 3", calls.Load())
	}
}

func TestNotModified(t *testing.T) {
	ts, _ := serve(t, func(_ int, w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") != `"v1"` || r.Header.Get("If-Modified-Since") != "yesterday" {
			t.Errorf("conditional headers missing: %v", r.Header)
		}
		w.WriteHeader(http.StatusNotModified)
	})
	prev := model.Validators{ETag: `"v1"`, LastModified: "yesterday"}
	res, err := New(fast(Options{})).Get(context.Background(), ts.URL, prev, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.NotModified || res.Validators != prev || len(res.Body) != 0 {
		t.Fatalf("unexpected response %+v", res)
	}
}

func TestRetryAfterHonored(t *testing.T) {
	ts, calls := serve(t, func(n int, w http.ResponseWriter, _ *http.Request) {
		if n == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Write([]byte("ok"))
	})
	start := time.Now()
	res, err := New(fast(Options{Retries: 1})).Get(context.Background(), ts.URL, model.Validators{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed < 900*time.Millisecond {
		t.Fatalf("retried after %v, Retry-After was ignored", elapsed)
	}
	if string(res.Body) != "ok" || calls.Load() != 2 {
		t.Fatalf("body %q, calls %d", res.Body, calls.Load())
	}
}

func TestRetryAfterParsing(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	cases := []struct {
		in   string
		want time.Duration
	}{
		{"", 0},
		{"abc", 0},
		{"7", 7 * time.Second},
		{"-3", 0},
		{"86400", maxWait},
		{now.Add(30 * time.Second).Format(http.TimeFormat), 30 * time.Second},
		{now.Add(-time.Hour).Format(http.TimeFormat), 0},
		{now.Add(48 * time.Hour).Format(http.TimeFormat), maxWait},
	}
	for _, tc := range cases {
		if got := retryAfter(tc.in, now); got != tc.want {
			t.Errorf("retryAfter(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestBodyCap(t *testing.T) {
	ts, _ := serve(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(strings.Repeat("x", 100)))
	})
	c := New(fast(Options{MaxBody: 50}))
	if _, err := c.Get(context.Background(), ts.URL, model.Validators{}, nil); !errors.Is(err, errBodyTooLarge) {
		t.Fatalf("err = %v, want body too large", err)
	}
	c = New(fast(Options{MaxBody: 100}))
	if res, err := c.Get(context.Background(), ts.URL, model.Validators{}, nil); err != nil || len(res.Body) != 100 {
		t.Fatalf("body at the limit must pass: %v", err)
	}
}

func TestNotFoundNotRetried(t *testing.T) {
	ts, calls := serve(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
		http.NotFound(w, nil)
	})
	_, err := New(fast(Options{Retries: 5})).Get(context.Background(), ts.URL, model.Validators{}, nil)
	var se *StatusError
	if !errors.As(err, &se) || se.Code != 404 {
		t.Fatalf("err = %v, want StatusError 404", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("calls = %d, want 1", calls.Load())
	}
}

func TestRateLimitSpacesRequests(t *testing.T) {
	ts, _ := serve(t, func(_ int, w http.ResponseWriter, _ *http.Request) {})
	c := New(fast(Options{Rate: 20})) // 50ms apart
	start := time.Now()
	for range 3 {
		if _, err := c.Get(context.Background(), ts.URL, model.Validators{}, nil); err != nil {
			t.Fatal(err)
		}
	}
	if elapsed := time.Since(start); elapsed < 90*time.Millisecond {
		t.Fatalf("3 requests took %v, rate limit not applied", elapsed)
	}
}

func TestRetriesDoNotBypassRateLimit(t *testing.T) {
	ts, calls := serve(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	})
	c := New(fast(Options{Rate: 20, Retries: 2}))
	start := time.Now()
	c.Get(context.Background(), ts.URL, model.Validators{}, nil)
	if elapsed := time.Since(start); elapsed < 90*time.Millisecond || calls.Load() != 3 {
		t.Fatalf("3 attempts took %v (%d calls), retries skipped the limiter", elapsed, calls.Load())
	}
}

func TestHostRateOverride(t *testing.T) {
	ts, _ := serve(t, func(_ int, w http.ResponseWriter, _ *http.Request) {})
	c := New(fast(Options{Rate: 1000, HostRates: map[string]float64{"127.0.0.1": 20}}))
	start := time.Now()
	for range 3 {
		c.Get(context.Background(), ts.URL, model.Validators{}, nil)
	}
	if time.Since(start) < 90*time.Millisecond {
		t.Fatal("host override not applied")
	}
}

func TestCooldownAfterRepeated429(t *testing.T) {
	ts, calls := serve(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	})
	c := New(fast(Options{Retries: 2, Threshold429: 2, Cooldown429: 150 * time.Millisecond}))
	start := time.Now()
	_, err := c.Get(context.Background(), ts.URL, model.Validators{}, nil)
	var se *StatusError
	if !errors.As(err, &se) || se.Code != 429 {
		t.Fatalf("err = %v, want StatusError 429", err)
	}
	if elapsed := time.Since(start); elapsed < 140*time.Millisecond || calls.Load() != 3 {
		t.Fatalf("took %v with %d calls, cooldown not applied before 3rd attempt", elapsed, calls.Load())
	}
}

func TestNon429ResetsStreak(t *testing.T) {
	g := &gate{}
	g.observe(429, 2, time.Hour)
	g.observe(200, 2, time.Hour)
	g.observe(429, 2, time.Hour)
	if !g.blocked.IsZero() {
		t.Fatal("cooldown started although the streak was broken")
	}
}

func TestCooldownHonorsContext(t *testing.T) {
	g := &gate{blocked: time.Now().Add(time.Hour)}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := g.wait(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want deadline exceeded", err)
	}
}

func TestRejectsOtherSchemes(t *testing.T) {
	c := New(Options{AllowPrivate: true})
	for _, u := range []string{"file:///etc/passwd", "ftp://example.com/x", "example.com/feed", "://bad"} {
		if _, err := c.Get(context.Background(), u, model.Validators{}, nil); err == nil {
			t.Errorf("Get(%q) succeeded, want error", u)
		}
	}
}

func TestRedirectDowngradeRefused(t *testing.T) {
	plain, plainCalls := serve(t, func(_ int, w http.ResponseWriter, _ *http.Request) {})
	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL, http.StatusFound)
	}))
	defer secure.Close()

	c := New(fast(Options{Retries: 3}))
	c.hc.Transport = secure.Client().Transport
	_, err := c.Get(context.Background(), secure.URL, model.Validators{}, nil)
	if !errors.Is(err, errRedirect) {
		t.Fatalf("err = %v, want refused redirect", err)
	}
	if plainCalls.Load() != 0 {
		t.Fatal("downgraded request was sent")
	}
}

func TestRedirectLimit(t *testing.T) {
	ts, calls := serve(t, func(_ int, w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.Path, http.StatusFound)
	})
	_, err := New(fast(Options{Retries: 3})).Get(context.Background(), ts.URL+"/loop", model.Validators{}, nil)
	if !errors.Is(err, errRedirect) {
		t.Fatalf("err = %v, want refused redirect", err)
	}
	if calls.Load() != maxRedirects+1 {
		t.Fatalf("calls = %d, want %d (no retry on redirect errors)", calls.Load(), maxRedirects+1)
	}
}

func TestContextCancelStopsRetries(t *testing.T) {
	ts, calls := serve(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	c := New(Options{AllowPrivate: true, Retries: 10, RetryDelay: time.Hour})
	if _, err := c.Get(ctx, ts.URL, model.Validators{}, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want deadline exceeded", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("calls = %d, want 1", calls.Load())
	}
}

func TestRefusesPrivateTargetsByDefault(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	c := New(Options{Retries: 0})
	if _, err := c.Get(context.Background(), srv.URL, model.Validators{}, nil); err == nil {
		t.Fatal("plain http to loopback must be refused")
	}
	tls := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer tls.Close()
	_, err := c.Get(context.Background(), tls.URL, model.Validators{}, nil)
	if err == nil || !strings.Contains(err.Error(), "non-public address") {
		t.Fatalf("loopback over https must be refused by the dial guard, got %v", err)
	}
}

func TestErrorsNeverLeakQueryOrCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(404) }))
	defer srv.Close()
	c := New(Options{AllowPrivate: true})
	_, err := c.Get(context.Background(), srv.URL+"/feed?token=SECRET", model.Validators{}, nil)
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("status error must not echo the query: %v", err)
	}
	_, err = c.Get(context.Background(), "http://user:pw@example.test/x", model.Validators{}, nil)
	if err == nil || strings.Contains(err.Error(), "pw") {
		t.Fatalf("credentials in URLs must be rejected without echo: %v", err)
	}
	c = New(Options{AllowPrivate: true, Timeout: time.Millisecond})
	_, err = c.Get(context.Background(), "http://127.0.0.1:1/x?token=SECRET", model.Validators{}, nil)
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("transport error must not echo the query: %v", err)
	}
}

func TestNonPublicRanges(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "10.1.2.3", "192.168.0.1", "172.16.5.5", "169.254.169.254", "100.64.0.1", "::1", "fe80::1", "0.0.0.0", "::ffff:10.0.0.1"} {
		if !nonPublic(netip.MustParseAddr(s)) {
			t.Errorf("%s must be non-public", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "93.184.216.34", "2606:4700::1111"} {
		if nonPublic(netip.MustParseAddr(s)) {
			t.Errorf("%s must be public", s)
		}
	}
}
