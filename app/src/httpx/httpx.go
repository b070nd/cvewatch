// Package httpx is a polite and resilient HTTP GET client for feed polling.
// It limits the request rate per host, retries with backoff, honors
// Retry-After, and backs off a host that keeps answering 429.
// It sends an honest User-Agent and never pretends to be a browser.
package httpx

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/b070nd/cvewatch/app/src/model"
)

const (
	defaultUserAgent  = "cvewatch/1.0"
	defaultTimeout    = 30 * time.Second
	defaultRetryDelay = time.Second
	defaultMaxBody    = 16 << 20
	maxWait           = 5 * time.Minute // upper bound for any single retry wait
	maxRedirects      = 5
	drainLimit        = 4096
)

var (
	errRedirect     = errors.New("redirect refused")
	errBodyTooLarge = errors.New("response body too large")
)

// Options configures a Client. Zero values select safe defaults.
type Options struct {
	UserAgent    string
	Timeout      time.Duration      // per attempt, including reading the body
	Retries      int                // extra attempts after the first
	RetryDelay   time.Duration      // first backoff; doubles on each retry
	Rate         float64            // requests per second per host; 0 means unlimited
	HostRates    map[string]float64 // per-host overrides of Rate
	MaxBody      int64              // bytes; default 16 MiB
	Threshold429 int                // consecutive 429s that start a cooldown; 0 disables
	Cooldown429  time.Duration      // how long a host is blocked after that

	// AllowPrivate permits plain http and connections to loopback, private
	// and link-local addresses. Off by default so a feed URL, or a redirect
	// from one, can never reach internal services (SSRF).
	AllowPrivate bool
}

// Response is the result of a successful GET.
type Response struct {
	Body        []byte
	NotModified bool // server answered 304; Body is empty
	Validators  model.Validators
	Link        string // the Link header, for paged APIs
}

// StatusError reports an unexpected HTTP status.
type StatusError struct {
	Code int
	URL  string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("GET %s: unexpected status %d %s", e.URL, e.Code, http.StatusText(e.Code))
}

// RateLimitError reports that the host refused the request because a request
// limit is used up, and when it allows requests again.
type RateLimitError struct {
	Host  string
	Code  int
	Until time.Time
}

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("rate limited by %s until %s; set auth_env on the source for a higher limit", e.Host, e.Until.Local().Format("15:04"))
}

// rateLimitUntil tells whether a 403 or 429 answer is a request limit and when
// it ends: Retry-After, else X-RateLimit-Reset (epoch seconds) when
// X-RateLimit-Remaining is 0. Other answers are not limits.
func rateLimitUntil(h http.Header, now time.Time) (time.Time, bool) {
	if v := strings.TrimSpace(h.Get("Retry-After")); v != "" {
		if secs, err := strconv.ParseInt(v, 10, 64); err == nil && secs >= 0 {
			return now.Add(time.Duration(min(secs, 1<<30)) * time.Second), true
		}
		if t, err := http.ParseTime(v); err == nil {
			return t, true
		}
	}
	if strings.TrimSpace(h.Get("X-RateLimit-Remaining")) == "0" {
		if secs, err := strconv.ParseInt(strings.TrimSpace(h.Get("X-RateLimit-Reset")), 10, 64); err == nil && secs > 0 {
			return time.Unix(secs, 0), true
		}
	}
	return time.Time{}, false
}

// redact drops credentials and the query string, where API tokens tend to
// live, so URLs are safe to put in logs and errors.
func redact(u *url.URL) string {
	return (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path}).String()
}

// stripURL removes the full request URL that net/http adds to its errors.
func stripURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// nonPublic reports addresses a feed fetcher has no business connecting to.
func nonPublic(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsMulticast() || a.IsUnspecified() || cgnat.Contains(a)
}

// publicOnly runs after DNS resolution, on the address actually dialled,
// so DNS tricks cannot point a public name at an internal address.
func publicOnly(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	if a, err := netip.ParseAddr(host); err != nil || nonPublic(a) {
		return fmt.Errorf("refusing to connect to non-public address %s", host)
	}
	return nil
}

// Client is safe for concurrent use.
type Client struct {
	opt Options
	hc  *http.Client

	mu    sync.Mutex
	hosts map[string]*gate
}

// New returns a Client with defaults applied to o.
func New(o Options) *Client {
	if o.UserAgent == "" {
		o.UserAgent = defaultUserAgent
	}
	if o.Timeout <= 0 {
		o.Timeout = defaultTimeout
	}
	if o.RetryDelay <= 0 {
		o.RetryDelay = defaultRetryDelay
	}
	if o.MaxBody <= 0 {
		o.MaxBody = defaultMaxBody
	}
	o.Retries = max(o.Retries, 0)
	rates := make(map[string]float64, len(o.HostRates))
	for h, r := range o.HostRates {
		rates[strings.ToLower(h)] = r
	}
	o.HostRates = rates
	return &Client{
		opt:   o,
		hc:    &http.Client{Timeout: o.Timeout, CheckRedirect: checkRedirect, Transport: transport(o)},
		hosts: map[string]*gate{},
	}
}

// transport is the default transport plus the address guard. Proxies from
// the environment still apply; behind an internal proxy set AllowPrivate.
func transport(o Options) *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	if !o.AllowPrivate {
		d.Control = publicOnly
	}
	t.DialContext = d.DialContext
	return t
}

// retryError marks a failed attempt that may be tried again. after is the
// wait the server asked for, if any.
type retryError struct {
	err   error
	after time.Duration
}

func (e *retryError) Error() string { return e.err.Error() }
func (e *retryError) Unwrap() error { return e.err }

// Get fetches rawURL. Validators in prev make the request conditional.
// Every attempt, including retries, waits for the host's rate limiter.
// Redirects to another host are not rate limited under that host's name.
func (c *Client) Get(ctx context.Context, rawURL string, prev model.Validators, headers map[string]string) (*Response, error) {
	u, err := c.parseURL(rawURL)
	if err != nil {
		return nil, err
	}
	shown := redact(u)
	g := c.gate(strings.ToLower(u.Hostname()))
	attempts := c.opt.Retries + 1
	for i := 0; ; i++ {
		if until := g.limitedUntil(); time.Now().Before(until) { // the host said so a moment ago
			return nil, fmt.Errorf("httpx: %w", &RateLimitError{Host: u.Hostname(), Until: until})
		}
		if err := g.wait(ctx); err != nil {
			return nil, fmt.Errorf("httpx: GET %s: %w", shown, err)
		}
		resp, err := c.attempt(ctx, g, u, prev, headers)
		if err == nil {
			return resp, nil
		}
		var re *retryError
		if !errors.As(err, &re) {
			return nil, fmt.Errorf("httpx: %w", err)
		}
		if i+1 >= attempts {
			return nil, fmt.Errorf("httpx: giving up after %d attempts: %w", attempts, re.err)
		}
		if err := sleep(ctx, c.backoff(i, re.after)); err != nil {
			return nil, fmt.Errorf("httpx: GET %s: %w", shown, err)
		}
	}
}

func (c *Client) parseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("httpx: invalid URL: %w", stripURL(err))
	}
	if u.Host == "" || u.User != nil {
		return nil, fmt.Errorf("httpx: unsupported URL %q: need a host and no credentials", redact(u))
	}
	if u.Scheme != "https" && !(c.opt.AllowPrivate && u.Scheme == "http") {
		return nil, fmt.Errorf("httpx: unsupported URL %q: only https is allowed", redact(u))
	}
	return u, nil
}

// attempt performs one request. Errors that are worth retrying come back as *retryError.
func (c *Client) attempt(ctx context.Context, g *gate, u *url.URL, prev model.Validators, headers map[string]string) (*Response, error) {
	req, err := c.newRequest(ctx, u, prev, headers)
	if err != nil {
		return nil, err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		if ctx.Err() != nil || errors.Is(err, errRedirect) {
			return nil, err
		}
		return nil, &retryError{err: stripURL(err)}
	}
	defer resp.Body.Close()
	g.observe(resp.StatusCode, c.opt.Threshold429, c.opt.Cooldown429)

	now := time.Now()
	until, limited := time.Time{}, false
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		until, limited = rateLimitUntil(resp.Header, now)
	}
	switch code := resp.StatusCode; {
	case limited:
		io.Copy(io.Discard, io.LimitReader(resp.Body, drainLimit))
		err := &RateLimitError{Host: u.Hostname(), Code: code, Until: until}
		wait := until.Sub(now)
		if wait > c.waitCap() { // not worth sleeping inside a cycle
			g.limitUntil(until)
			return nil, err
		}
		return nil, &retryError{err: err, after: max(wait, 0)}
	case code == http.StatusNotModified:
		return &Response{NotModified: true, Validators: prev}, nil
	case code >= 200 && code < 300:
		return c.readBody(ctx, resp)
	case code == http.StatusTooManyRequests || code >= 500:
		io.Copy(io.Discard, io.LimitReader(resp.Body, drainLimit))
		return nil, &retryError{
			err:   &StatusError{Code: code, URL: redact(u)},
			after: retryAfter(resp.Header.Get("Retry-After"), time.Now()),
		}
	default:
		io.Copy(io.Discard, io.LimitReader(resp.Body, drainLimit))
		return nil, &StatusError{Code: code, URL: redact(u)}
	}
}

// waitCap is the longest wait for a request limit that is worth it.
func (c *Client) waitCap() time.Duration {
	if c.opt.Cooldown429 > 0 {
		return c.opt.Cooldown429
	}
	return maxWait
}

func (c *Client) newRequest(ctx context.Context, u *url.URL, prev model.Validators, headers map[string]string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", c.opt.UserAgent)
	if prev.ETag != "" {
		req.Header.Set("If-None-Match", prev.ETag)
	}
	if prev.LastModified != "" {
		req.Header.Set("If-Modified-Since", prev.LastModified)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req, nil
}

// readBody reads at most MaxBody bytes and fails if the body is larger.
func (c *Client) readBody(ctx context.Context, resp *http.Response) (*Response, error) {
	limit := c.opt.MaxBody
	if resp.ContentLength > limit {
		return nil, fmt.Errorf("%w: %d bytes, limit %d", errBodyTooLarge, resp.ContentLength, limit)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, &retryError{err: fmt.Errorf("read body: %w", err)}
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("%w: more than %d bytes", errBodyTooLarge, limit)
	}
	return &Response{
		Body: body,
		Validators: model.Validators{
			ETag:         resp.Header.Get("ETag"),
			LastModified: resp.Header.Get("Last-Modified"),
		},
		Link: resp.Header.Get("Link"),
	}, nil
}

// backoff is the wait after failed attempt i (0-based): the server's
// Retry-After if given, else RetryDelay doubled once per earlier failure.
func (c *Client) backoff(i int, after time.Duration) time.Duration {
	if after > 0 {
		return after
	}
	d := c.opt.RetryDelay
	for ; i > 0 && d < maxWait; i-- {
		d *= 2
	}
	return min(d, maxWait)
}

// retryAfter reads a Retry-After value given in seconds or as an HTTP date.
// It returns 0 when the value is missing or invalid, and caps it at maxWait.
func retryAfter(v string, now time.Time) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	var d time.Duration
	if secs, err := strconv.ParseInt(v, 10, 64); err == nil {
		d = time.Duration(min(secs, int64(maxWait/time.Second))) * time.Second
	} else if t, err := http.ParseTime(v); err == nil {
		d = t.Sub(now)
	}
	return min(max(d, 0), maxWait)
}

func (c *Client) gate(host string) *gate {
	c.mu.Lock()
	defer c.mu.Unlock()
	g, ok := c.hosts[host]
	if !ok {
		g = &gate{interval: c.interval(host)}
		c.hosts[host] = g
	}
	return g
}

func (c *Client) interval(host string) time.Duration {
	rate := c.opt.Rate
	if r, ok := c.opt.HostRates[host]; ok {
		rate = r
	}
	if rate <= 0 {
		return 0
	}
	return time.Duration(float64(time.Second) / rate)
}

// checkRedirect allows a few redirects, never from https to http. When the
// target is another host, caller headers (such as API keys) are dropped.
func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) > maxRedirects {
		return fmt.Errorf("%w: more than %d redirects", errRedirect, maxRedirects)
	}
	last := via[len(via)-1]
	if last.URL.Scheme == "https" && req.URL.Scheme != "https" {
		return fmt.Errorf("%w: downgrade from https to %s", errRedirect, req.URL.Scheme)
	}
	if req.URL.Host != via[0].URL.Host {
		req.Header = http.Header{}
		for _, k := range []string{"User-Agent", "Accept"} {
			if v := via[0].Header.Get(k); v != "" {
				req.Header.Set(k, v)
			}
		}
	}
	return nil
}
