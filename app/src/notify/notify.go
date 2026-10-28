// Package notify delivers new findings and periodic digests to people. A
// Channel is one delivery route (Slack, a signed JSON webhook, email); the
// pipeline holds a list of them and tracks delivery per channel, so one
// failing channel never repeats alerts on the others.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/query"
)

// BatchSize is the most alerts sent in one message, to stay under Slack limits.
const BatchSize = 10

// Alert is one new vulnerability with the findings it created.
type Alert struct {
	Vuln     *model.Vulnerability
	Findings []model.Finding
}

// Channel is one way of reaching people. An error from Send or SendDigest
// means nothing in that delivery counts as notified. Errors never contain a
// secret (webhook URL, signing key, password).
type Channel interface {
	Name() string // "slack", "webhook", "email"; the key in Finding.Alerted
	// Send delivers one batch of new alerts.
	Send(ctx context.Context, batch []Alert, now time.Time) error
	// SendDigest delivers a periodic summary of what is still open.
	SendDigest(ctx context.Context, d Digest, now time.Time) error
}

// Digest summarises open work. Env "" means all environments. Items is the
// part worth listing (the caller sorts and caps it); Truncated counts the
// items left out.
type Digest struct {
	Env        model.Env
	Open       int
	Overdue    int
	BySeverity map[model.Severity]int
	Items      []DigestItem
	Truncated  int
}

// DigestItem is one open vulnerability in a digest.
type DigestItem struct {
	ID, Title string
	Severity  model.Severity
	Projects  []string
	Age       string
	KEV       bool
	Overdue   bool
	Owner     string
	URL       string
}

// ---- Slack ----

type Slack struct {
	URL    string
	Client *http.Client
	Delay  time.Duration // base retry delay
}

var _ Channel = (*Slack)(nil)

// NewSlack validates the webhook. Its URL is a secret: it is never logged and
// is stripped from transport errors.
func NewSlack(raw string) (*Slack, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, errors.New("slack webhook must be a valid https URL")
	}
	return &Slack{URL: raw, Client: &http.Client{Timeout: 15 * time.Second}, Delay: 2 * time.Second}, nil
}

func (s *Slack) Name() string { return "slack" }

func (s *Slack) Send(ctx context.Context, batch []Alert, now time.Time) error {
	return s.post(ctx, Format(batch, now))
}

func (s *Slack) SendDigest(ctx context.Context, d Digest, _ time.Time) error {
	return s.post(ctx, FormatDigest(d))
}

func (s *Slack) post(ctx context.Context, text string) error {
	body, err := json.Marshal(map[string]string{"text": text})
	if err != nil {
		return err
	}
	return postJSON(ctx, s.Client, s.Delay, s.URL, body, nil, "slack", " (check the webhook URL)",
		func(code int) bool { return code == http.StatusOK })
}

// postJSON POSTs body with up to 3 attempts. Network errors, 429 and 5xx are
// retried with backoff (Retry-After is honoured up to a minute); any other
// status fails at once. The URL is a secret: every error is stripped of it.
func postJSON(ctx context.Context, c *http.Client, delay time.Duration, rawURL string, body []byte,
	header http.Header, name, hint string, ok func(int) bool) error {
	var last error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(delay << attempt):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(body))
		if err != nil {
			return errors.New(name + ": invalid URL") // the parse error would quote it
		}
		req.Header.Set("Content-Type", "application/json")
		for k, v := range header {
			req.Header[k] = v
		}
		resp, err := c.Do(req)
		if err != nil {
			var ue *url.Error
			if errors.As(err, &ue) {
				err = ue.Err // the wrapper carries the secret URL
			}
			last = err
			continue
		}
		resp.Body.Close()
		switch {
		case ok(resp.StatusCode):
			return nil
		case resp.StatusCode == http.StatusTooManyRequests:
			if secs, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && secs > 0 && secs <= 60 {
				select {
				case <-time.After(time.Duration(secs) * time.Second):
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			last = fmt.Errorf("%s: status %d", name, resp.StatusCode)
		case resp.StatusCode >= 500:
			last = fmt.Errorf("%s: status %d", name, resp.StatusCode)
		default:
			return fmt.Errorf("%s: status %d%s", name, resp.StatusCode, hint) // retrying will not help
		}
	}
	return last
}

// ---- Slack text ----

// Format renders a batch as Slack mrkdwn.
func Format(batch []Alert, now time.Time) string {
	var b strings.Builder
	fmt.Fprintf(&b, ":rotating_light: *%d new vulnerabilit%s*\n", len(batch), plural(len(batch)))
	for _, a := range batch {
		v := a.Vuln
		fmt.Fprintf(&b, "\n• *%s* %s — %s\n", strings.ToUpper(string(v.Severity)), link(v.ID, alertURL(v)), esc(v.Title))
		if len(v.Techs) > 0 {
			fmt.Fprintf(&b, "   tech: %s\n", esc(strings.Join(v.Techs, ", ")))
		}
		if parts := exploitParts(v); len(parts) > 0 {
			fmt.Fprintf(&b, "   *%s*\n", esc(strings.Join(parts, " · ")))
		}
		fmt.Fprintf(&b, "   %s\n", esc(strings.Join(factParts(v, now), " · ")))
		for _, p := range groupEnvs(a.Findings) {
			fmt.Fprintf(&b, "   %s: %s", esc(p.project), p.envs)
			if len(p.matched) > 0 {
				fmt.Fprintf(&b, " (%s)", esc(strings.Join(p.matched, ", ")))
			}
			b.WriteString("\n")
		}
	}
	return b.String()
}

// FormatDigest renders a digest as Slack mrkdwn.
func FormatDigest(d Digest) string {
	var b strings.Builder
	b.WriteString(":clipboard: *cvewatch digest*")
	if d.Env != "" {
		fmt.Fprintf(&b, " · %s", esc(string(d.Env)))
	}
	fmt.Fprintf(&b, "\n%d open · %d overdue\n", d.Open, d.Overdue)
	if s := severityLine(d.BySeverity); s != "" {
		b.WriteString(esc(s) + "\n")
	}
	for _, it := range d.Items {
		fmt.Fprintf(&b, "\n• *%s* %s — %s\n", strings.ToUpper(string(it.Severity)), link(it.ID, it.URL), esc(it.Title))
		if flags := itemFlags(it); len(flags) > 0 {
			fmt.Fprintf(&b, "   *%s*\n", esc(strings.Join(flags, ", ")))
		}
		if line := itemFacts(it); line != "" {
			fmt.Fprintf(&b, "   %s\n", esc(line))
		}
	}
	if d.Truncated > 0 {
		fmt.Fprintf(&b, "\n…and %d more not shown\n", d.Truncated)
	}
	return b.String()
}

var severityOrder = []model.Severity{model.SevCritical, model.SevHigh, model.SevMedium, model.SevLow, model.SevUnknown}

// severityLine is "critical 2 · high 4", most severe first, zeros left out.
func severityLine(m map[model.Severity]int) string {
	var parts []string
	for _, s := range severityOrder {
		if n := m[s]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", s, n))
		}
	}
	return strings.Join(parts, " · ")
}

func itemFlags(it DigestItem) []string {
	var flags []string
	if it.KEV {
		flags = append(flags, "KEV")
	}
	if it.Overdue {
		flags = append(flags, "overdue")
	}
	return flags
}

func itemFacts(it DigestItem) string {
	var parts []string
	if len(it.Projects) > 0 {
		parts = append(parts, strings.Join(it.Projects, ", "))
	}
	if it.Age != "" {
		parts = append(parts, "age "+it.Age)
	}
	if it.Owner != "" {
		parts = append(parts, "owner "+it.Owner)
	}
	return strings.Join(parts, " · ")
}

// factParts is the one-line summary: age, article count and fix status.
func factParts(v *model.Vulnerability, now time.Time) []string {
	arts := articleCount(v)
	parts := []string{}
	if age := ageOf(v, now); age != "" {
		parts = append(parts, "published "+age+" ago")
	}
	parts = append(parts, fmt.Sprintf("%d article%s", arts, map[bool]string{true: "", false: "s"}[arts == 1]))
	return append(parts, fixText(v))
}

func articleCount(v *model.Vulnerability) int { return len(query.Articles(v.Refs)) }

func ageOf(v *model.Vulnerability, now time.Time) string { return query.Age(v.Published, now) }

func fixText(v *model.Vulnerability) string {
	switch fixKind(v) {
	case "official":
		return "official fix"
	case "reference":
		return "fix reference"
	}
	return "no fix known"
}

// fixKind is "none", "reference" or "official".
func fixKind(v *model.Vulnerability) string {
	kind := "none"
	for _, f := range v.Fixes {
		kind = "reference"
		if f.Official {
			return "official"
		}
	}
	return kind
}

// exploitParts is what makes a vulnerability urgent regardless of its score:
// listed as exploited (KEV, with CISA's due date) and the EPSS probability.
func exploitParts(v *model.Vulnerability) []string {
	var parts []string
	if v.KEV != nil {
		s := "KEV"
		if !v.KEV.DueDate.IsZero() {
			s += ", remediation due " + v.KEV.DueDate.UTC().Format("2006-01-02")
		}
		parts = append(parts, s)
	}
	if v.EPSS != nil {
		parts = append(parts, "EPSS "+percent(v.EPSS.Score))
	}
	return parts
}

// percent renders a probability: "43%", "4.3%".
func percent(p float64) string {
	p *= 100
	if p >= 10 {
		return strconv.FormatFloat(p, 'f', 0, 64) + "%"
	}
	return strconv.FormatFloat(p, 'f', 1, 64) + "%"
}

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

// alertURL is the vulnerability's first reference, or "".
func alertURL(v *model.Vulnerability) string {
	if len(v.Refs) == 0 {
		return ""
	}
	return v.Refs[0].URL
}

// link is a Slack link, or the bare id without a URL. Characters that would
// end the link early are percent-encoded; feeds are untrusted.
func link(id, u string) string {
	if u == "" {
		return esc(id)
	}
	u = strings.NewReplacer("<", "%3C", ">", "%3E", "|", "%7C", " ", "%20", "\n", "%0A", "\r", "%0D").Replace(u)
	return fmt.Sprintf("<%s|%s>", u, esc(id))
}

// esc escapes the three characters Slack treats as markup.
func esc(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

type projectEnvs struct {
	project, envs string
	matched       []string
}

// groupEnvs folds findings into one line per project, e.g. "dev, int, prod".
func groupEnvs(fs []model.Finding) []projectEnvs {
	var out []projectEnvs
	for _, f := range fs {
		i := slices.IndexFunc(out, func(p projectEnvs) bool { return p.project == f.Project })
		if i < 0 {
			out = append(out, projectEnvs{project: f.Project, envs: string(f.Env), matched: f.Matched})
			continue
		}
		out[i].envs += ", " + string(f.Env)
	}
	return out
}
