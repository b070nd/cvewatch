package notify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"syscall"
	"time"

	"github.com/b070nd/cvewatch/app/src/model"
)

// SchemaVersion is the version of the webhook JSON body.
const SchemaVersion = 1

// SignatureHeader carries "sha256=<hex HMAC-SHA256 of the exact body>".
const SignatureHeader = "X-Cvewatch-Signature"

// Webhook POSTs a JSON document per delivery to a generic endpoint.
type Webhook struct {
	URL    string
	Secret string // signs the body when set
	Client *http.Client
	Delay  time.Duration // base retry delay
}

var _ Channel = (*Webhook)(nil)

// NewWebhook validates the endpoint. The URL is treated as a secret (it often
// embeds a token): it never appears in errors. Unless allowPrivate is set the
// scheme must be https and connections to loopback, private, link-local and
// other non-public addresses are refused when dialing (so DNS tricks and
// redirects cannot reach internal services). With allowPrivate, http is
// allowed and nothing is blocked; use it for internal receivers.
func NewWebhook(rawURL, secret string, allowPrivate bool) (*Webhook, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" || u.Hostname() == "" {
		return nil, errors.New("webhook must be a valid URL")
	}
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && allowPrivate:
	case u.Scheme == "http":
		return nil, errors.New("webhook must use https (http is only allowed for private receivers)")
	default:
		return nil, errors.New("webhook must be a valid https URL")
	}
	c := &http.Client{
		Timeout: 15 * time.Second,
		// A redirect could point at an internal address or downgrade to http.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	if !allowPrivate {
		c.Transport = &http.Transport{ // no proxy: the dial check must see the real destination
			DialContext:         (&net.Dialer{Timeout: 10 * time.Second, Control: publicOnly}).DialContext,
			TLSHandshakeTimeout: 10 * time.Second,
		}
	}
	return &Webhook{URL: rawURL, Secret: secret, Client: c, Delay: 2 * time.Second}, nil
}

// publicOnly runs on the resolved address just before connecting.
func publicOnly(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return errors.New("address not allowed")
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || nonPublic(ip) {
		return errors.New("address not allowed (private or reserved)")
	}
	return nil
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

func nonPublic(ip netip.Addr) bool {
	ip = ip.Unmap()
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() || cgnat.Contains(ip)
}

func (w *Webhook) Name() string { return "webhook" }

type webhookDoc struct {
	SchemaVersion int         `json:"schema_version"`
	Type          string      `json:"type"`
	GeneratedAt   string      `json:"generated_at"`
	Alerts        []jsonAlert `json:"alerts,omitempty"` // present for type "alerts" only
	Digest        *jsonDigest `json:"digest,omitempty"` // present for type "digest" only
}

type jsonAlert struct {
	ID       string       `json:"id"`
	Severity string       `json:"severity"`
	Title    string       `json:"title"`
	URL      string       `json:"url"`
	Techs    []string     `json:"techs"`
	Age      string       `json:"age"`
	Articles int          `json:"articles"`
	Fix      string       `json:"fix"` // none | reference | official
	KEV      bool         `json:"kev"`
	Targets  []jsonTarget `json:"targets"`
}

type jsonTarget struct {
	Project string `json:"project"`
	Env     string `json:"env"`
	Applies string `json:"applies"`
}

type jsonDigest struct {
	Env        string         `json:"env"`
	Open       int            `json:"open"`
	Overdue    int            `json:"overdue"`
	BySeverity map[string]int `json:"by_severity"`
	Items      []jsonItem     `json:"items"`
	Truncated  int            `json:"truncated"`
}

type jsonItem struct {
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Severity string   `json:"severity"`
	Projects []string `json:"projects"`
	Age      string   `json:"age"`
	KEV      bool     `json:"kev"`
	Overdue  bool     `json:"overdue"`
	Owner    string   `json:"owner"`
	URL      string   `json:"url"`
}

func (w *Webhook) Send(ctx context.Context, batch []Alert, now time.Time) error {
	return w.post(ctx, alertsDoc(batch, now))
}

func (w *Webhook) SendDigest(ctx context.Context, d Digest, now time.Time) error {
	return w.post(ctx, digestDoc(d, now))
}

func (w *Webhook) post(ctx context.Context, doc webhookDoc) error {
	body, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	h := http.Header{"User-Agent": {"cvewatch"}}
	if w.Secret != "" {
		h.Set(SignatureHeader, Sign(w.Secret, body))
	}
	return postJSON(ctx, w.Client, w.Delay, w.URL, body, h, "webhook", "",
		func(code int) bool { return code >= 200 && code < 300 })
}

// Sign returns the signature header value for body: "sha256=" and the hex
// HMAC-SHA256 under secret. Receivers recompute it over the raw body.
func Sign(secret string, body []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write(body)
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

func alertsDoc(batch []Alert, now time.Time) webhookDoc {
	alerts := make([]jsonAlert, 0, len(batch))
	for _, a := range batch {
		v := a.Vuln
		ja := jsonAlert{
			ID: v.ID, Severity: string(v.Severity), Title: v.Title, URL: alertURL(v),
			Techs: nonNil(v.Techs), Age: ageOf(v, now), Articles: articleCount(v), Fix: fixKind(v),
			KEV: v.KEV != nil, Targets: make([]jsonTarget, 0, len(a.Findings)),
		}
		for _, f := range a.Findings {
			applies := f.Applies
			if applies == "" {
				applies = model.AppUnknown
			}
			ja.Targets = append(ja.Targets, jsonTarget{Project: f.Project, Env: string(f.Env), Applies: string(applies)})
		}
		alerts = append(alerts, ja)
	}
	return webhookDoc{SchemaVersion: SchemaVersion, Type: "alerts", GeneratedAt: stamp(now), Alerts: alerts}
}

func digestDoc(d Digest, now time.Time) webhookDoc {
	jd := &jsonDigest{
		Env: string(d.Env), Open: d.Open, Overdue: d.Overdue, Truncated: d.Truncated,
		BySeverity: map[string]int{}, Items: make([]jsonItem, 0, len(d.Items)),
	}
	for s, n := range d.BySeverity {
		jd.BySeverity[string(s)] = n
	}
	for _, it := range d.Items {
		jd.Items = append(jd.Items, jsonItem{
			ID: it.ID, Title: it.Title, Severity: string(it.Severity), Projects: nonNil(it.Projects),
			Age: it.Age, KEV: it.KEV, Overdue: it.Overdue, Owner: it.Owner, URL: it.URL,
		})
	}
	return webhookDoc{SchemaVersion: SchemaVersion, Type: "digest", GeneratedAt: stamp(now), Digest: jd}
}

func stamp(now time.Time) string { return now.UTC().Format(time.RFC3339) }

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
