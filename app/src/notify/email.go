package notify

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/b070nd/cvewatch/app/src/model"
)

// EmailConfig is the SMTP delivery setup. Authentication is used only when
// Username is set; STARTTLS is used whenever the server offers it.
type EmailConfig struct {
	Host     string
	Port     int // default 587
	From     string
	To       []string
	Username string
	Password string
}

// Email sends plain-text mail through an SMTP server.
type Email struct {
	cfg  EmailConfig
	send func(addr string, a smtp.Auth, from string, to []string, msg []byte) error // injectable for tests
}

var _ Channel = (*Email)(nil)

// NewEmail validates the configuration. Addresses must parse and carry no
// line breaks, so nothing configured can add headers to a message.
func NewEmail(c EmailConfig) (*Email, error) {
	c.Host = strings.TrimSpace(c.Host)
	if c.Host == "" || strings.ContainsAny(c.Host, " \t\r\n/") {
		return nil, errors.New("email: host is required")
	}
	if c.Port == 0 {
		c.Port = 587
	}
	if c.Port < 1 || c.Port > 65535 {
		return nil, fmt.Errorf("email: port %d is out of range", c.Port)
	}
	if _, err := parseAddr(c.From); err != nil {
		return nil, fmt.Errorf("email: from: %w", err)
	}
	if len(c.To) == 0 {
		return nil, errors.New("email: at least one recipient is required")
	}
	for _, t := range c.To {
		if _, err := parseAddr(t); err != nil {
			return nil, fmt.Errorf("email: to: %w", err)
		}
	}
	c.To = append([]string(nil), c.To...)
	return &Email{cfg: c, send: smtpSend}, nil
}

func parseAddr(s string) (*mail.Address, error) {
	if strings.ContainsAny(s, "\r\n") {
		return nil, errors.New("address contains a line break")
	}
	a, err := mail.ParseAddress(s)
	if err != nil {
		return nil, errors.New("invalid address")
	}
	return a, nil
}

func (e *Email) Name() string { return "email" }

func (e *Email) Send(ctx context.Context, batch []Alert, now time.Time) error {
	top := model.SevUnknown
	for _, a := range batch {
		if a.Vuln.Severity.Rank() > top.Rank() {
			top = a.Vuln.Severity
		}
	}
	subject := fmt.Sprintf("[cvewatch] %d new vulnerabilit%s (highest: %s)", len(batch), plural(len(batch)), top)
	return e.deliver(ctx, subject, formatEmail(batch, now), now)
}

func (e *Email) SendDigest(ctx context.Context, d Digest, now time.Time) error {
	subject := fmt.Sprintf("[cvewatch] digest: %d open", d.Open)
	return e.deliver(ctx, subject, formatDigestEmail(d), now)
}

func (e *Email) deliver(ctx context.Context, subject, body string, now time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	from, _ := mail.ParseAddress(e.cfg.From) // validated in NewEmail
	to := make([]string, 0, len(e.cfg.To))
	hdrTo := make([]string, 0, len(e.cfg.To))
	for _, t := range e.cfg.To {
		a, _ := mail.ParseAddress(t)
		to = append(to, a.Address)
		hdrTo = append(hdrTo, a.String())
	}
	msg := buildMessage(from.String(), hdrTo, subject, body, now)
	var auth smtp.Auth
	if e.cfg.Username != "" {
		auth = smtp.PlainAuth("", e.cfg.Username, e.cfg.Password, e.cfg.Host) // refuses to run unencrypted off localhost
	}
	addr := net.JoinHostPort(e.cfg.Host, strconv.Itoa(e.cfg.Port))
	if err := e.send(addr, auth, from.Address, to, msg); err != nil {
		return fmt.Errorf("email: %w", err)
	}
	return nil
}

// buildMessage assembles the RFC 5322 message. Every header value goes through
// header(): feed text must never be able to start a new header line.
func buildMessage(from string, to []string, subject, body string, now time.Time) []byte {
	var b strings.Builder
	put := func(k, v string) { b.WriteString(k + ": " + v + "\r\n") }
	put("From", header(from))
	put("To", header(strings.Join(to, ", ")))
	put("Subject", mime.QEncoding.Encode("utf-8", header(subject)))
	put("Date", now.Format(time.RFC1123Z))
	put("MIME-Version", "1.0")
	put("Content-Type", "text/plain; charset=utf-8")
	put("Content-Transfer-Encoding", "8bit")
	b.WriteString("\r\n")
	b.WriteString(strings.ReplaceAll(strings.ReplaceAll(body, "\r\n", "\n"), "\n", "\r\n"))
	return []byte(b.String())
}

// header removes CR, LF and every other control character from a header value.
func header(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}

// line makes untrusted text safe for one line of the body: control characters
// (including line breaks) become spaces and the length is capped.
func line(s string) string {
	s = strings.Join(strings.Fields(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)), " ")
	if r := []rune(s); len(r) > 300 {
		s = string(r[:300]) + "…"
	}
	return s
}

func formatEmail(batch []Alert, now time.Time) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d new vulnerabilit%s\n", len(batch), plural(len(batch)))
	for _, a := range batch {
		v := a.Vuln
		fmt.Fprintf(&b, "\n[%s] %s\n", strings.ToUpper(line(string(v.Severity))), line(v.ID))
		fmt.Fprintf(&b, "  Title:    %s\n", line(v.Title))
		if u := alertURL(v); u != "" {
			fmt.Fprintf(&b, "  URL:      %s\n", line(u))
		}
		if len(v.Techs) > 0 {
			fmt.Fprintf(&b, "  Tech:     %s\n", line(strings.Join(v.Techs, ", ")))
		}
		for _, p := range groupEnvs(a.Findings) {
			fmt.Fprintf(&b, "  Project:  %s: %s", line(p.project), line(p.envs))
			if len(p.matched) > 0 {
				fmt.Fprintf(&b, " (%s)", line(strings.Join(p.matched, ", ")))
			}
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "  Facts:    %s\n", line(strings.Join(factParts(v, now), " · ")))
		if parts := exploitParts(v); len(parts) > 0 {
			fmt.Fprintf(&b, "  KEV/EPSS: %s\n", line(strings.Join(parts, " · ")))
		}
	}
	return b.String()
}

func formatDigestEmail(d Digest) string {
	var b strings.Builder
	b.WriteString("cvewatch digest")
	if d.Env != "" {
		b.WriteString(" (" + line(string(d.Env)) + ")")
	}
	fmt.Fprintf(&b, "\n%d open, %d overdue\n", d.Open, d.Overdue)
	if s := severityLine(d.BySeverity); s != "" {
		b.WriteString(s + "\n")
	}
	for _, it := range d.Items {
		fmt.Fprintf(&b, "\n[%s] %s  %s\n", strings.ToUpper(line(string(it.Severity))), line(it.ID), line(it.Title))
		if flags := itemFlags(it); len(flags) > 0 {
			fmt.Fprintf(&b, "  Flags:    %s\n", strings.Join(flags, ", "))
		}
		if f := itemFacts(it); f != "" {
			fmt.Fprintf(&b, "  Details:  %s\n", line(f))
		}
		if it.URL != "" {
			fmt.Fprintf(&b, "  URL:      %s\n", line(it.URL))
		}
	}
	if d.Truncated > 0 {
		fmt.Fprintf(&b, "\n...and %d more not shown\n", d.Truncated)
	}
	return b.String()
}

// smtpSend delivers one message, with timeouts. It uses STARTTLS when the
// server offers it (certificate verified) and authenticates only when asked;
// PlainAuth itself refuses to send a password over an unencrypted link to a
// non-local host.
func smtpSend(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	conn, err := (&net.Dialer{Timeout: 15 * time.Second}).Dial("tcp", addr)
	if err != nil {
		return err
	}
	conn.SetDeadline(time.Now().Add(60 * time.Second))
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
	if ok, _ := c.Extension("STARTTLS"); ok {
		if err := c.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); err != nil {
			return err
		}
	}
	if a != nil {
		if ok, _ := c.Extension("AUTH"); !ok {
			return errors.New("server does not support authentication")
		}
		if err := c.Auth(a); err != nil {
			return err
		}
	}
	if err := c.Mail(from); err != nil {
		return err
	}
	for _, t := range to {
		if err := c.Rcpt(t); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}
