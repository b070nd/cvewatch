package notify

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/b070nd/cvewatch/app/src/model"
)

func goodConfig() EmailConfig {
	return EmailConfig{Host: "mail.example.com", Port: 2525, From: "cvewatch <alerts@example.com>", To: []string{"ops@example.com", "Bob <bob@example.com>"}}
}

type sent struct {
	addr string
	auth smtp.Auth
	from string
	to   []string
	msg  []byte
}

func fakeEmail(t *testing.T, c EmailConfig) (*Email, *sent) {
	t.Helper()
	e, err := NewEmail(c)
	if err != nil {
		t.Fatal(err)
	}
	var got sent
	e.send = func(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
		got = sent{addr, a, from, to, msg}
		return nil
	}
	return e, &got
}

func TestNewEmailValidation(t *testing.T) {
	mut := func(f func(*EmailConfig)) EmailConfig { c := goodConfig(); f(&c); return c }
	for name, c := range map[string]EmailConfig{
		"no host":       mut(func(c *EmailConfig) { c.Host = "" }),
		"host with sp":  mut(func(c *EmailConfig) { c.Host = "a b" }),
		"port low":      mut(func(c *EmailConfig) { c.Port = -1 }),
		"port high":     mut(func(c *EmailConfig) { c.Port = 65536 }),
		"no from":       mut(func(c *EmailConfig) { c.From = "" }),
		"bad from":      mut(func(c *EmailConfig) { c.From = "not an address" }),
		"from crlf":     mut(func(c *EmailConfig) { c.From = "a@example.com\r\nBcc: x@evil.test" }),
		"no recipients": mut(func(c *EmailConfig) { c.To = nil }),
		"bad to":        mut(func(c *EmailConfig) { c.To = []string{"ok@example.com", "nope"} }),
		"to lf":         mut(func(c *EmailConfig) { c.To = []string{"ok@example.com\nBcc: x@evil.test"} }),
	} {
		if _, err := NewEmail(c); err == nil {
			t.Errorf("%s: must be refused", name)
		}
	}
	e, err := NewEmail(mut(func(c *EmailConfig) { c.Port = 0 }))
	if err != nil || e.cfg.Port != 587 {
		t.Fatalf("default port: %v %+v", err, e)
	}
	if e.Name() != "email" {
		t.Error(e.Name())
	}
}

func TestEmailSendsAlertMessage(t *testing.T) {
	c := goodConfig()
	c.Username, c.Password = "user", "hunter2"
	e, got := fakeEmail(t, c)
	al := sample()
	al = append(al, Alert{Vuln: &model.Vulnerability{ID: "CVE-2026-2", Title: "meh", Severity: model.SevLow}})
	al[0].Vuln.KEV = &model.KEV{DueDate: time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC)}
	if err := e.Send(context.Background(), al, testNow); err != nil {
		t.Fatal(err)
	}
	if got.addr != "mail.example.com:2525" || got.from != "alerts@example.com" ||
		strings.Join(got.to, ",") != "ops@example.com,bob@example.com" || got.auth == nil {
		t.Errorf("envelope: %+v", got)
	}
	m, err := mail.ReadMessage(strings.NewReader(string(got.msg)))
	if err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]string{
		"Subject":                   "[cvewatch] 2 new vulnerabilities (highest: critical)",
		"Mime-Version":              "1.0",
		"Content-Type":              "text/plain; charset=utf-8",
		"Content-Transfer-Encoding": "8bit",
	} {
		if m.Header.Get(k) != want {
			t.Errorf("%s = %q, want %q", k, m.Header.Get(k), want)
		}
	}
	if from, _ := m.Header.AddressList("From"); len(from) != 1 || from[0].Address != "alerts@example.com" {
		t.Errorf("From: %v", m.Header["From"])
	}
	if to, _ := m.Header.AddressList("To"); len(to) != 2 {
		t.Errorf("To: %v", m.Header["To"])
	}
	if _, err := m.Header.Date(); err != nil {
		t.Errorf("Date: %v", err)
	}
	body, _ := io.ReadAll(m.Body)
	for _, want := range []string{"[CRITICAL] CVE-2026-1", "Title:    RCE <in> PHP", "https://x.test/1", "shop: dev, prod (php@8.2)",
		"no fix known", "KEV, remediation due 2026-10-24", "[LOW] CVE-2026-2"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("missing %q in body:\n%s", want, body)
		}
	}
}

func TestEmailNoAuthWithoutUsername(t *testing.T) {
	e, got := fakeEmail(t, goodConfig())
	if err := e.Send(context.Background(), sample(), testNow); err != nil || got.auth != nil {
		t.Fatalf("err=%v auth=%v", err, got.auth)
	}
}

func TestEmailDigest(t *testing.T) {
	e, got := fakeEmail(t, goodConfig())
	if err := e.SendDigest(context.Background(), sampleDigest(), testNow); err != nil {
		t.Fatal(err)
	}
	m, _ := mail.ReadMessage(strings.NewReader(string(got.msg)))
	if m.Header.Get("Subject") != "[cvewatch] digest: 12 open" {
		t.Errorf("subject %q", m.Header.Get("Subject"))
	}
	body, _ := io.ReadAll(m.Body)
	for _, want := range []string{"12 open, 2 overdue", "[CRITICAL] CVE-2026-1", "Flags:    KEV, overdue", "owner alice", "...and 10 more not shown"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("missing %q in:\n%s", want, body)
		}
	}
}

func TestEmailHeaderInjectionIsNeutralised(t *testing.T) {
	e, got := fakeEmail(t, goodConfig())
	al := sample()
	evil := "x\r\nBcc: evil@evil.test\r\nX-Injected: 1"
	al[0].Vuln.Title = evil
	al[0].Vuln.ID = evil
	al[0].Vuln.Severity = model.Severity("critical\r\nBcc: evil@evil.test")
	al[0].Vuln.Techs = []string{evil}
	al[0].Findings[0].Project = evil
	if err := e.Send(context.Background(), al, testNow); err != nil {
		t.Fatal(err)
	}
	m, err := mail.ReadMessage(strings.NewReader(string(got.msg)))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Header) != 7 {
		t.Errorf("want 7 headers, got %v", m.Header)
	}
	for _, k := range []string{"Bcc", "X-Injected"} {
		if m.Header.Get(k) != "" {
			t.Errorf("injected header %s present", k)
		}
	}
	// Nothing in the body may start a line that looks like a header or an SMTP command either.
	body, _ := io.ReadAll(m.Body)
	for _, l := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(l, "Bcc:") || strings.HasPrefix(l, "X-Injected:") {
			t.Errorf("injected line in body: %q", l)
		}
	}
	// The same defence applies to the subject helper directly.
	if h := header("a\r\nBcc: b\x00\x07c"); strings.ContainsAny(h, "\r\n\x00\x07") {
		t.Errorf("header() left control characters: %q", h)
	}
}

func TestEmailSendErrorAndContext(t *testing.T) {
	e, _ := fakeEmail(t, EmailConfig{Host: "h", From: "a@example.com", To: []string{"b@example.com"}, Username: "u", Password: "SECRETPW"})
	e.send = func(string, smtp.Auth, string, []string, []byte) error { return errors.New("550 rejected") }
	err := e.Send(context.Background(), sample(), testNow)
	if err == nil || !strings.Contains(err.Error(), "550") || strings.Contains(err.Error(), "SECRETPW") {
		t.Errorf("err=%v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := e.Send(ctx, sample(), testNow); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled context: %v", err)
	}
}

// fakeSMTP speaks just enough SMTP (no TLS, no AUTH) to receive one message.
func fakeSMTP(t *testing.T) (addr string, data <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("cannot listen:", err)
	}
	t.Cleanup(func() { ln.Close() })
	out := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		r := bufio.NewReader(conn)
		reply := func(s string) { io.WriteString(conn, s+"\r\n") }
		reply("220 fake ESMTP")
		var cmds []string
		for {
			l, err := r.ReadString('\n')
			if err != nil {
				return
			}
			l = strings.TrimRight(l, "\r\n")
			cmds = append(cmds, l)
			switch u := strings.ToUpper(l); {
			case strings.HasPrefix(u, "EHLO"), strings.HasPrefix(u, "HELO"):
				reply("250 fake")
			case strings.HasPrefix(u, "DATA"):
				reply("354 go")
				var b strings.Builder
				for {
					dl, err := r.ReadString('\n')
					if err != nil {
						return
					}
					if dl == ".\r\n" {
						break
					}
					b.WriteString(strings.TrimPrefix(dl, ".")) // undo dot-stuffing
				}
				out <- strings.Join(cmds, "\n") + "\n--DATA--\n" + b.String()
				reply("250 queued")
			case strings.HasPrefix(u, "QUIT"):
				reply("221 bye")
				return
			default:
				reply("250 ok")
			}
		}
	}()
	return ln.Addr().String(), out
}

func TestEmailRealSMTPPath(t *testing.T) {
	addr, data := fakeSMTP(t)
	host, port, _ := net.SplitHostPort(addr)
	p, _ := strconv.Atoi(port)
	e, err := NewEmail(EmailConfig{Host: host, Port: p, From: "alerts@example.com", To: []string{"ops@example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	al := sample()
	al[0].Vuln.Title = ".leading dot line"
	if err := e.Send(context.Background(), al, testNow); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-data:
		for _, want := range []string{"MAIL FROM:<alerts@example.com>", "RCPT TO:<ops@example.com>",
			"Subject: [cvewatch] 1 new vulnerability (highest: critical)", "[CRITICAL] CVE-2026-1", ".leading dot line"} {
			if !strings.Contains(got, want) {
				t.Errorf("missing %q in:\n%s", want, got)
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server saw no message")
	}
}

func TestEmailRealSMTPPathSendsNoPasswordWithoutAuthSupport(t *testing.T) {
	addr, _ := fakeSMTP(t)
	_, port, _ := net.SplitHostPort(addr)
	p, _ := strconv.Atoi(port)
	// The fake server offers neither STARTTLS nor AUTH, so the password must not be sent.
	e, _ := NewEmail(EmailConfig{Host: "mail.example.invalid", Port: p, From: "a@example.com", To: []string{"b@example.com"}, Username: "u", Password: "SECRETPW"})
	e.send = func(_ string, a smtp.Auth, from string, to []string, msg []byte) error {
		return smtpSend(addr, a, from, to, msg)
	}
	err := e.Send(context.Background(), sample(), testNow)
	if err == nil || strings.Contains(err.Error(), "SECRETPW") {
		t.Fatalf("err=%v", err)
	}
}
