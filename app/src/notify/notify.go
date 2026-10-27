// Package notify delivers new findings to people. Slack is the only channel
// today; the interface exists so the pipeline can be tested without a network.
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

	"cvewatch/src/model"
)

// BatchSize is the most alerts sent in one message, to stay under Slack limits.
const BatchSize = 10

// Alert is one new vulnerability with the findings it created.
type Alert struct {
	Vuln     *model.Vulnerability
	Findings []model.Finding
}

type Notifier interface {
	// Send delivers one batch. An error means nothing in the batch counts as alerted.
	Send(ctx context.Context, batch []Alert) error
}

type Slack struct {
	URL    string
	Client *http.Client
	Delay  time.Duration // base retry delay
}

// NewSlack validates the webhook. Its URL is a secret: it is never logged and
// is stripped from transport errors.
func NewSlack(raw string) (*Slack, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, errors.New("slack webhook must be a valid https URL")
	}
	return &Slack{URL: raw, Client: &http.Client{Timeout: 15 * time.Second}, Delay: 2 * time.Second}, nil
}

func (s *Slack) Send(ctx context.Context, batch []Alert) error {
	body, err := json.Marshal(map[string]string{"text": Format(batch)})
	if err != nil {
		return err
	}
	var last error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(s.Delay << attempt):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.URL, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := s.Client.Do(req)
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
		case resp.StatusCode == http.StatusOK:
			return nil
		case resp.StatusCode == http.StatusTooManyRequests:
			if secs, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && secs > 0 && secs <= 60 {
				time.Sleep(time.Duration(secs) * time.Second)
			}
			last = fmt.Errorf("slack: status %d", resp.StatusCode)
		case resp.StatusCode >= 500:
			last = fmt.Errorf("slack: status %d", resp.StatusCode)
		default:
			return fmt.Errorf("slack: status %d (check the webhook URL)", resp.StatusCode) // retrying will not help
		}
	}
	return last
}

// Format renders a batch as Slack mrkdwn.
func Format(batch []Alert) string {
	var b strings.Builder
	fmt.Fprintf(&b, ":rotating_light: *%d new vulnerabilit%s*\n", len(batch), plural(len(batch)))
	for _, a := range batch {
		v := a.Vuln
		fmt.Fprintf(&b, "\n• *%s* %s — %s\n", strings.ToUpper(string(v.Severity)), link(v), esc(v.Title))
		if len(v.Techs) > 0 {
			fmt.Fprintf(&b, "   tech: %s\n", strings.Join(v.Techs, ", "))
		}
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

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

func link(v *model.Vulnerability) string {
	if len(v.Refs) == 0 {
		return v.ID
	}
	return fmt.Sprintf("<%s|%s>", v.Refs[0].URL, v.ID)
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
