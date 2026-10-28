package epss

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/b070nd/cvewatch/app/src/httpx"
	"github.com/b070nd/cvewatch/app/src/model"
)

// fake records every request and answers with reply(call number, url).
type fake struct {
	urls    []string
	headers []map[string]string
	reply   func(n int, rawURL string) (*httpx.Response, error)
}

func (f *fake) Get(_ context.Context, rawURL string, _ model.Validators, headers map[string]string) (*httpx.Response, error) {
	f.urls = append(f.urls, rawURL)
	f.headers = append(f.headers, headers)
	return f.reply(len(f.urls), rawURL)
}

// echoFake answers every request with one row per id it asked for.
func echoFake(t *testing.T) *fake {
	return &fake{reply: func(_ int, rawURL string) (*httpx.Response, error) {
		var rows []map[string]string
		for _, id := range cvesIn(t, rawURL) {
			rows = append(rows, map[string]string{"cve": id, "epss": "0.5", "percentile": "0.9", "date": "2026-10-27"})
		}
		return okReply(t, rows), nil
	}}
}

// okReply wraps data in FIRST's envelope.
func okReply(t *testing.T, data any) *httpx.Response {
	t.Helper()
	b, err := json.Marshal(map[string]any{"status": "OK", "total": 0, "data": data})
	if err != nil {
		t.Fatal(err)
	}
	return &httpx.Response{Body: b}
}

// cvesIn returns the ids of a request URL and checks where it was sent.
func cvesIn(t *testing.T, rawURL string) []string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	if got := u.Scheme + "://" + u.Host + u.Path; got != endpoint {
		t.Errorf("request went to %s, want %s", got, endpoint)
	}
	return strings.Split(u.Query().Get("cve"), ",")
}

// seq returns CVE-2024-from .. CVE-2024-to, zero-padded so they sort in order.
func seq(from, to int) []string {
	var out []string
	for i := from; i <= to; i++ {
		out = append(out, fmt.Sprintf("CVE-2024-%04d", i))
	}
	return out
}

func TestBatchesOf50(t *testing.T) {
	f := echoFake(t)
	got, err := Scores(context.Background(), f, seq(1, 120))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.urls) != 3 {
		t.Fatalf("requests = %d, want 3", len(f.urls))
	}
	for i, want := range []int{50, 50, 20} {
		if n := len(cvesIn(t, f.urls[i])); n != want {
			t.Errorf("batch %d has %d ids, want %d", i+1, n, want)
		}
		if f.headers[i]["Accept"] != "application/json" {
			t.Errorf("batch %d Accept = %q", i+1, f.headers[i]["Accept"])
		}
	}
	if len(got) != 120 {
		t.Errorf("got %d scores, want 120", len(got))
	}
}

func TestCleansIDs(t *testing.T) {
	f := echoFake(t)
	in := []string{
		"cve-2021-44228", " CVE-2021-44228 ", "CVE-2022-0001", "CVE-2022-0001",
		"junk", "", "CVE-21-1", "CVE-2021-44228; DROP", "https://evil.example/CVE-2023-0001",
		"CVE-2021-44228\n",
	}
	got, err := Scores(context.Background(), f, in)
	if err != nil {
		t.Fatal(err)
	}
	want := endpoint + "?cve=CVE-2021-44228,CVE-2022-0001"
	if len(f.urls) != 1 || f.urls[0] != want {
		t.Fatalf("urls = %v, want [%s]", f.urls, want)
	}
	if len(got) != 2 {
		t.Errorf("got %d scores, want 2", len(got))
	}
}

func TestParsesStrings(t *testing.T) {
	f := &fake{reply: func(int, string) (*httpx.Response, error) {
		return &httpx.Response{Body: []byte(`{"status":"OK","total":6,"data":[
			{"cve":"CVE-2021-44228","epss":"0.975","percentile":"0.999","date":"2026-10-27"},
			{"cve":"cve-2022-0001","epss":"0","percentile":"1","date":"2026-10-27"},
			{"cve":"CVE-2022-0002","epss":"1.5","percentile":"0.5","date":"2026-10-27"},
			{"cve":"CVE-2022-0003","epss":"0.2","percentile":"-0.1","date":"2026-10-27"},
			{"cve":"CVE-2022-0004","epss":"NaN","percentile":"0.5","date":"2026-10-27"},
			{"cve":"CVE-2022-0005","epss":"abc","percentile":"0.5","date":"2026-10-27"}
		]}`)}, nil
	}}
	got, err := Scores(context.Background(), f, []string{"CVE-2021-44228", "CVE-2022-0001", "CVE-2022-0002", "CVE-2022-0003", "CVE-2022-0004", "CVE-2022-0005"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d scores, want 2 (out-of-range, NaN and junk rows dropped): %v", len(got), got)
	}
	s := got["CVE-2021-44228"]
	wantDate := time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC)
	if s.Score != 0.975 || s.Percentile != 0.999 || !s.Date.Equal(wantDate) {
		t.Errorf("CVE-2021-44228 = %+v", s)
	}
	if z, ok := got["CVE-2022-0001"]; !ok || z.Score != 0 || z.Percentile != 1 {
		t.Errorf("boundary values CVE-2022-0001 = %+v, ok=%v", z, ok)
	}
}

func TestNoIDsNoRequest(t *testing.T) {
	for _, in := range [][]string{nil, {}, {"junk", "cve-x"}} {
		f := echoFake(t)
		got, err := Scores(context.Background(), f, in)
		if err != nil || got == nil || len(got) != 0 {
			t.Errorf("Scores(%v) = %v, %v; want empty map, nil", in, got, err)
		}
		if len(f.urls) != 0 {
			t.Errorf("Scores(%v) made %d requests, want 0", in, len(f.urls))
		}
	}
}

func TestPartialFailure(t *testing.T) {
	bad := map[string]func(rawURL string) (*httpx.Response, error){
		"transport": func(u string) (*httpx.Response, error) {
			return nil, errors.New("Get " + u + ": connection reset")
		},
		"http status": func(u string) (*httpx.Response, error) {
			return nil, &httpx.StatusError{Code: 503, URL: u}
		},
		"malformed json": func(string) (*httpx.Response, error) {
			return &httpx.Response{Body: []byte("<html>oops")}, nil
		},
		"bad status": func(string) (*httpx.Response, error) {
			return &httpx.Response{Body: []byte(`{"status":"ERROR","data":[]}`)}, nil
		},
	}
	for name, fail := range bad {
		t.Run(name, func(t *testing.T) {
			echo := echoFake(t)
			f := &fake{reply: func(n int, u string) (*httpx.Response, error) {
				if n == 2 {
					return fail(u)
				}
				return echo.reply(n, u)
			}}
			got, err := Scores(context.Background(), f, seq(1, 120))
			if err == nil {
				t.Fatal("want an error")
			}
			if !strings.Contains(err.Error(), "batch 2") {
				t.Errorf("error %q does not name batch 2", err)
			}
			for _, leak := range []string{"api.first.org", "cve=", "http"} {
				if strings.Contains(err.Error(), leak) {
					t.Errorf("error %q leaks %q", err, leak)
				}
			}
			if len(got) != 50 {
				t.Errorf("got %d scores, want the 50 from batch 1", len(got))
			}
			if len(f.urls) != 2 {
				t.Errorf("requests = %d, want 2 (batch 3 must not run)", len(f.urls))
			}
		})
	}
}

func TestRequestCap(t *testing.T) {
	f := echoFake(t)
	got, err := Scores(context.Background(), f, seq(1, 1100))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.urls) != 20 {
		t.Fatalf("requests = %d, want 20", len(f.urls))
	}
	sent := map[string]bool{}
	for _, u := range f.urls {
		for _, id := range cvesIn(t, u) {
			sent[id] = true
		}
	}
	if len(sent) != 1000 || !sent["CVE-2024-1000"] || sent["CVE-2024-1001"] {
		t.Errorf("sent %d ids; want the first 1000 in sorted order", len(sent))
	}
	if len(got) != 1000 {
		t.Errorf("got %d scores, want 1000", len(got))
	}
}
