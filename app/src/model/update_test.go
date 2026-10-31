package model

import (
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestProjectUpdateDefaultsAndPeriods(t *testing.T) {
	var p Project
	if !p.AutoUpdate() || p.Every(4*time.Hour) != 4*time.Hour {
		t.Fatalf("no block: auto on, the global interval: %+v", p.Update)
	}
	off := false
	p.Update = ProjectUpdate{Auto: &off, Every: 90 * time.Minute}
	if p.AutoUpdate() || p.Every(4*time.Hour) != 90*time.Minute {
		t.Fatalf("own settings win: %+v", p.Update)
	}
}

func TestProjectUpdateIsDecodedStrictly(t *testing.T) {
	var p Project
	if err := yaml.Unmarshal([]byte("name: shop\nupdate: {every: 2h, auto: false}\nwhen@prod: {image: x}\n"), &p); err != nil {
		t.Fatal(err)
	}
	if p.Update.Every != 2*time.Hour || p.AutoUpdate() || p.Environments[EnvProd].Image != "x" {
		t.Fatalf("%+v", p)
	}
	if err := yaml.Unmarshal([]byte("name: shop\nupdates: {every: 2h}\n"), &p); err == nil {
		t.Fatal("a misspelt key is not silently ignored")
	}
}

func TestSpan(t *testing.T) {
	for d, want := range map[time.Duration]string{5 * time.Minute: "5m", time.Hour: "1h", 90 * time.Minute: "1h30m", 48 * time.Hour: "48h", 30 * time.Second: "30s"} {
		if got := Span(d); got != want {
			t.Errorf("Span(%v) = %q, want %q", d, got, want)
		}
	}
}
