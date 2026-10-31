package catalog

import (
	"slices"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/b070nd/cvewatch/app/src/defaults"
	"github.com/b070nd/cvewatch/app/src/model"
)

func shippedCatalog(t *testing.T) *Catalog {
	t.Helper()
	var f struct {
		Techs []model.Tech `yaml:"techs"`
	}
	if err := yaml.Unmarshal(defaults.Techs(), &f); err != nil {
		t.Fatal(err)
	}
	return New(f.Techs)
}

func names(ts []model.Tech) []string {
	var out []string
	for _, t := range ts {
		out = append(out, t.Name)
	}
	return out
}

func TestSuggestRanksAndDropsFillers(t *testing.T) {
	c := shippedCatalog(t)
	for _, tc := range []struct {
		term  string
		first string // "" means nothing close enough
	}{
		{"rabbitMW", "rabbitmq"},
		{"RabbitMQ", "rabbitmq"},
		{"myssql", "mysql"},
		{"mysql", "mysql"},
		{"postgres", "postgresql"},
		{"golang", "go"},
		{"algolia", ""},
		{"akeneo", ""},
		{"channable", ""},
		{"gcp", ""},
		{"", ""},
	} {
		got := names(c.Suggest(tc.term, 5))
		if tc.first == "" {
			if len(got) != 0 {
				t.Errorf("Suggest(%q) = %v, want nothing", tc.term, got)
			}
			continue
		}
		if len(got) == 0 || got[0] != tc.first {
			t.Errorf("Suggest(%q) = %v, want %s first", tc.term, got, tc.first)
		}
	}
	if got := names(c.Suggest("exchang", 5)); !slices.Contains(got, "exchange") {
		t.Errorf("prefix: %v", got)
	}
}

func TestSuggestLimitAndOrder(t *testing.T) {
	c := New([]model.Tech{
		{Name: "redis-sentinel"},
		{Name: "redis"},
		{Name: "reddit-bot"},
		{Name: "keydb", Aliases: []string{"redis-compatible"}},
	})
	got := names(c.Suggest("redis", 2))
	if !slices.Equal(got, []string{"redis", "redis-sentinel"}) {
		t.Fatalf("exact then prefix, limited: %v", got)
	}
	if got := names(c.Suggest("redys", 5)); len(got) == 0 || got[0] != "redis" {
		t.Fatalf("near miss: %v", got)
	}
	if got := c.Suggest("node.js", 3); len(got) != 0 {
		t.Fatalf("unrelated: %v", got)
	}
	if got := New([]model.Tech{{Name: "nodejs", Aliases: []string{"node"}}}).Suggest("Node.JS", 3); len(got) != 1 {
		t.Fatalf("punctuation is ignored: %v", got)
	}
}
