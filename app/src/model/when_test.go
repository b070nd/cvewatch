package model

import (
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func decodeStrict(t *testing.T, src string) (Project, error) {
	t.Helper()
	dec := yaml.NewDecoder(strings.NewReader(src))
	dec.KnownFields(true)
	var p Project
	err := dec.Decode(&p)
	return p, err
}

const whenSample = `name: shop
envs: [local, prod]
techs:
  - {name: php, version: "8.2"}
  - {name: xdebug, envs: [local]}
  - {name: mysql, version: "8.0"}
when@prod:
  techs: {php: "8.3", varnish: "7.4"}
  exclude: [mysql]
  image: shop:1.4.2
`

func TestWhenBlocksAreReadIntoEnvironments(t *testing.T) {
	p, err := decodeStrict(t, whenSample)
	if err != nil {
		t.Fatal(err)
	}
	ec := p.Environments[EnvProd]
	if ec.Techs["php"] != "8.3" || ec.Techs["varnish"] != "7.4" || !reflect.DeepEqual(ec.Exclude, []string{"mysql"}) || ec.Image != "shop:1.4.2" || ec.Old {
		t.Fatalf("%+v", ec)
	}
	if !reflect.DeepEqual(p.Techs[1].Envs, []Env{EnvLocal}) {
		t.Fatalf("%+v", p.Techs)
	}
}

func TestOldEnvironmentsKeyStillReads(t *testing.T) {
	p, err := decodeStrict(t, "name: shop\nenvironments:\n  prod:\n    techs: {php: \"8.3\"}\n    image: x\n")
	if err != nil {
		t.Fatal(err)
	}
	ec := p.Environments[EnvProd]
	if ec.Techs["php"] != "8.3" || ec.Image != "x" || !ec.Old {
		t.Fatalf("%+v", ec)
	}
}

func TestProjectStaysStrict(t *testing.T) {
	for name, tc := range map[string]struct{ src, want string }{
		"unknown top key":    {"name: a\ntechz: []\n", "line 2: field techz not found"},
		"unknown when key":   {"name: a\nwhen@prod:\n  tech: {}\n", "line 3: field tech not found"},
		"unknown tech key":   {"name: a\ntechs:\n  - {name: php, verison: \"8\"}\n", "field verison not found"},
		"both spellings":     {"name: a\nenvironments:\n  prod: {image: x}\nwhen@prod:\n  image: y\n", "both environments: and when@prod"},
		"missing env name":   {"name: a\nwhen@:\n  image: y\n", "needs an environment name"},
		"wrong type in when": {"name: a\nwhen@prod:\n  exclude: nope\n", "cannot unmarshal"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := decodeStrict(t, tc.src)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestTechsIn(t *testing.T) {
	p, err := decodeStrict(t, whenSample)
	if err != nil {
		t.Fatal(err)
	}
	show := func(env Env) string {
		var out []string
		for _, tt := range p.TechsIn(env) {
			out = append(out, tt.Name+"="+tt.Version)
		}
		return strings.Join(out, " ")
	}
	for env, want := range map[Env]string{
		EnvLocal: "php=8.2 xdebug= mysql=8.0", // scoped tech present where it names, no differences
		EnvProd:  "php=8.3 varnish=7.4",       // override, add, scoped tech gone, excluded gone
		"qa":     "php=8.2 mysql=8.0",         // an environment without a block gets the generic list
	} {
		if got := show(env); got != want {
			t.Errorf("%s: %q, want %q", env, got, want)
		}
	}
}

func TestTechsInPrecedence(t *testing.T) {
	p := Project{
		Techs: []ProjectTech{{Name: "PHP", Version: "8.2"}, {Name: "redis", Envs: []Env{EnvLocal}}},
		Environments: map[Env]EnvConfig{
			EnvProd:  {Techs: map[string]string{"php": "8.3", "redis": "7", "memcached": "1"}, Exclude: []string{"MEMCACHED"}},
			EnvLocal: {Exclude: []string{"php"}},
		},
	}
	got := func(env Env) []ProjectTech { return p.TechsIn(env) }
	if g := got(EnvProd); !reflect.DeepEqual(g, []ProjectTech{{Name: "PHP", Version: "8.3"}, {Name: "redis", Version: "7"}}) {
		t.Errorf("prod: %+v (a difference adds a tech scoped away elsewhere; exclude wins over the same block's techs, ignoring case)", g)
	}
	if g := got(EnvLocal); !reflect.DeepEqual(g, []ProjectTech{{Name: "redis"}}) {
		t.Errorf("local: %+v", g)
	}
}
