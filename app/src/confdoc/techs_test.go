package confdoc

import (
	"strings"
	"testing"

	"github.com/b070nd/cvewatch/app/src/model"
)

const userTechs = `# mine
techs:
  - name: acme
    aliases: [acme gateway]
    cpe: ["acme:gateway"]   # checked
    detect:
      files: [acme.conf]
      packages:
        - {ecosystem: npm, name: acme-sdk}
    feeds:
      - {id: acme-feed, type: rss, url: "https://example.com/feed"}
`

func TestTechEditsChangeFieldsAndKeepTheRest(t *testing.T) {
	root := t.TempDir()
	put(t, root, "config/techs.yaml", userTechs)
	s := mustRead(t, root)
	mine, err := s.UserTechs()
	if err != nil || len(mine) != 1 || mine[0].Detect.Packages[0].Name != "acme-sdk" {
		t.Fatalf("%+v %v", mine, err)
	}
	if shipped, err := s.ShippedTechs(); err != nil || len(shipped) < 50 {
		t.Fatalf("shipped: %d %v", len(shipped), err)
	}

	next := mine[0]
	next.Aliases = []string{"acme gateway", "acmegw"}
	next.CPE = nil
	next.Detect.Files = nil
	next.Detect.Packages = append(next.Detect.Packages, model.PackageHint{Ecosystem: "composer", Name: "acme/sdk"})
	next.Vendor = "ACME"
	c := mustWith(t, s, ChangeTechEdits(mine[0], next)...)
	got := text(t, c, IDTechs)
	for _, want := range []string{"# mine", "acmegw", "vendor: ACME", "acme/sdk", "feeds:", "acme-feed"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	for _, gone := range []string{"cpe", "acme.conf"} {
		if strings.Contains(got, gone) {
			t.Errorf("%q should be gone:\n%s", gone, got)
		}
	}
	if edits := ChangeTechEdits(mine[0], mine[0]); len(edits) != 0 {
		t.Fatalf("nothing changed: %+v", edits)
	}
}

func TestAddAndRemoveTechEdits(t *testing.T) {
	root := t.TempDir()
	put(t, root, "config/techs.yaml", "techs: []\n")
	s := mustRead(t, root)
	c := mustWith(t, s, AddTechEdit(model.Tech{Name: "algolia", Aliases: []string{"algolia"}, Category: "search",
		Detect: model.Detect{Files: []string{"algolia.json"}}}))
	if mine, err := c.UserTechs(); err != nil || len(mine) != 1 || mine[0].Name != "algolia" || mine[0].Detect.Files[0] != "algolia.json" {
		t.Fatalf("%+v %v", mine, err)
	}
	if _, err := c.With(AddTechEdit(model.Tech{Name: "algolia"})); err == nil {
		t.Fatal("a second entry of the same name must be refused")
	}
	d := mustWith(t, c, RemoveTechEdit("algolia"))
	if mine, _ := d.UserTechs(); len(mine) != 0 || !strings.Contains(text(t, d, IDTechs), "techs: []") {
		t.Fatalf("%s", text(t, d, IDTechs))
	}
}
