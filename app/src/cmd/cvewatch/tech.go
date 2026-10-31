package main

import (
	"errors"
	"flag"
	"fmt"
	"strings"

	"github.com/b070nd/cvewatch/app/src/catalog"
	"github.com/b070nd/cvewatch/app/src/model"
	"github.com/b070nd/cvewatch/app/src/ops"
)

const techUsage = `usage: cvewatch tech <command>
  add NAME [-alias A]... [-category C] [-title T] [-vendor V] [-cpe VENDOR:PRODUCT]... [-exclude X]... [-yes]
                                    add a technology the catalog does not have; advisories that name an alias
                                    (default: the name) as a whole word then match it
  edit NAME [same flags]            change one of your own; a flag that is given replaces that list or value ("" clears)
  remove NAME [-yes]                delete one of your own
  list [-json]                      your own technologies (cvewatch catalog lists them all)
Without -yes only the change is shown. They are written to config/techs.yaml.`

// techCmd edits the user's own technologies. Like settings it opens the
// documents without loading the configuration.
func techCmd(root string, args []string) error {
	if len(args) == 0 {
		return errors.New(techUsage)
	}
	sub, rest := args[0], args[1:]
	ss, err := ops.OpenSettings(root)
	if err != nil {
		return err
	}
	switch sub {
	case "list":
		return techList(ss, rest)
	case "add", "edit", "remove":
		return techEdit(ss, sub, rest)
	}
	return fmt.Errorf("unknown tech command %q\n%s", sub, techUsage)
}

func techList(ss *ops.SettingsSession, args []string) error {
	fs := flag.NewFlagSet("tech list", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	techs, err := ss.UserTechs()
	if err != nil {
		return err
	}
	if *asJSON {
		out := []map[string]any{}
		for _, t := range techs {
			out = append(out, map[string]any{"name": t.Name, "title": t.Title, "category": t.Category, "vendor": t.Vendor,
				"aliases": t.Aliases, "cpe": t.CPE, "excludes": t.Excludes})
		}
		return printJSON(out)
	}
	for _, t := range techs {
		words := t.Aliases
		if len(words) == 0 {
			words = []string{t.Name}
		}
		fmt.Printf("%-18s %-14s keywords: %s\n", t.Name, t.Category, strings.Join(words, ", "))
	}
	if len(techs) == 0 {
		fmt.Println("none yet: cvewatch tech add NAME adds one")
	}
	return nil
}

func techEdit(ss *ops.SettingsSession, verb string, args []string) error {
	fs := flag.NewFlagSet("tech "+verb, flag.ContinueOnError)
	var alias, cpe, exclude listFlag
	var category, title, vendor optFlag
	fs.Var(&alias, "alias", "a keyword advisories name it by, repeatable (default: the name)")
	fs.Var(&cpe, "cpe", "an NVD CPE name vendor:product in lowercase, repeatable")
	fs.Var(&exclude, "exclude", "an item containing this word is not about it, repeatable")
	fs.Var(&category, "category", "one of: "+strings.Join(catalog.Categories, ", "))
	fs.Var(&title, "title", "display name")
	fs.Var(&vendor, "vendor", "vendor name")
	yes := fs.Bool("yes", false, "write the change; without it only show the diff")
	pos, err := intermixed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("usage: cvewatch tech %s NAME [flags] [-yes]", verb)
	}
	name := pos[0]
	var p ops.SettingsPreview
	switch verb {
	case "remove":
		p, err = ss.RemoveTech(ops.TechChange{Tech: model.Tech{Name: name}, Save: *yes})
	case "add":
		t := model.Tech{Name: name, Aliases: alias, CPE: cpe, Excludes: exclude, Category: category.val, Title: title.val, Vendor: vendor.val}
		p, err = ss.AddTech(ops.TechChange{Tech: t, Save: *yes})
	default:
		mine, uerr := ss.UserTechs()
		if uerr != nil {
			return uerr
		}
		t, ok := findUserTech(mine, name)
		if !ok {
			return fmt.Errorf("%s is not one of your technologies; built-in ones are changed in settings", name)
		}
		set := map[string]bool{}
		fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
		if len(set) == 0 || len(set) == 1 && set["yes"] {
			return errors.New("nothing to change: give -alias, -cpe, -exclude, -category, -title or -vendor")
		}
		if set["alias"] {
			t.Aliases = alias
		}
		if set["cpe"] {
			t.CPE = cpe
		}
		if set["exclude"] {
			t.Excludes = exclude
		}
		if category.set {
			t.Category = category.val
		}
		if title.set {
			t.Title = title.val
		}
		if vendor.set {
			t.Vendor = vendor.val
		}
		p, err = ss.EditTech(ops.TechChange{Tech: t, Save: *yes})
	}
	return showSettings(p, err, *yes)
}

func findUserTech(list []model.Tech, name string) (model.Tech, bool) {
	for _, t := range list {
		if strings.EqualFold(t.Name, name) {
			return t, true
		}
	}
	return model.Tech{}, false
}
