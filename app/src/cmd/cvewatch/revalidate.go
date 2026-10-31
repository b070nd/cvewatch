package main

import (
	"context"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/b070nd/cvewatch/app/src/ops"
	"github.com/b070nd/cvewatch/app/src/pipeline"
)

// maxListed bounds the issues printed one per line.
const maxListed = 40

func revalidateCmd(ctx context.Context, s *ops.Session, args []string) error {
	fs := flag.NewFlagSet("revalidate", flag.ContinueOnError)
	apply := fs.Bool("apply", false, "make the changes; without it only report them")
	fetch := fs.Bool("fetch", false, "after applying, fetch the older items the change needs (implies -apply)")
	asJSON := fs.Bool("json", false, "print JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	*apply = *apply || *fetch
	rv, err := s.Revalidate(*apply)
	if err != nil {
		return err
	}
	var fetched *pipeline.Result
	if *fetch {
		res, ferr := s.Backfill(ctx, func(p ops.RefreshProgress) {
			if !*asJSON && p.Chunk > 0 {
				fmt.Printf("fetching %s: part %d%s\n", p.Source, p.Chunk, ofTotal(p.Chunks))
			}
		})
		if ferr != nil {
			return ferr
		}
		fetched = &res
	}
	if *asJSON {
		return printJSON(struct {
			pipeline.Revalidation
			Fetched *pipeline.Result `json:"fetched,omitempty"`
		}{rv, fetched})
	}
	for i, c := range rv.Changes {
		if i == maxListed {
			fmt.Printf("... and %d more\n", len(rv.Changes)-maxListed)
			break
		}
		fmt.Printf("%-9s %-18s %-30s %s\n", c.Action, c.ID, strings.Join(c.Projects, ","), c.Title)
	}
	fmt.Printf("%d new finding(s), %d closed by a since date, %d reopened, %d re-checked after an inventory change, %d unchanged.\n",
		rv.NewFindings, rv.Closed, rv.Reopened, rv.Reconciled, rv.Unchanged)
	if len(rv.Projects) > 0 {
		fmt.Println("Projects changed:", strings.Join(rv.Projects, ", "))
	}
	if len(rv.BackfillSources) > 0 && !rv.Backfill.IsZero() {
		verb := "will reach back"
		if !rv.Applied {
			verb = "would be asked to reach back"
		}
		fmt.Printf("%s %s to %s on their next fetch.\n", strings.Join(rv.BackfillSources, ", "), verb, rv.Backfill.UTC().Format(time.DateOnly))
	}
	switch {
	case fetched != nil:
		fmt.Printf("Fetched older items: %d item(s), %d new finding(s).\n", fetched.Items, fetched.Findings)
		for _, n := range fetched.Notes {
			fmt.Println("note:", n)
		}
	case !rv.Applied && (rv.NewFindings+rv.Closed+rv.Reopened+rv.Reconciled > 0 || len(rv.Projects) > 0):
		fmt.Println("Nothing was changed. Run again with -apply to make these changes, or -fetch to also fetch older items.")
	case rv.Applied && len(rv.BackfillSources) > 0:
		fmt.Println("Run cvewatch update (or the daemon) to fetch the older items, or revalidate -fetch.")
	}
	return nil
}

func ofTotal(total int) string {
	if total <= 0 {
		return ""
	}
	return fmt.Sprintf(" of %d", total)
}
