// Command kutctl is the operator command line for database administration.
//
//	kutctl migrate up        apply every pending migration
//	kutctl migrate status    list migrations and whether each is applied
//	kutctl migrate baseline  record the baseline as applied on an existing installation
//
// The connection comes from -dsn, else KUT_MIGRATE_DATABASE_URL, else KUT_DATABASE_URL (each also
// accepts a _FILE variant). Run it with the owner/migration role, not the application role.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"time"

	"kut.corp/suite/server/internal/dbmigrate"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "kutctl:", err)
		os.Exit(1)
	}
}

const usage = "usage: kutctl migrate [-dsn URL] up|status|baseline"

func run(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 || args[0] != "migrate" {
		return fmt.Errorf("%s", usage)
	}
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	dsn := fs.String("dsn", "", "database URL (default: KUT_MIGRATE_DATABASE_URL, then KUT_DATABASE_URL)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("%s", usage)
	}
	cmd := fs.Arg(0)
	if cmd != "up" && cmd != "status" && cmd != "baseline" {
		return fmt.Errorf("unknown command %q; %s", cmd, usage)
	}

	url := *dsn
	if url == "" {
		var err error
		if url, err = dbmigrate.DSNFromEnv(); err != nil {
			return err
		}
	}
	db, err := dbmigrate.Open(url)
	if err != nil {
		return err
	}
	defer db.Close()

	switch cmd {
	case "up":
		res, err := dbmigrate.Up(ctx, db)
		if err != nil {
			return err
		}
		if len(res) == 0 {
			fmt.Fprintln(out, "database is up to date")
		}
		for _, r := range res {
			fmt.Fprintf(out, "applied %s (%s)\n", r.Source.Path, r.Duration.Round(time.Millisecond))
		}
	case "status":
		st, err := dbmigrate.Status(ctx, db)
		if err != nil {
			return err
		}
		for _, s := range st {
			applied := "-"
			if !s.AppliedAt.IsZero() {
				applied = s.AppliedAt.UTC().Format(time.RFC3339)
			}
			fmt.Fprintf(out, "%-8s %-40s %s\n", s.State, s.Source.Path, applied)
		}
	case "baseline":
		stamped, err := dbmigrate.Baseline(ctx, db)
		if err != nil {
			return err
		}
		if stamped {
			fmt.Fprintf(out, "baseline (version %d) recorded as applied\n", dbmigrate.BaselineVersion)
		} else {
			fmt.Fprintln(out, "baseline already recorded")
		}
	}
	return nil
}
