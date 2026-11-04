package dbmigrate

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"kut.corp/suite/db/postgres"
)

// The embedded migrations parse, are numbered from the baseline, and are contiguous.
func TestEmbeddedMigrationsParse(t *testing.T) {
	db, err := Open("postgres://unused@127.0.0.1:1/unused")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	p, err := newProvider(db)
	if err != nil {
		t.Fatalf("provider: %v", err)
	}
	src := p.ListSources()
	if len(src) < 2 {
		t.Fatalf("expected at least the baseline and the role migration, got %d", len(src))
	}
	if src[0].Version != BaselineVersion {
		t.Fatalf("first migration is version %d, want %d", src[0].Version, BaselineVersion)
	}
	for i, s := range src {
		if s.Version != int64(i+1) {
			t.Fatalf("migration versions must be contiguous: position %d has version %d", i, s.Version)
		}
	}
}

// goose annotation lines carry no SQL. Normalise line endings and drop them so the baseline
// migration can be compared with the schema file.
var gooseLine = regexp.MustCompile(`(?m)^-- \+goose .*\n`)

func upSection(t *testing.T, name string) string {
	t.Helper()
	b, err := postgres.Migrations.ReadFile("migrations/" + name)
	if err != nil {
		t.Fatal(err)
	}
	s := strings.ReplaceAll(string(b), "\r\n", "\n")
	i := strings.Index(s, "\n-- +goose Down\n")
	if i < 0 {
		t.Fatalf("%s has no Down section", name)
	}
	return strings.TrimSpace(gooseLine.ReplaceAllString(s[:i], ""))
}

// db/schema.sql is the baseline migration without its goose annotations; the two must not drift.
func TestSchemaFileMatchesBaselineMigration(t *testing.T) {
	raw, err := os.ReadFile("../../../db/schema.sql")
	if err != nil {
		t.Fatal(err)
	}
	schema := strings.TrimSpace(strings.ReplaceAll(string(raw), "\r\n", "\n"))
	if got := upSection(t, "00001_baseline.sql"); got != schema {
		t.Fatal("db/schema.sql and db/postgres/migrations/00001_baseline.sql differ")
	}
}
