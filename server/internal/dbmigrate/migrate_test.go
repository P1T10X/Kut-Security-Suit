package dbmigrate

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/pressly/goose/v3/lock"

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

func probeSet(kind string) map[string]bool {
	out := map[string]bool{}
	for _, c := range baselineProbe() {
		if c.kind != kind {
			continue
		}
		k := c.object
		if c.name != "" {
			k += "." + c.name
		}
		out[k] = true
	}
	return out
}

func statementNames(t *testing.T, sql, pattern string, groups ...int) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, m := range regexp.MustCompile(pattern).FindAllStringSubmatch(sql, -1) {
		parts := make([]string, len(groups))
		for i, g := range groups {
			parts[i] = m[g]
		}
		out[strings.Join(parts, ".")] = true
	}
	return out
}

func sameSet(t *testing.T, what string, fromBaseline, inProbe map[string]bool) {
	t.Helper()
	for k := range fromBaseline {
		if !inProbe[k] {
			t.Errorf("baseline creates %s %q but the probe does not check it", what, k)
		}
	}
	for k := range inProbe {
		if !fromBaseline[k] {
			t.Errorf("probe checks %s %q but the baseline does not create it", what, k)
		}
	}
}

// Every table, policy, trigger, enum type, added column, index and role the baseline creates is
// in the probe list, so extending the baseline cannot leave the adoption check behind.
func TestBaselineProbeListCoversBaselineStatements(t *testing.T) {
	sql := upSection(t, "00001_baseline.sql")

	// Partition children ("... PARTITION OF ...") are not followed by a column list.
	sameSet(t, "table", statementNames(t, sql, `(?m)^CREATE TABLE IF NOT EXISTS (\w+)\s*\(`, 1), probeSet("table"))
	sameSet(t, "row-level security table",
		statementNames(t, sql, `(?m)^ALTER TABLE (\w+) FORCE ROW LEVEL SECURITY`, 1), probeSet("rls"))
	sameSet(t, "policy", statementNames(t, sql, `(?m)^CREATE POLICY (\w+) ON (\w+)`, 2, 1), probeSet("policy"))
	sameSet(t, "trigger",
		statementNames(t, sql, `(?s)(?m)^CREATE (?:OR REPLACE )?TRIGGER (\w+)\s.*?\sON (\w+)`, 2, 1), probeSet("trigger"))
	sameSet(t, "enum type", statementNames(t, sql, `CREATE TYPE (\w+) AS ENUM`, 1), probeSet("type"))
	sameSet(t, "added column",
		statementNames(t, sql, `(?m)^ALTER TABLE (\w+) ADD COLUMN IF NOT EXISTS (\w+)`, 1, 2), probeSet("column"))
	sameSet(t, "role", statementNames(t, sql, `CREATE ROLE (\w+)`, 1), probeSet("role"))

	// Enum labels: every quoted label of the checked enums appears in the probe.
	for typ, vals := range baselineEnums {
		if vals == nil {
			continue
		}
		m := regexp.MustCompile(`CREATE TYPE ` + typ + ` AS ENUM\s*\(([^)]*)\)`).FindStringSubmatch(sql)
		if m == nil {
			t.Fatalf("enum %s not found in the baseline", typ)
		}
		got := map[string]bool{}
		for _, l := range regexp.MustCompile(`'([^']+)'`).FindAllStringSubmatch(m[1], -1) {
			got[typ+"."+l[1]] = true
		}
		want := map[string]bool{}
		for _, v := range vals {
			want[typ+"."+v] = true
		}
		sameSet(t, "enum label", got, want)
	}
	// Every index created by the baseline need not be probed, but every probed one must exist.
	for _, i := range baselineIndexes {
		if !regexp.MustCompile(`(?m)^CREATE (?:UNIQUE )?INDEX IF NOT EXISTS ` + i + `\b`).MatchString(sql) {
			t.Errorf("probe checks index %q but the baseline does not create it", i)
		}
	}
}

func TestConnConfigLockTimeout(t *testing.T) {
	env := func(v string) func(string) string {
		return func(k string) string {
			if k == "KUT_MIGRATE_LOCK_TIMEOUT" {
				return v
			}
			return ""
		}
	}
	for _, c := range []struct {
		name, dsn, env, want string
		bad                  bool
	}{
		{name: "default", dsn: "postgres://u@h/d", want: "30s"},
		{name: "env override", dsn: "postgres://u@h/d", env: "5s", want: "5s"},
		{name: "env milliseconds", dsn: "postgres://u@h/d", env: "1500", want: "1500"},
		{name: "env beats url", dsn: "postgres://u@h/d?lock_timeout=9s", env: "2min", want: "2min"},
		{name: "url kept without env", dsn: "postgres://u@h/d?lock_timeout=9s", want: "9s"},
		{name: "rejects garbage", dsn: "postgres://u@h/d", env: "soon; DROP", bad: true},
		{name: "rejects negative", dsn: "postgres://u@h/d", env: "-1", bad: true},
	} {
		cfg, err := connConfig(c.dsn, env(c.env))
		if c.bad {
			if err == nil {
				t.Errorf("%s: want an error", c.name)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if got := cfg.RuntimeParams["lock_timeout"]; got != c.want {
			t.Errorf("%s: lock_timeout = %q, want %q", c.name, got, c.want)
		}
	}
}

// The transaction lock Baseline takes must be the lock goose's session locker takes, or the
// two would not exclude each other.
func TestMigrationLockIDMatchesSessionLocker(t *testing.T) {
	if lock.DefaultLockID != 4097083626 {
		t.Fatalf("goose default lock id is %d; the pinned value changed", lock.DefaultLockID)
	}
}
