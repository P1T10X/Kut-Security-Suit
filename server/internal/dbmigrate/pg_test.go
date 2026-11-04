package dbmigrate

// Integration tests against a real PostgreSQL. They need KUT_DATABASE_URL to point at a role that
// may create databases, and are skipped otherwise. Each test works in its own scratch database.

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"net/url"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/pressly/goose/v3"
)

// scratchDB creates an empty database, returns a handle to it, and drops it when the test ends.
func scratchDB(t *testing.T) (*sql.DB, context.Context) {
	t.Helper()
	dsn := os.Getenv("KUT_DATABASE_URL")
	if dsn == "" {
		t.Skip("KUT_DATABASE_URL not set; PostgreSQL migration test skipped")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)

	admin, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Close() })
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	name := "kut_mig_" + hex.EncodeToString(b)
	if _, err := admin.ExecContext(ctx, `CREATE DATABASE `+name); err != nil {
		t.Fatalf("create scratch database: %v", err)
	}
	t.Cleanup(func() {
		_, _ = admin.ExecContext(context.Background(), `DROP DATABASE IF EXISTS `+name+` WITH (FORCE)`)
	})

	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	db, err := Open(u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db, ctx
}

// loadSchemaFile runs db/schema.sql, the pre-migration way of creating the schema.
func loadSchemaFile(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	raw, err := os.ReadFile("../../../db/schema.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, string(raw)); err != nil {
		t.Fatalf("schema.sql: %v", err)
	}
}

// objects lists the schema objects of a database so two databases can be compared.
func objects(t *testing.T, ctx context.Context, db *sql.DB) []string {
	t.Helper()
	const q = `
SELECT 'rel ' || c.relkind::text || ' ' || c.relname FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public'
UNION ALL SELECT 'col ' || table_name || '.' || column_name || ' ' || data_type
  FROM information_schema.columns WHERE table_schema = 'public'
UNION ALL SELECT 'policy ' || tablename || '.' || policyname FROM pg_policies WHERE schemaname = 'public'
UNION ALL SELECT 'trigger ' || tgname FROM pg_trigger WHERE NOT tgisinternal
UNION ALL SELECT 'constraint ' || conname FROM pg_constraint c
  JOIN pg_namespace n ON n.oid = c.connamespace WHERE n.nspname = 'public'
UNION ALL SELECT 'type ' || typname FROM pg_type t
  JOIN pg_namespace n ON n.oid = t.typnamespace WHERE n.nspname = 'public' AND t.typtype = 'e'
UNION ALL SELECT 'func ' || proname FROM pg_proc p
  JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'public'`
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		// goose's own bookkeeping is not part of the application schema.
		if strings.Contains(s, "goose_db_version") {
			continue
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	sort.Strings(out)
	return out
}

func TestPGMigrateUpIsIdempotent(t *testing.T) {
	db, ctx := scratchDB(t)
	first, err := Up(ctx, db)
	if err != nil {
		t.Fatalf("first up: %v", err)
	}
	if len(first) < 2 {
		t.Fatalf("first up applied %d migrations, want at least 2", len(first))
	}
	again, err := Up(ctx, db)
	if err != nil || len(again) != 0 {
		t.Fatalf("second up must be a no-op: applied=%d err=%v", len(again), err)
	}
	st, err := Status(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if len(st) != len(first) {
		t.Fatalf("status lists %d migrations, want %d", len(st), len(first))
	}
	for _, s := range st {
		if s.State != goose.StateApplied {
			t.Errorf("%s is %s, want applied", s.Source.Path, s.State)
		}
	}
}

// An installation created from schema.sql adopts migrations by stamping the baseline, and
// reaches the same schema as a fresh database.
func TestPGBaselineAdoptsExistingInstall(t *testing.T) {
	fresh, ctx := scratchDB(t)
	if _, err := Up(ctx, fresh); err != nil {
		t.Fatal(err)
	}

	existing, _ := scratchDB(t)
	if stamped, err := Baseline(ctx, existing); err == nil {
		t.Fatalf("baseline on an empty database must be refused (stamped=%v)", stamped)
	}
	loadSchemaFile(t, ctx, existing)
	if stamped, err := Baseline(ctx, existing); err != nil || !stamped {
		t.Fatalf("baseline: stamped=%v err=%v", stamped, err)
	}
	if stamped, err := Baseline(ctx, existing); err != nil || stamped {
		t.Fatalf("second baseline must be a no-op: stamped=%v err=%v", stamped, err)
	}
	applied, err := Up(ctx, existing)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range applied {
		if r.Source.Version == BaselineVersion {
			t.Fatal("up re-ran the baseline after it was stamped")
		}
	}
	if a, b := objects(t, ctx, fresh), objects(t, ctx, existing); !reflect.DeepEqual(a, b) {
		t.Fatalf("schemas differ between fresh up and schema.sql + baseline + up:\nfresh:    %d objects\nexisting: %d objects", len(a), len(b))
	}
}

// The baseline is safe to run over an installation that was never stamped.
func TestPGUpOverUnstampedInstall(t *testing.T) {
	db, ctx := scratchDB(t)
	loadSchemaFile(t, ctx, db)
	loadSchemaFile(t, ctx, db) // schema.sql itself can be re-run
	if _, err := Up(ctx, db); err != nil {
		t.Fatalf("up over an existing schema: %v", err)
	}
	if res, err := Up(ctx, db); err != nil || len(res) != 0 {
		t.Fatalf("second up: applied=%d err=%v", len(res), err)
	}
}

func TestPGApplicationRole(t *testing.T) {
	db, ctx := scratchDB(t)
	if _, err := Up(ctx, db); err != nil {
		t.Fatal(err)
	}
	var super, bypass, login bool
	if err := db.QueryRowContext(ctx,
		`SELECT rolsuper, rolbypassrls, rolcanlogin FROM pg_roles WHERE rolname = 'kut_app'`).
		Scan(&super, &bypass, &login); err != nil {
		t.Fatalf("kut_app missing: %v", err)
	}
	if super || bypass || login {
		t.Fatalf("kut_app must be NOSUPERUSER NOBYPASSRLS NOLOGIN: super=%v bypass=%v login=%v", super, bypass, login)
	}

	has := func(table, priv string) bool {
		var ok bool
		if err := db.QueryRowContext(ctx, `SELECT has_table_privilege('kut_app', $1::text, $2::text)`, table, priv).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		return ok
	}
	for _, c := range []struct {
		table, priv string
		want        bool
	}{
		{"devices", "SELECT", true}, {"devices", "INSERT", true}, {"devices", "UPDATE", true},
		{"devices", "DELETE", true}, {"devices", "TRUNCATE", false}, {"devices", "REFERENCES", false},
		{"event_logs", "INSERT", true},
		{"audit_log", "SELECT", true}, {"audit_log", "INSERT", true},
		{"audit_log", "UPDATE", false}, {"audit_log", "DELETE", false},
		{"evidence_custody", "INSERT", true}, {"evidence_custody", "DELETE", false},
	} {
		if got := has(c.table, c.priv); got != c.want {
			t.Errorf("kut_app %s on %s = %v, want %v", c.priv, c.table, got, c.want)
		}
	}

	// Under forced row-level security and without a tenant setting the role sees no rows.
	var isSuper bool
	if err := db.QueryRowContext(ctx, `SELECT rolsuper FROM pg_roles WHERE rolname = current_user`).Scan(&isSuper); err != nil {
		t.Fatal(err)
	}
	if !isSuper {
		t.Skip("current role cannot SET ROLE kut_app; row-level security check skipped")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback() //nolint:errcheck // always rolled back
	if _, err := tx.ExecContext(ctx, `SET LOCAL ROLE kut_app`); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM devices`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("kut_app without a tenant setting: rows=%d err=%v", n, err)
	}
	if _, err := tx.ExecContext(ctx, `TRUNCATE devices`); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("TRUNCATE must be denied to kut_app, got %v", err)
	}
}
