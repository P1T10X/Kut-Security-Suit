// Package dbmigrate applies the embedded, versioned PostgreSQL migrations with goose. It is used
// by the kutctl command, by tests, and by the server's opt-in migrate-on-start switch.
package dbmigrate

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"

	"kut.corp/suite/db/postgres"
)

// BaselineVersion is the version of the migration that holds the complete initial schema.
const BaselineVersion int64 = 1

// DefaultLockTimeout bounds how long a migration statement waits for a table lock.
const DefaultLockTimeout = "30s"

// lockTimeoutPattern is the subset of PostgreSQL duration syntax accepted for the lock timeout:
// a whole number with an optional ms, s or min unit (a bare number is milliseconds, 0 disables).
var lockTimeoutPattern = regexp.MustCompile(`^[0-9]+(ms|s|min)?$`)

// connConfig parses dsn and sets lock_timeout as a connection runtime parameter, so DDL in the
// shipped migrations (which cannot be edited) fails instead of queueing behind long-running
// transactions. KUT_MIGRATE_LOCK_TIMEOUT overrides the default; a lock_timeout already present in
// the URL is kept when the variable is unset.
func connConfig(dsn string, getenv func(string) string) (*pgx.ConnConfig, error) {
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("dbmigrate: parse database URL: %w", err)
	}
	if cfg.RuntimeParams == nil {
		cfg.RuntimeParams = map[string]string{}
	}
	if v := strings.TrimSpace(getenv("KUT_MIGRATE_LOCK_TIMEOUT")); v != "" {
		if !lockTimeoutPattern.MatchString(v) {
			return nil, fmt.Errorf("dbmigrate: KUT_MIGRATE_LOCK_TIMEOUT %q is not a duration such as 30s, 500ms or 1min", v)
		}
		cfg.RuntimeParams["lock_timeout"] = v
	} else if _, ok := cfg.RuntimeParams["lock_timeout"]; !ok {
		cfg.RuntimeParams["lock_timeout"] = DefaultLockTimeout
	}
	return cfg, nil
}

// Open opens a database/sql handle for a PostgreSQL DSN. No connection is made until first use.
// Every connection runs with a lock_timeout (see connConfig). goose takes its session lock by
// polling pg_try_advisory_lock, which never waits, so the timeout does not shorten that wait.
func Open(dsn string) (*sql.DB, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, errors.New("dbmigrate: empty database URL")
	}
	cfg, err := connConfig(dsn, os.Getenv)
	if err != nil {
		return nil, err
	}
	return stdlib.OpenDB(*cfg), nil
}

// DSNFromEnv resolves the migration DSN. KUT_MIGRATE_DATABASE_URL (the owner/migration role)
// wins over KUT_DATABASE_URL; each also accepts a _FILE variant that names a file holding the URL.
func DSNFromEnv() (string, error) {
	for _, k := range []string{"KUT_MIGRATE_DATABASE_URL", "KUT_DATABASE_URL"} {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v, nil
		}
		if f := os.Getenv(k + "_FILE"); f != "" {
			b, err := os.ReadFile(f) // #nosec G304 -- operator-supplied secret file path
			if err != nil {
				return "", fmt.Errorf("dbmigrate: %s_FILE: %w", k, err)
			}
			if v := strings.TrimSpace(string(b)); v != "" {
				return v, nil
			}
		}
	}
	return "", errors.New("dbmigrate: set KUT_MIGRATE_DATABASE_URL or KUT_DATABASE_URL")
}

// newProvider builds a goose provider over the embedded migrations. A session-level advisory lock
// serialises concurrent runners.
func newProvider(db *sql.DB) (*goose.Provider, error) {
	fsys, err := fs.Sub(postgres.Migrations, "migrations")
	if err != nil {
		return nil, err
	}
	locker, err := lock.NewPostgresSessionLocker()
	if err != nil {
		return nil, err
	}
	return goose.NewProvider(goose.DialectPostgres, db, fsys,
		goose.WithSessionLocker(locker),
		goose.WithDisableGlobalRegistry(true),
	)
}

// Up applies every pending migration and returns the ones it applied. Calling it again is a no-op.
func Up(ctx context.Context, db *sql.DB) ([]*goose.MigrationResult, error) {
	p, err := newProvider(db)
	if err != nil {
		return nil, err
	}
	return p.Up(ctx)
}

// Status reports every embedded migration and whether it has been applied.
func Status(ctx context.Context, db *sql.DB) ([]*goose.MigrationStatus, error) {
	p, err := newProvider(db)
	if err != nil {
		return nil, err
	}
	return p.Status(ctx)
}

// UpDSN opens dsn, applies pending migrations and closes the handle.
func UpDSN(ctx context.Context, dsn string) (int, error) {
	db, err := Open(dsn)
	if err != nil {
		return 0, err
	}
	defer db.Close()
	res, err := Up(ctx, db)
	return len(res), err
}

// probeCheck is one object the baseline creates. object is the table, type, index or role; name
// is the column, policy, trigger or enum value inside it.
type probeCheck struct {
	kind, object, name string
}

func (c probeCheck) label() string {
	switch c.kind {
	case "table", "partitioned", "index", "type", "role":
		return c.kind + " " + c.object
	case "rls":
		return "row-level security (enabled and forced) on " + c.object
	case "enumvalue":
		return "value " + c.name + " of type " + c.object
	default:
		return c.kind + " " + c.name + " on " + c.object
	}
}

// What the baseline creates. baselineProbe turns these into the checks the probe runs.
var (
	baselineTables = []string{
		"devices", "enrollment_tokens", "agent_certificates", "policies", "policy_rules",
		"device_policies", "ota_releases", "event_logs", "event_ack", "discovered_hosts",
		"device_commands", "artifacts", "evidence_custody", "scim_users", "cases", "verify_checks",
		"tokens", "msp_customers", "admins", "audit_log", "pending_wipes", "incidents", "saved_searches",
	}
	// Tables with row-level security enabled and forced; each gets two policies.
	baselineRLSTables = []string{
		"event_logs", "event_ack", "scim_users", "cases", "verify_checks", "msp_customers", "devices", "incidents",
	}
	// Enum types and their labels (nil: only the type is checked).
	baselineEnums = map[string][]string{
		"device_status":  {"PENDING_ENROLLMENT", "ACTIVE", "OFFLINE", "QUARANTINE_PENDING", "QUARANTINED", "UNINSTALLED"},
		"admin_role":     {"VIEWER", "OPERATOR", "ADMIN"},
		"event_category": nil,
		"severity":       nil,
		"command_type":   nil,
	}
	baselineTriggers = [][2]string{ // table, trigger
		{"evidence_custody", "trg_custody_no_update"}, {"evidence_custody", "trg_custody_no_delete"},
		{"audit_log", "trg_audit_log_no_update"}, {"audit_log", "trg_audit_log_no_delete"},
	}
	// Columns the baseline adds to a table after its first definition.
	baselineColumns = [][2]string{ // table, column
		{"admins", "mfa_pending_secret"}, {"audit_log", "tenant_id"}, {"incidents", "tenant_id"},
		{"policies", "tenant_id"}, {"tokens", "tenant_id"},
	}
	baselineIndexes = []string{"uq_devices_tenant_mac", "idx_policies_tenant"}
)

// baselinePolicies lists the two policies each row-level-security table receives.
func baselinePolicies() [][2]string { // table, policy
	var out [][2]string
	for _, t := range baselineRLSTables {
		out = append(out, [2]string{t, "tenant_isolation_" + t}, [2]string{t, "superuser_bypass_" + t})
	}
	return out
}

// baselineProbe is the full list of objects a database must have before the baseline can be
// recorded as applied without running it.
func baselineProbe() []probeCheck {
	var cs []probeCheck
	for _, t := range baselineTables {
		cs = append(cs, probeCheck{kind: "table", object: t})
	}
	cs = append(cs, probeCheck{kind: "partitioned", object: "event_logs"})
	for _, t := range baselineRLSTables {
		cs = append(cs, probeCheck{kind: "rls", object: t})
	}
	for _, p := range baselinePolicies() {
		cs = append(cs, probeCheck{kind: "policy", object: p[0], name: p[1]})
	}
	for _, p := range baselineTriggers {
		cs = append(cs, probeCheck{kind: "trigger", object: p[0], name: p[1]})
	}
	for typ, vals := range baselineEnums {
		cs = append(cs, probeCheck{kind: "type", object: typ})
		for _, v := range vals {
			cs = append(cs, probeCheck{kind: "enumvalue", object: typ, name: v})
		}
	}
	for _, p := range baselineColumns {
		cs = append(cs, probeCheck{kind: "column", object: p[0], name: p[1]})
	}
	for _, i := range baselineIndexes {
		cs = append(cs, probeCheck{kind: "index", object: i})
	}
	return append(cs, probeCheck{kind: "role", object: "kut_admin"})
}

// missingQuery returns the label of every probe check that does not hold. A check kind it does
// not know, or a NULL result, counts as missing, so the probe never passes by default.
const missingQuery = `SELECT c.label
FROM jsonb_to_recordset($1::jsonb) AS c(kind text, object text, name text, label text)
WHERE NOT COALESCE(CASE c.kind
  WHEN 'table' THEN EXISTS (SELECT 1 FROM pg_class WHERE oid = to_regclass(c.object) AND relkind IN ('r', 'p'))
  WHEN 'partitioned' THEN EXISTS (SELECT 1 FROM pg_class WHERE oid = to_regclass(c.object) AND relkind = 'p')
  WHEN 'rls' THEN EXISTS (SELECT 1 FROM pg_class WHERE oid = to_regclass(c.object) AND relrowsecurity AND relforcerowsecurity)
  WHEN 'index' THEN EXISTS (SELECT 1 FROM pg_class WHERE oid = to_regclass(c.object) AND relkind IN ('i', 'I'))
  WHEN 'column' THEN EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = to_regclass(c.object)
                             AND attname = c.name::name AND attnum > 0 AND NOT attisdropped)
  WHEN 'policy' THEN EXISTS (SELECT 1 FROM pg_policy WHERE polrelid = to_regclass(c.object) AND polname = c.name::name)
  WHEN 'trigger' THEN EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid = to_regclass(c.object)
                              AND tgname = c.name::name AND NOT tgisinternal)
  WHEN 'type' THEN EXISTS (SELECT 1 FROM pg_type WHERE oid = to_regtype(c.object) AND typtype = 'e')
  WHEN 'enumvalue' THEN EXISTS (SELECT 1 FROM pg_enum WHERE enumtypid = to_regtype(c.object) AND enumlabel = c.name::name)
  WHEN 'role' THEN EXISTS (SELECT 1 FROM pg_roles WHERE rolname = c.object::name)
  ELSE false END, false)
ORDER BY c.label`

// missingFromBaseline runs the probe and returns a label for each object the database lacks.
func missingFromBaseline(ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}) ([]string, error) {
	type row struct {
		Kind   string `json:"kind"`
		Object string `json:"object"`
		Name   string `json:"name"`
		Label  string `json:"label"`
	}
	var rows []row
	for _, c := range baselineProbe() {
		rows = append(rows, row{c.kind, c.object, c.name, c.label()})
	}
	payload, err := json.Marshal(rows)
	if err != nil {
		return nil, err
	}
	rs, err := q.QueryContext(ctx, missingQuery, string(payload))
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	var missing []string
	for rs.Next() {
		var l string
		if err := rs.Scan(&l); err != nil {
			return nil, err
		}
		missing = append(missing, l)
	}
	return missing, rs.Err()
}

// Baseline records the baseline migration as applied without running it. It is how an existing
// installation, created from the schema file, adopts migrations without any data change. It
// refuses a database that lacks any object the baseline creates (use Up for those), and reports
// false when the baseline was already recorded.
func Baseline(ctx context.Context, db *sql.DB) (stamped bool, err error) {
	p, err := newProvider(db)
	if err != nil {
		return false, err
	}
	// Status creates the version table when it is missing.
	if _, err := p.Status(ctx); err != nil {
		return false, err
	}
	return stampBaseline(ctx, db)
}

// stampBaseline probes the schema and inserts the baseline version row in one transaction that
// holds the migration lock, so the row cannot be written while a concurrent Up is running.
func stampBaseline(ctx context.Context, db *sql.DB) (bool, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after Commit

	// goose's session lock and this transaction lock share one key space, so this waits for a
	// running Up (up to lock_timeout) and holds off a new one until the stamp commits.
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, lock.DefaultLockID); err != nil {
		return false, err
	}
	missing, err := missingFromBaseline(ctx, tx)
	if err != nil {
		return false, err
	}
	if len(missing) > 0 {
		return false, fmt.Errorf("dbmigrate: database does not have the baseline schema (missing: %s); run `migrate up` instead of `baseline`", summarize(missing, 8))
	}
	res, err := tx.ExecContext(ctx,
		`INSERT INTO goose_db_version (version_id, is_applied)
		 SELECT $1::bigint, true WHERE NOT EXISTS (SELECT 1 FROM goose_db_version WHERE version_id = $1::bigint)`,
		BaselineVersion)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 1, tx.Commit()
}

// summarize joins at most limit items and counts the rest.
func summarize(items []string, limit int) string {
	if len(items) <= limit {
		return strings.Join(items, "; ")
	}
	return fmt.Sprintf("%s; and %d more", strings.Join(items[:limit], "; "), len(items)-limit)
}
