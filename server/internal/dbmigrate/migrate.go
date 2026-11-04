// Package dbmigrate applies the embedded, versioned PostgreSQL migrations with goose. It is used
// by the kutctl command, by tests, and by the server's opt-in migrate-on-start switch.
package dbmigrate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"

	// pgx's database/sql driver, registered under the name "pgx".
	_ "github.com/jackc/pgx/v5/stdlib"

	"kut.corp/suite/db/postgres"
)

// BaselineVersion is the version of the migration that holds the complete initial schema.
const BaselineVersion int64 = 1

// Open opens a database/sql handle for a PostgreSQL DSN. No connection is made until first use.
func Open(dsn string) (*sql.DB, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, errors.New("dbmigrate: empty database URL")
	}
	return sql.Open("pgx", dsn)
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

// shapeQuery is true when the database already has the final shape the baseline migration
// produces: the devices table, the per-tenant MAC index, and tenant_id on policies and tokens.
const shapeQuery = `SELECT to_regclass('devices') IS NOT NULL
	AND to_regclass('uq_devices_tenant_mac') IS NOT NULL
	AND EXISTS (SELECT 1 FROM information_schema.columns
	            WHERE table_schema = current_schema() AND table_name = 'policies' AND column_name = 'tenant_id')
	AND EXISTS (SELECT 1 FROM information_schema.columns
	            WHERE table_schema = current_schema() AND table_name = 'tokens' AND column_name = 'tenant_id')`

// Baseline records the baseline migration as applied without running it. It is how an existing
// installation, created from the schema file, adopts migrations without any data change. It
// refuses a database that does not already have the baseline's final shape (use Up for those),
// and reports false when the baseline was already recorded.
func Baseline(ctx context.Context, db *sql.DB) (stamped bool, err error) {
	p, err := newProvider(db)
	if err != nil {
		return false, err
	}
	// Status creates the version table when it is missing.
	if _, err := p.Status(ctx); err != nil {
		return false, err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after Commit

	var shaped bool
	if err := tx.QueryRowContext(ctx, shapeQuery).Scan(&shaped); err != nil {
		return false, err
	}
	if !shaped {
		return false, errors.New("dbmigrate: database does not have the baseline schema; run `migrate up` instead of `baseline`")
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
