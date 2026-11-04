package app

import (
	"bytes"
	"context"
	"errors"
	"log"
	"strings"
	"testing"

	"kut.corp/suite/server/internal/config"
)

func TestMigrateDSN(t *testing.T) {
	for _, c := range []struct {
		name string
		cfg  config.Config
		want string
	}{
		{"owner url wins", config.Config{DatabaseURL: "app", MigrateDatabaseURL: "owner"}, "owner"},
		{"falls back to the app url", config.Config{DatabaseURL: "app"}, "app"},
		{"neither set", config.Config{}, ""},
	} {
		if got := migrateDSN(&c.cfg); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestMigrateOnStartUsesOwnerDSNAndLogsRoleOnly(t *testing.T) {
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)

	const dsn = "postgres://owner:s3cret-pw@h/kut"
	t.Setenv("KUT_MIGRATE_ON_START", "1")
	var upDSN, roleDSN string
	err := migrateOnStart(context.Background(), &config.Config{DatabaseURL: "postgres://app@h/kut", MigrateDatabaseURL: dsn},
		func(_ context.Context, d string) (int, error) { upDSN = d; return 2, nil },
		func(_ context.Context, d string) (string, error) { roleDSN = d; return "kut_owner", nil })
	if err != nil {
		t.Fatal(err)
	}
	if upDSN != dsn || roleDSN != dsn {
		t.Fatalf("migration did not use the given DSN: up=%q role=%q", upDSN, roleDSN)
	}
	out := buf.String()
	if !strings.Contains(out, "kut_owner") || !strings.Contains(out, "2 applied") {
		t.Errorf("log lacks role or count: %q", out)
	}
	if strings.Contains(out, "s3cret-pw") || strings.Contains(out, "postgres://") {
		t.Errorf("log leaks the URL: %q", out)
	}
}

func TestMigrateOnStartRoleFailureDoesNotFailMigration(t *testing.T) {
	err := migrateOnStart(context.Background(), &config.Config{DatabaseURL: "dsn"},
		func(context.Context, string) (int, error) { return 0, nil },
		func(context.Context, string) (string, error) { return "", errors.New("no role") })
	if err != nil {
		t.Fatalf("role lookup failure must not fail the migration: %v", err)
	}
}

func TestMigrateOnStartFailureIsReturned(t *testing.T) {
	t.Setenv("KUT_MIGRATE_ON_START", "1")
	boom := errors.New("boom")
	err := migrateOnStart(context.Background(), &config.Config{DatabaseURL: "dsn"},
		func(context.Context, string) (int, error) { return 0, boom },
		func(context.Context, string) (string, error) {
			t.Fatal("role must not be read after a failure")
			return "", nil
		})
	if !errors.Is(err, boom) {
		t.Fatalf("got %v, want wrapped boom", err)
	}
}

func TestMigrateOnStartIsOptIn(t *testing.T) {
	t.Setenv("KUT_MIGRATE_ON_START", "")
	called := false
	up := func(context.Context, string) (int, error) { called = true; return 0, nil }
	role := func(context.Context, string) (string, error) { return "", nil }
	if err := migrateOnStart(context.Background(), &config.Config{DatabaseURL: "dsn"}, up, role); err != nil || called {
		t.Fatalf("migration ran without KUT_MIGRATE_ON_START=1 (called=%v, err=%v)", called, err)
	}
}
