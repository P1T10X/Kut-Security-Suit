// Package postgres embeds the versioned PostgreSQL migrations so the binaries that apply them
// need no files next to them.
package postgres

import "embed"

// Migrations holds the goose migration files under "migrations/".
//
//go:embed migrations/*.sql
var Migrations embed.FS
