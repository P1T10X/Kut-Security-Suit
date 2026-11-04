package dbmigrate

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"kut.corp/suite/db/postgres"
)

// baselineStatementsSHA256 pins the executable content of the baseline migration (comments and
// whitespace outside literals removed). The baseline is applied on existing installs, so its
// statements must only change through a new migration.
const baselineStatementsSHA256 = "88cc07fe88301c0074555f1e50b673c54c8cfa199d3b607aa55b11fae60de159"

// stripSQLComments removes "--" line comments and "/* */" block comments and collapses runs of
// whitespace to a single space, leaving single-quoted strings, double-quoted identifiers and
// dollar-quoted bodies byte-for-byte intact so comment markers inside them are not misread.
func stripSQLComments(src string) string {
	var out strings.Builder
	n := len(src)
	space := func() {
		if cur := out.String(); cur != "" && cur[len(cur)-1] != ' ' {
			out.WriteByte(' ')
		}
	}
	for i := 0; i < n; {
		c := src[i]
		switch {
		case c == '-' && i+1 < n && src[i+1] == '-':
			for i < n && src[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < n && src[i+1] == '*':
			depth := 1
			i += 2
			for i < n && depth > 0 {
				switch {
				case src[i] == '/' && i+1 < n && src[i+1] == '*':
					depth++
					i += 2
				case src[i] == '*' && i+1 < n && src[i+1] == '/':
					depth--
					i += 2
				default:
					i++
				}
			}
			space()
		case c == '\'' || c == '"':
			j := i + 1
			for j < n {
				if src[j] == c {
					if j+1 < n && src[j+1] == c { // doubled quote is an escape
						j += 2
						continue
					}
					break
				}
				j++
			}
			if j < n {
				j++
			}
			out.WriteString(src[i:j])
			i = j
		case c == '$':
			if tag := dollarTag(src[i:]); tag != "" {
				end := strings.Index(src[i+len(tag):], tag)
				if end < 0 {
					out.WriteString(src[i:])
					i = n
				} else {
					j := i + len(tag) + end + len(tag)
					out.WriteString(src[i:j])
					i = j
				}
				break
			}
			out.WriteByte(c)
			i++
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			for i < n && (src[i] == ' ' || src[i] == '\t' || src[i] == '\n' || src[i] == '\r') {
				i++
			}
			space()
		default:
			out.WriteByte(c)
			i++
		}
	}
	return strings.TrimSpace(out.String())
}

// dollarTag returns the opening dollar-quote tag ("$$" or "$name$") at the start of s, or "".
func dollarTag(s string) string {
	for k := 1; k < len(s); k++ {
		switch ch := s[k]; {
		case ch == '$':
			return s[:k+1]
		case ch == '_' || (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (k > 1 && ch >= '0' && ch <= '9'):
		default:
			return ""
		}
	}
	return ""
}

func TestStripSQLCommentsKeepsLiteralsAndBodies(t *testing.T) {
	in := "SELECT 'a -- b', \"c--d\"; -- gone\n/* x /* y */ z */ SELECT $$ -- kept\n$$;\nSELECT $t$ /* kept */ $t$, 1;"
	want := "SELECT 'a -- b', \"c--d\"; SELECT $$ -- kept\n$$; SELECT $t$ /* kept */ $t$, 1;"
	if got := stripSQLComments(in); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// Changing only comments in the baseline must leave its executable statements untouched.
func TestBaselineExecutableStatementsUnchanged(t *testing.T) {
	raw, err := postgres.Migrations.ReadFile("migrations/00001_baseline.sql")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(stripSQLComments(strings.ReplaceAll(string(raw), "\r\n", "\n"))))
	if got := hex.EncodeToString(sum[:]); got != baselineStatementsSHA256 {
		t.Fatalf("baseline executable statements changed: sha256 %s, want %s; add a new migration instead of editing the baseline", got, baselineStatementsSHA256)
	}
}
