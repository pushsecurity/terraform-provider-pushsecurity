package provider

import (
	"strings"
	"testing"

	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/pushapi"
)

func TestParseAliasPattern(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		wantErr string
	}{
		{name: "local suffix", pattern: "{local}.admin@{domain}"},
		{name: "plus addressing", pattern: "{local}+svc@{domain}"},
		{name: "subdomain", pattern: "{local}@admin.{domain}"},
		{name: "fixed domain", pattern: "{local}@admin.example.com"},
		{name: "empty", pattern: "  ", wantErr: "empty"},
		{name: "no at", pattern: "{local}.admin", wantErr: "exactly one @"},
		{name: "two ats", pattern: "{local}@a@b.com", wantErr: "exactly one @"},
		{name: "no placeholder", pattern: "admin@example.com", wantErr: "no placeholder"},
		// A mistyped placeholder is the failure worth catching: as a literal
		// it would parse, match nobody, and look like a rule that simply had
		// nothing to do.
		{name: "unknown placeholder", pattern: "{localpart}.admin@{domain}", wantErr: "unknown placeholder"},
		{name: "unterminated placeholder", pattern: "{local.admin@{domain}", wantErr: "unknown placeholder"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseAliasPattern(tt.pattern)
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("parseAliasPattern(%q) = %v, want no error", tt.pattern, err)
			case tt.wantErr != "" && err == nil:
				t.Fatalf("parseAliasPattern(%q) = nil, want error containing %q", tt.pattern, tt.wantErr)
			case tt.wantErr != "" && !strings.Contains(err.Error(), tt.wantErr):
				t.Errorf("parseAliasPattern(%q) = %v, want error containing %q", tt.pattern, err, tt.wantErr)
			}
		})
	}
}

func TestAliasPatternInstantiate(t *testing.T) {
	tests := []struct {
		pattern string
		primary string
		want    string
	}{
		{"{local}.admin@{domain}", "a.person@example.org", "a.person.admin@example.org"},
		{"{local}+support@{domain}", "a.person@example.org", "a.person+support@example.org"},
		{"{local}@admin.{domain}", "a.person@example.org", "a.person@admin.example.org"},
		{"{local}.admin@{domain}", "A.Person@EXAMPLE.org", "a.person.admin@example.org"},
		// Nothing to instantiate from.
		{"{local}.admin@{domain}", "not-an-address", ""},
		// A pattern that reproduces the primary would ask the API to merge
		// somebody into themselves, which it rejects.
		{"{local}@{domain}", "a.person@example.org", ""},
	}

	for _, tt := range tests {
		p, err := parseAliasPattern(tt.pattern)
		if err != nil {
			t.Fatalf("parseAliasPattern(%q): %v", tt.pattern, err)
		}
		if got := p.instantiate(tt.primary); got != tt.want {
			t.Errorf("%q.instantiate(%q) = %q, want %q", tt.pattern, tt.primary, got, tt.want)
		}
	}
}

// employees builds an inventory from addresses, giving each a stable
// identifier derived from the address.
func employees(emails ...string) []pushapi.Employee {
	out := make([]pushapi.Employee, 0, len(emails))
	for _, e := range emails {
		out = append(out, pushapi.Employee{ID: "id-" + e, Email: e})
	}
	return out
}

func patterns(t *testing.T, raw ...string) []aliasPattern {
	t.Helper()
	out := make([]aliasPattern, 0, len(raw))
	for _, r := range raw {
		p, err := parseAliasPattern(r)
		if err != nil {
			t.Fatalf("parseAliasPattern(%q): %v", r, err)
		}
		out = append(out, p)
	}
	return out
}

func TestFindAliasMatches(t *testing.T) {
	admin := patterns(t, "{local}.admin@{domain}", "{local}.support@{domain}")

	tests := []struct {
		name          string
		employees     []pushapi.Employee
		patterns      []aliasPattern
		scope         aliasScope
		want          []string
		wantConflicts []string
	}{
		{
			name:      "pairs each alias with its owner",
			employees: employees("a@example.org", "a.admin@example.org", "a.support@example.org", "b@example.org"),
			patterns:  admin,
			want: []string{
				"a.admin@example.org -> a@example.org",
				"a.support@example.org -> a@example.org",
			},
		},
		{
			name:      "an alias with no owner is left alone",
			employees: employees("orphan.admin@example.org"),
			patterns:  admin,
		},
		{
			name:      "an owner with no alias is left alone",
			employees: employees("a@example.org"),
			patterns:  admin,
		},
		{
			// Without this, a@ takes a.admin@ and a.admin@ takes
			// a.admin.admin@ in the same apply, and an unrepeatable operation
			// runs twice on one person.
			name:      "aliases do not chain",
			employees: employees("a@example.org", "a.admin@example.org", "a.admin.admin@example.org"),
			patterns:  admin,
			want:      []string{"a.admin@example.org -> a@example.org"},
		},
		{
			name:      "case is not significant",
			employees: employees("A.Person@Example.org", "a.person.ADMIN@example.org"),
			patterns:  admin,
			want:      []string{"a.person.admin@example.org -> a.person@example.org"},
		},
		{
			name:      "domains narrow the primaries considered",
			employees: employees("a@example.org", "a.admin@example.org", "c@contractor.com", "c.admin@contractor.com"),
			patterns:  admin,
			scope:     aliasScope{Domains: []string{"example.org"}},
			want:      []string{"a.admin@example.org -> a@example.org"},
		},
		{
			name:      "exclusions apply to both sides of a pair",
			employees: employees("a@example.org", "a.admin@example.org", "b@example.org", "b.admin@example.org"),
			patterns:  admin,
			scope:     aliasScope{Excluded: []string{"a@example.org", "b.admin@example.org"}},
		},
		{
			// support@ is one character away from being everybody's alias
			// under a `{local}support@{domain}` style pattern; the provider
			// must not guess whose it is.
			name:      "an address two people could claim is a conflict",
			employees: employees("a@example.org", "b@example.org", "shared@example.org"),
			patterns:  patterns(t, "shared@{domain}"),
			wantConflicts: []string{
				"shared@example.org is claimed by a@example.org and b@example.org",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, conflicts := findAliasMatches(tt.employees, tt.patterns, tt.scope)

			got := matchStrings(matches)
			if len(got) != len(tt.want) {
				t.Fatalf("matches = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("matches[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}

			if len(conflicts) != len(tt.wantConflicts) {
				t.Fatalf("conflicts = %v, want %v", conflicts, tt.wantConflicts)
			}
			for i, c := range conflicts {
				if c.Error() != tt.wantConflicts[i] {
					t.Errorf("conflicts[%d] = %q, want %q", i, c.Error(), tt.wantConflicts[i])
				}
			}
		})
	}
}

// The identifiers a match carries are what the merge call uses, so a match
// that names the right addresses but the wrong records would merge the wrong
// people.
func TestFindAliasMatchesCarriesIdentifiers(t *testing.T) {
	inventory := employees("a@example.org", "a.admin@example.org")
	matches, _ := findAliasMatches(inventory, patterns(t, "{local}.admin@{domain}"), aliasScope{})
	if len(matches) != 1 {
		t.Fatalf("matches = %v, want one", matchStrings(matches))
	}
	if matches[0].PrimaryID != "id-a@example.org" {
		t.Errorf("PrimaryID = %q", matches[0].PrimaryID)
	}
	if matches[0].SecondaryID != "id-a.admin@example.org" {
		t.Errorf("SecondaryID = %q", matches[0].SecondaryID)
	}
}
