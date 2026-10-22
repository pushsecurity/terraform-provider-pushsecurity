package provider

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/pushapi"
)

// Alias patterns express the shape of a person's second address —
// `{local}.admin@{domain}`, `{local}+support@{domain}`,
// `{local}@admin.{domain}` — so that a rule can say "merge these into the
// person they belong to" without naming anybody.
//
// A pattern is instantiated against a *primary* address and the result is
// looked for in the tenant, rather than being matched against every address as
// a wildcard would be. That direction is the whole point: a match then carries
// the primary it belongs to, which is what the merge needs. A regular
// expression could find `ada.lovelace.admin@example.com` but could not say whose
// it is.

const (
	placeholderLocal  = "{local}"
	placeholderDomain = "{domain}"
)

type aliasPattern struct {
	raw string
}

// parseAliasPattern enforces the constraints that make instantiation total: exactly one `@`, at
// least one placeholder, and no placeholder other than the two understood
// ones — a typo like `{localpart}` would otherwise be treated as a literal and
// match nobody, with nothing to say why.
func parseAliasPattern(raw string) (aliasPattern, error) {
	p := strings.TrimSpace(raw)
	if p == "" {
		return aliasPattern{}, errors.New("pattern is empty")
	}
	if n := strings.Count(p, "@"); n != 1 {
		return aliasPattern{}, fmt.Errorf("pattern %q must contain exactly one @, found %d", raw, n)
	}
	if !strings.Contains(p, placeholderLocal) && !strings.Contains(p, placeholderDomain) {
		return aliasPattern{}, fmt.Errorf(
			"pattern %q contains no placeholder: use %s, %s or both, otherwise the pattern "+
				"names one fixed address rather than a shape",
			raw, placeholderLocal, placeholderDomain)
	}
	if rest := unknownPlaceholder(p); rest != "" {
		return aliasPattern{}, fmt.Errorf(
			"pattern %q contains unknown placeholder %s: only %s and %s are understood",
			raw, rest, placeholderLocal, placeholderDomain)
	}
	return aliasPattern{raw: strings.ToLower(p)}, nil
}

// unknownPlaceholder returns the first `{…}` token that is not one of the two
// understood placeholders, or "" if there is none.
func unknownPlaceholder(p string) string {
	rest := p
	for {
		open := strings.Index(rest, "{")
		if open < 0 {
			return ""
		}
		shut := strings.Index(rest[open:], "}")
		if shut < 0 {
			return rest[open:]
		}
		token := rest[open : open+shut+1]
		if token != placeholderLocal && token != placeholderDomain {
			return token
		}
		rest = rest[open+shut+1:]
	}
}

// instantiate fills the pattern in from a primary address, returning "" when
// the address cannot be split.
func (p aliasPattern) instantiate(primary string) string {
	local, domain, ok := strings.Cut(strings.ToLower(strings.TrimSpace(primary)), "@")
	if !ok || local == "" || domain == "" {
		return ""
	}
	out := strings.ReplaceAll(p.raw, placeholderLocal, local)
	out = strings.ReplaceAll(out, placeholderDomain, domain)
	if out == strings.ToLower(strings.TrimSpace(primary)) {
		// A pattern that instantiates to the primary itself — `{local}@{domain}`
		// — would ask the API to merge somebody into themselves.
		return ""
	}
	return out
}

// aliasMatch is one address to merge, and the primary it belongs to.
type aliasMatch struct {
	PrimaryEmail   string
	PrimaryID      string
	SecondaryEmail string
	SecondaryID    string
}

func (m aliasMatch) String() string {
	return m.SecondaryEmail + " -> " + m.PrimaryEmail
}

// aliasScope narrows which employees a rule considers.
type aliasScope struct {
	Domains  []string // primary must be in one of these domains; empty means any
	Excluded []string // addresses that are never a primary and never merged
}

func (s aliasScope) allowsPrimary(email string) bool {
	if s.excludes(email) {
		return false
	}
	if len(s.Domains) == 0 {
		return true
	}
	_, domain, ok := strings.Cut(strings.ToLower(email), "@")
	if !ok {
		return false
	}
	for _, d := range s.Domains {
		if strings.EqualFold(strings.TrimSpace(d), domain) {
			return true
		}
	}
	return false
}

func (s aliasScope) excludes(email string) bool {
	for _, e := range s.Excluded {
		if strings.EqualFold(strings.TrimSpace(e), strings.TrimSpace(email)) {
			return true
		}
	}
	return false
}

// aliasConflict is one address that more than one primary claims.
type aliasConflict struct {
	SecondaryEmail string
	Primaries      []string
}

func (c aliasConflict) Error() string {
	return fmt.Sprintf("%s is claimed by %s", c.SecondaryEmail, strings.Join(c.Primaries, " and "))
}

// findAliasMatches pairs every employee whose address is an instantiation of
// one of the patterns with the employee it was instantiated from.
//
// Returned matches are sorted, so a plan renders the same way twice.
//
// Three cases are deliberately not matched:
//
//   - An employee that is itself somebody's alias is never a primary. Without
//     that, `{local}.admin@…` makes `a.admin.admin@…` a merge target of
//     `a.admin@…`, and a chain of merges is much harder to undo than a single
//     one: only addresses that had accounts can be split out again, one at a
//     time, each as a new employee.
//   - An address claimed by two primaries is reported as a conflict rather
//     than merged into whichever was seen first.
//   - Anything the scope excludes, on either side of the pair.
func findAliasMatches(employees []pushapi.Employee, patterns []aliasPattern, scope aliasScope) ([]aliasMatch, []aliasConflict) {
	byEmail := make(map[string]pushapi.Employee, len(employees))
	for _, e := range employees {
		if e.Email == "" || e.ID == "" {
			continue
		}
		byEmail[strings.ToLower(e.Email)] = e
	}

	// First pass: every address that is an alias of some other employee. These
	// are excluded as primaries in the second pass.
	isAlias := make(map[string]bool, len(employees))
	for _, e := range employees {
		for _, p := range patterns {
			if target := p.instantiate(e.Email); target != "" {
				if _, ok := byEmail[target]; ok {
					isAlias[target] = true
				}
			}
		}
	}

	claims := make(map[string][]aliasMatch)
	for _, e := range employees {
		email := strings.ToLower(e.Email)
		if email == "" || e.ID == "" || isAlias[email] || !scope.allowsPrimary(e.Email) {
			continue
		}
		for _, p := range patterns {
			target := p.instantiate(email)
			if target == "" || scope.excludes(target) {
				continue
			}
			secondary, ok := byEmail[target]
			if !ok || secondary.ID == e.ID {
				continue
			}
			claims[target] = append(claims[target], aliasMatch{
				PrimaryEmail:   email,
				PrimaryID:      e.ID,
				SecondaryEmail: target,
				SecondaryID:    secondary.ID,
			})
		}
	}

	var matches []aliasMatch
	var conflicts []aliasConflict
	for target, cs := range claims {
		primaries := distinctPrimaries(cs)
		if len(primaries) > 1 {
			conflicts = append(conflicts, aliasConflict{SecondaryEmail: target, Primaries: primaries})
			continue
		}
		matches = append(matches, cs[0])
	}

	sort.Slice(matches, func(i, j int) bool { return matches[i].String() < matches[j].String() })
	sort.Slice(conflicts, func(i, j int) bool { return conflicts[i].SecondaryEmail < conflicts[j].SecondaryEmail })
	return matches, conflicts
}

func distinctPrimaries(matches []aliasMatch) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range matches {
		if !seen[m.PrimaryEmail] {
			seen[m.PrimaryEmail] = true
			out = append(out, m.PrimaryEmail)
		}
	}
	sort.Strings(out)
	return out
}
