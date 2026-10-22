package provider

import (
	"fmt"
	"regexp"
	"strings"
)

// The blocked URL endpoints use two different formats for the same value, and
// they are not interchangeable:
//
//   - POST accepts a *pattern*: "example.com", "*.example.com/path*".
//   - GET returns a *canonical* form: "*://example.com/*".
//   - POSTing a canonical form is rejected with 400 "Invalid url pattern".
//
// So the list cannot be read and written back, and the provider has to convert
// between the two forms itself. The functions below follow the API's own
// splitting and validation of a pattern, and are pinned by round-trip tests.

// canonicalPrefix is the scheme wildcard the API prepends to everything.
const canonicalPrefix = "*://"

// The host and path rules the API applies to a pattern on POST. A host is
// lower-case ASCII labels of letters, digits, hyphens and `*`, with at least
// one letter somewhere, or an IPv4 address; either may carry a port. A path
// takes letters, digits and the characters of a URL path, query and fragment.
var (
	blockedURLLabel  = `[a-z0-9*]([a-z0-9*-]*[a-z0-9*])?`
	blockedURLLabels = regexp.MustCompile(`^` + blockedURLLabel + `(\.` + blockedURLLabel + `)*$`)
	blockedURLIPv4   = regexp.MustCompile(`^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}` +
		`(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`)
	blockedURLPort = regexp.MustCompile(`^[0-9]{1,5}$`)
	blockedURLPath = regexp.MustCompile(`^[A-Za-z0-9_,;=:/@%!'.~$&()*+?#-]+$`)
	// blockedURLScheme is how the API recognises a scheme at the start of a
	// pattern. "*://" is not one, and is the canonical form's prefix.
	blockedURLScheme = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*://`)
)

// The API's length limits on the two halves of a pattern. The host's includes
// its port; the path's is measured after leading slashes are dropped and
// includes any query string and fragment.
const (
	maxBlockedURLHostLength = 75
	maxBlockedURLPathLength = 256
)

// splitBlockedURL splits a pattern the way the API does: the host runs to the
// first `/`, `?` or `#`, and the rest is the path, with its leading slashes
// dropped and its query string and fragment kept. An empty query string or
// fragment is dropped, and an empty path means every path.
func splitBlockedURL(p string) (host, path string) {
	i := strings.IndexAny(p, "/?#")
	if i < 0 {
		return p, "*"
	}
	host, rest := p[:i], p[i:]
	rest, fragment, _ := strings.Cut(rest, "#")
	rest, query, _ := strings.Cut(rest, "?")
	path = strings.TrimLeft(rest, "/")
	if query != "" {
		path += "?" + query
	}
	if fragment != "" {
		path += "#" + fragment
	}
	if path == "" {
		path = "*"
	}
	return host, path
}

// canonicalizeBlockedURL converts a pattern to the form the API stores and
// returns, so that configuration can be compared with what the API reports.
// An already-canonical value is returned unchanged.
//
// So `example.com`, `example.com/` and `example.com/*` are all
// `*://example.com/*`, and `example.com?q=1` is `*://example.com/?q=1`.
//
// Returns false for input the API would reject.
func canonicalizeBlockedURL(pattern string) (string, bool) {
	p := strings.TrimSpace(pattern)
	// An already-canonical value is accepted here even though POST would
	// reject it, because comparing configuration with what the API reports is
	// the whole purpose.
	p = strings.TrimPrefix(p, canonicalPrefix)

	host, path := splitBlockedURL(p)
	if blockedURLHostProblem(host) != "" || blockedURLPathProblem(path) != "" {
		return "", false
	}
	return canonicalPrefix + host + "/" + path, true
}

// blockedURLPattern converts a canonical value back into a pattern the API's
// POST will accept, which is what the provider has to send when converging.
//
// "*://example.com/*" becomes "example.com"; "*://example.com/path" becomes
// "example.com/path". The conversion is not injective — "example.com",
// "example.com/" and "example.com/*" all canonicalise to the same value — which
// is why comparison is always done in the canonical direction and this is used
// only for writing.
func blockedURLPattern(canonical string) string {
	p := strings.TrimPrefix(canonical, canonicalPrefix)
	host, path, _ := strings.Cut(p, "/")
	if path == "*" {
		return host
	}
	return host + "/" + path
}

func blockedURLHostProblem(host string) string {
	switch {
	case host == "":
		return "has no host"
	case len(host) > maxBlockedURLHostLength:
		return fmt.Sprintf("has a host longer than the %d characters the API accepts",
			maxBlockedURLHostLength)
	case host != strings.ToLower(host):
		return fmt.Sprintf("has upper-case letters in its host, which the API rejects; write %q",
			strings.ToLower(host))
	}
	name, port, hasPort := strings.Cut(host, ":")
	labels := blockedURLLabels.MatchString(name) && strings.ContainsAny(name, "abcdefghijklmnopqrstuvwxyz")
	validName := labels || blockedURLIPv4.MatchString(name)
	if !validName || (hasPort && !blockedURLPort.MatchString(port)) {
		return "has a host the API rejects: write lower-case labels of letters, digits, " +
			"hyphens and `*`, separated by dots and containing at least one letter, or an " +
			"IPv4 address, either optionally followed by a port such as `:8080`"
	}
	return ""
}

func blockedURLPathProblem(path string) string {
	switch {
	case len(path) > maxBlockedURLPathLength:
		return fmt.Sprintf("has a path longer than the %d characters the API accepts",
			maxBlockedURLPathLength)
	case !blockedURLPath.MatchString(path):
		return "has a path the API rejects: a path may hold letters, digits, `*` and " +
			"the characters `_,;=:/@%!'.~$&()+?#-`"
	}
	return ""
}

// validateBlockedURLPattern reports why a pattern is unusable, or "" when it is
// fine. The checks are the API's own, so that a pattern it would reject fails
// during plan: a write that removes a pattern deletes the whole list before
// re-adding it, so a rejection at apply can leave blocking partially restored.
func validateBlockedURLPattern(pattern string) string {
	p := strings.TrimSpace(pattern)
	if p == "" {
		return "must not be empty"
	}
	if scheme := blockedURLScheme.FindString(p); scheme != "" {
		return fmt.Sprintf(
			"must not include a scheme: the API matches every scheme and rejects a pattern "+
				"that names one. Write %q instead",
			strings.TrimLeft(p[len(scheme):], "/"))
	}
	host, path := splitBlockedURL(strings.TrimPrefix(p, canonicalPrefix))
	if problem := blockedURLHostProblem(host); problem != "" {
		return problem
	}
	return blockedURLPathProblem(path)
}
