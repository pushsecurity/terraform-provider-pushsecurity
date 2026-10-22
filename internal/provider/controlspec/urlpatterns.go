package controlspec

// URL pattern checks: CheckValue for MatchPatternURLs and GlobURLs.
//
// The Push API accepts some URL patterns that can never match, and how a
// pattern matches differs from control to control. These checks catch both
// during plan.
//
// The API also rewrites a pattern with no path, which these checks mirror so
// that the read-back does not fail the apply; see storedURLPattern.
//
// The checks rely on how each control matches a pattern:
//
//   - File download and upload blocking evaluate a pattern as a WebExtension
//     match pattern. A pattern that is not a valid match pattern never
//     matches.
//   - Clipboard blocking and the URL pattern app banner match a pattern as a
//     regular expression in which `*` is `.*`, `.` matches only itself, and
//     every other character keeps its regular expression meaning. It is
//     tested against the page's URL without its query string or fragment.

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// anyScheme is the prefix every URL pattern must have.
const anyScheme = "*://"

// maxURLPatternLength is the API's limit on a whole pattern: a 75-character
// host, a 256-character path, and four characters for `*://`.
const maxURLPatternLength = 75 + 256 + 4

// The parts of the URL pattern grammar the API accepts. Expressed as a single
// regular expression it needs lookahead, which Go's regexp does not have, so
// parseURLPattern splits the host, port and path apart and these check each
// one.
var (
	wildcardHostRegex = regexp.MustCompile(`^\*\.([a-z0-9-]+\.)*[a-z0-9-]+\.[a-z]+$`)
	domainHostRegex   = regexp.MustCompile(`^([a-z0-9-]+\.)+[a-z]+$`)
	// A single-label host must also contain a letter, so that a bare number is
	// not read as an IPv4 address.
	labelHostRegex = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)
	ipv4HostRegex  = regexp.MustCompile(
		`^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`)
	// pathCharsRegex is the characters a path may contain.
	pathCharsRegex = regexp.MustCompile(`^[A-Za-z0-9_,;=:/@%!'.~$&()*+?#-]*$`)
)

// urlPattern is a URL pattern without its `*://`, split into its parts.
type urlPattern struct {
	host string // as written, e.g. "*.example.com"
	port string // digits only, or "" for none
	path string // "", or everything from the first `/`, `*`, `?` or `#` on
}

func (u urlPattern) String() string {
	s := anyScheme + u.host
	if u.port != "" {
		s += ":" + u.port
	}
	return s + u.path
}

// parseURLPattern splits what follows `*://` into host, port and path, and
// names the first part the API would reject: "host", "port" or "path", or ""
// when it accepts the pattern.
//
// The split is the only one the grammar allows. After an optional leading
// `*.`, a host is made of [a-z0-9.-] and cannot contain any of `:/*?#`. A port
// starts with `:` and a path with one of `/*?#`. So the host ends exactly at
// the first of those characters.
func parseURLPattern(rest string) (urlPattern, string) {
	start := 0
	if strings.HasPrefix(rest, "*.") {
		start = 2
	}
	end := len(rest)
	if i := strings.IndexAny(rest[start:], ":/*?#"); i >= 0 {
		end = start + i
	}
	u := urlPattern{host: rest[:end], path: rest[end:]}

	if strings.HasPrefix(u.path, ":") {
		n := 1
		for n < len(u.path) && isDigit(u.path[n]) {
			n++
		}
		u.port, u.path = u.path[1:n], u.path[n:]
	}

	switch {
	case !validHost(u.host):
		return u, "host"
	case strings.HasPrefix(rest[end:], ":") && (u.port == "" || len(u.port) > 5):
		return u, "port"
	case !validPath(u.path):
		return u, "path"
	}
	return u, ""
}

func validHost(h string) bool {
	if wildcardHostRegex.MatchString(h) || domainHostRegex.MatchString(h) ||
		ipv4HostRegex.MatchString(h) {
		return true
	}
	return labelHostRegex.MatchString(h) && strings.ContainsAny(h, "abcdefghijklmnopqrstuvwxyz")
}

func validPath(p string) bool {
	if p == "" {
		return true
	}
	if !strings.ContainsRune("/*?#", rune(p[0])) {
		return false
	}
	// A port written after a wildcard, as in `example.com*:8080`, is rejected.
	if len(p) > 2 && p[0] == '*' && p[1] == ':' && isDigit(p[2]) {
		return false
	}
	return pathCharsRegex.MatchString(p[1:])
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

// storedURLPattern is what the API stores for a pattern it accepts. A pattern
// with no path gets `/*`, and a `?` or `#` straight after the host gets `/` in
// front of it.
func storedURLPattern(p string) string {
	rest := strings.TrimPrefix(p, anyScheme)
	i := strings.IndexAny(rest, "/?#")
	switch {
	case i < 0:
		return p + "/*"
	case rest[i] == '/':
		return p
	}
	return anyScheme + rest[:i] + "/" + rest[i:]
}

func checkURLPattern(p string, kind ValueKind) *ValueProblem {
	if n := utf8.RuneCountInString(p); n > maxURLPatternLength {
		return &ValueProblem{
			Summary: "URL pattern is too long",
			Detail: fmt.Sprintf("The Push API accepts URL patterns of at most %d characters; "+
				"this one has %d.", maxURLPatternLength, n),
		}
	}

	if !strings.HasPrefix(p, anyScheme) {
		fixed := anyScheme + p
		if i := strings.Index(p, "://"); i >= 0 {
			fixed = anyScheme + p[i+3:]
		}
		return &ValueProblem{
			Summary: "URL pattern must start with `*://`",
			Detail: fmt.Sprintf("The Push API only accepts URL patterns that start with `*://`, "+
				"which matches both http and https. Write %q.", fixed),
		}
	}

	u, bad := parseURLPattern(strings.TrimPrefix(p, anyScheme))
	if bad != "" {
		return rejectedURLPattern(p, bad)
	}

	switch kind {
	case MatchPatternURLs:
		if prob := checkMatchPattern(p, u); prob != nil {
			return prob
		}
	case GlobURLs:
		if prob := checkGlobURL(p, u); prob != nil {
			return prob
		}
	}

	if stored := storedURLPattern(p); stored != p {
		return &ValueProblem{
			Summary: "The Push API rewrites this URL pattern",
			Detail: fmt.Sprintf("The Push API stores %q as %q: it adds `/*` to a pattern with "+
				"no path, and puts a `/` before a `?` or `#` that follows the host. The provider "+
				"reads back what the API stored, so the apply would fail with \"Provider "+
				"produced inconsistent result after apply\". Write %q.", p, stored, stored),
		}
	}

	if kind == MatchPatternURLs && u.port == "443" {
		u.port = ""
		return &ValueProblem{
			Warning: true,
			Summary: "The port in this URL pattern is ignored",
			Detail: fmt.Sprintf("`:443` has no effect in a file download or upload URL "+
				"pattern: %q matches the host on every port, not just 443. "+
				"Write %q to say so.", p, u.String()),
		}
	}

	return nil
}

// rejectedURLPattern explains why the API rejects a pattern, as specifically
// as the part that failed allows.
func rejectedURLPattern(p, bad string) *ValueProblem {
	// The host as the user wrote it, wildcards included. parseURLPattern ends
	// a host at a `*`, which is right for a valid pattern and unhelpful for
	// explaining an invalid one such as `pub-*.r2.dev`.
	rest := strings.TrimPrefix(p, anyScheme)
	written := rest
	if i := strings.IndexAny(rest, ":/?#"); i >= 0 {
		written = rest[:i]
	}

	var why string
	switch {
	case bad == "host" && (written == "" || written == "*"):
		why = "It has no host. The API does not accept a bare `*` as the host, as in " +
			"`*://*/path`: name the host, or every subdomain of a domain, as in " +
			"`*://*.example.com/*`."
	case bad == "host" && strings.ToLower(written) != written:
		why = "The host must be lowercase."
		lower := strings.ToLower(written) + rest[len(written):]
		if _, stillBad := parseURLPattern(lower); stillBad == "" {
			why += fmt.Sprintf(" Write %q.", anyScheme+lower)
		}
	case bad == "host" && strings.Contains(written, "*"):
		why = "The only wildcard the API accepts in a host is a leading `*.` followed by a " +
			"domain, as in `*.example.com`. It does not accept one inside a label " +
			"(`pub-*.r2.dev`), in place of the top-level domain (`example.*`), or in front of " +
			"a top-level domain alone (`*.com`)."
	case bad == "host":
		why = "The host must be a lowercase domain, a domain with a leading `*.`, a " +
			"single-label name containing a letter (such as `intranet`), or an IPv4 address."
	case bad == "port":
		why = "A port must be `:` followed by one to five digits."
	default:
		why = "After the host and port, a path must start with `/`, `*`, `?` or `#`, and can " +
			"only contain letters, digits and the characters `_,;=:/@%!'.~$&()*+?#-`."
	}
	return &ValueProblem{
		Summary: "Not a URL pattern the Push API accepts",
		Detail:  fmt.Sprintf("The Push API rejects %q. %s", p, why),
	}
}

// checkMatchPattern catches patterns the API stores that are not valid match
// patterns. An invalid pattern never matches, so a rule whose patterns are
// all invalid never matches, and no error reports it.
func checkMatchPattern(p string, u urlPattern) *ValueProblem {
	const summary = "URL pattern never matches"

	switch {
	case strings.HasPrefix(u.path, "*"):
		example := u
		example.path = "/*"
		return &ValueProblem{
			Summary: summary,
			Detail: fmt.Sprintf("%q has a `*` straight after the host. A file download or "+
				"upload URL pattern must not have one: the pattern never matches. Start the "+
				"path with `/`, for example %q.", p, example.String()),
		}

	// `:443` alone is valid, and ignored; checkURLPattern warns about it.
	// Every other port, `:80` included, makes the pattern invalid.
	case u.port != "" && u.port != "443":
		fixed := u
		fixed.port = ""
		return &ValueProblem{
			Summary: summary,
			Detail: fmt.Sprintf("%q has a port. A file download or upload URL pattern must "+
				"not have one: the pattern never matches. Without a port, a pattern matches "+
				"the host on every port, this one included. Write %q.", p, storedURLPattern(fixed.String())),
		}

	case strings.Contains(u.path, "#"):
		fixed := u
		fixed.path, _, _ = strings.Cut(u.path, "#")
		return &ValueProblem{
			Summary: summary,
			Detail: fmt.Sprintf("%q has a fragment. A file download or upload URL pattern "+
				"must not have one: the pattern never matches. Write %q.", p, storedURLPattern(fixed.String())),
		}
	}

	return nil
}

// checkGlobURL catches patterns the API stores and that can never match the
// URL clipboard blocking and the URL pattern app banner compare them with.
func checkGlobURL(p string, u urlPattern) *ValueProblem {
	const summary = "URL pattern never matches"

	switch {
	// A page URL as the browser writes it has no default port, so `:443` and
	// `:80` never match. Strictly, `:443` would match plain http on port 443
	// and `:80` https on port 80, which is not what anyone means. A
	// non-default port is fine: it matches that port, and only that port.
	case u.port == "443" || u.port == "80":
		fixed := u
		fixed.port = ""
		return &ValueProblem{
			Summary: summary,
			Detail: fmt.Sprintf("%q names a default port. A page's URL leaves the default "+
				"port out, and the pattern is compared with the URL as written, so the pattern "+
				"never matches. Write %q.", p, storedURLPattern(fixed.String())),
		}

	case strings.ContainsAny(u.path, "?#"):
		fixed := u
		fixed.path = u.path[:strings.IndexAny(u.path, "?#")]
		return &ValueProblem{
			Summary: summary,
			Detail: fmt.Sprintf("%q has a query string or fragment. The pattern is compared "+
				"with the page's URL without either, so the pattern never matches, and `?` "+
				"does not match itself. Without them, the pattern matches the page whatever "+
				"its query string. Write %q.", p, storedURLPattern(fixed.String())),
		}

	case strings.ContainsAny(u.path, "+()$"):
		fixed := u
		fixed.path = strings.NewReplacer("+", "*", "(", "*", ")", "*", "$", "*").Replace(u.path)
		return &ValueProblem{
			Summary: summary,
			Detail: fmt.Sprintf("%q contains `+`, `(`, `)` or `$`. In a URL pattern on this "+
				"control these are regular expression operators and do not match themselves, "+
				"and a pattern with an unbalanced `(` never matches. Use `*` in their place. "+
				"Write %q.", p, fixed.String()),
		}
	}

	return nil
}
