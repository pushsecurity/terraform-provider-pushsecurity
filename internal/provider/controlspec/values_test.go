package controlspec

import (
	"regexp"
	"strings"
	"testing"
)

type valueCase struct {
	in string
	// want is a fragment of the problem's Detail, or "" when the value must
	// pass. warn marks a problem that must be a warning rather than an error.
	want string
	warn bool
}

// runValueCases checks each case against a criterion of the given kind, and
// that whatever a diagnostic tells the user to write passes the same check:
// a suggestion that fails in turn sends the user round in circles.
func runValueCases(t *testing.T, kind ValueKind, cases []valueCase) {
	t.Helper()
	c := Criterion{Name: "test", Values: kind}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got := c.CheckValue(tc.in)
			switch {
			case tc.want == "" && got != nil:
				t.Fatalf("CheckValue(%q) = %+v, want no problem", tc.in, *got)
			case tc.want == "":
				return
			case got == nil:
				t.Fatalf("CheckValue(%q) = nil, want a problem mentioning %q", tc.in, tc.want)
			}
			if !strings.Contains(got.Detail, tc.want) {
				t.Errorf("Detail = %q, want it to contain %q", got.Detail, tc.want)
			}
			if got.Warning != tc.warn {
				t.Errorf("Warning = %v, want %v", got.Warning, tc.warn)
			}
			if fix := suggestion(got.Detail); fix != "" {
				if again := c.CheckValue(fix); again != nil && !again.Warning {
					t.Errorf("suggested %q, which fails in turn: %s", fix, again.Detail)
				}
			}
		})
	}
}

var writeRegex = regexp.MustCompile(`Write "((?:[^"\\]|\\.)*)"`)

// suggestion extracts the value a Detail tells the user to write, if any.
func suggestion(detail string) string {
	m := writeRegex.FindStringSubmatch(detail)
	if m == nil {
		return ""
	}
	return strings.ReplaceAll(m[1], `\\`, `\`)
}

// Shared by both URL kinds: what the API itself rejects or rewrites.
var urlAPICases = []valueCase{
	// Patterns that must keep working.
	{in: "*://*.anydesk.com/*"},
	{in: "*://anydesk.com/*"},
	{in: "*://download.anydesk.com/AnyDesk.exe"},
	{in: "*://*.screenconnect.com/Bin/*"},
	{in: "*://*.example.com/"},
	{in: "*://203.0.113.5/*"},
	{in: "*://localhost/*"},
	{in: "*://*.co.uk/*"},
	{in: "*://xn--bcher-kva.example/*"},

	// No path: the API appends one, and the read-back differs.
	{in: "*://*.anydesk.com", want: `Write "*://*.anydesk.com/*"`},
	{in: "*://example.com", want: `Write "*://example.com/*"`},

	// Rejected outright by the API.
	{in: "https://example.com/*", want: `Write "*://example.com/*"`},
	{in: "example.com/*", want: `Write "*://example.com/*"`},
	{in: "*://Example.com/*", want: `Write "*://example.com/*"`},
	{in: "*://*/meshagents*", want: "It has no host"},
	{in: "*://pub-*.r2.dev/*", want: "leading `*.`"},
	{in: "*://example.*/*", want: "leading `*.`"},
	{in: "*://*.com/*", want: "leading `*.`"},
	{in: "*://8080/*", want: "single-label name containing a letter"},
	{in: "*://exa_mple.com/*", want: "lowercase domain"},
	{in: "*://example.com:123456/*", want: "one to five digits"},
	{in: "*://example.com:/*", want: "one to five digits"},
	{in: "*://example.com*:8080/*", want: "a path must start with"},
	{in: "*://example.com/a b", want: "a path must start with"},
	{in: "*://example.com/" + strings.Repeat("a", 331), want: "at most 335 characters"},
}

func TestCheckValueMatchPatternURLs(t *testing.T) {
	runValueCases(t, MatchPatternURLs, append(urlAPICases, []valueCase{
		// Query characters are fine for the file controls' matcher.
		{in: "*://example.com/a?b=c"},
		{in: "*://example.com/a+b(c)$&d"},

		// A `?` straight after the host is rewritten by the API.
		{in: "*://example.com?q=1", want: `Write "*://example.com/?q=1"`},

		// Accepted by the API, and never matched.
		{in: "*://example.com*", want: "`*` straight after the host"},
		{in: "*://*.example.com*/*", want: "`*` straight after the host"},
		{in: "*://203.0.113.5:8040/*", want: `Write "*://203.0.113.5/*"`},
		{in: "*://example.com:8443", want: `Write "*://example.com/*"`},
		{in: "*://example.com:80/*", want: "has a port"},
		{in: "*://example.com/#frag", want: `Write "*://example.com/"`},
		{in: "*://example.com/page#frag", want: `Write "*://example.com/page"`},
		{in: "*://example.com#frag", want: "has a fragment"},

		// `:443` works, but means every port.
		{in: "*://example.com:443/*", want: `Write "*://example.com/*"`, warn: true},
	}...))
}

func TestCheckValueGlobURLs(t *testing.T) {
	runValueCases(t, GlobURLs, append(urlAPICases, []valueCase{
		// The clipboard and banner matcher handles these.
		{in: "*://example.com*/*"},
		{in: "*://example.com:8040/*"},
		{in: "*://example.com/a&b"},
		{in: "*://example.com/a,b;c=d@e%20f!g'h~i"},

		// No path, so the API appends one; the pattern works either way.
		{in: "*://example.com*", want: `Write "*://example.com*/*"`},

		// A default port never appears in the page URL a pattern is compared with.
		{in: "*://example.com:443/*", want: `Write "*://example.com/*"`},
		{in: "*://example.com:80/*", want: `Write "*://example.com/*"`},

		// The query and fragment are removed before comparing.
		{in: "*://example.com/a?b=c", want: `Write "*://example.com/a"`},
		{in: "*://example.com/x#frag", want: `Write "*://example.com/x"`},
		{in: "*://example.com?q=1", want: "query string or fragment"},

		// Regular expression operators, which do not match themselves.
		{in: "*://example.com/a+b", want: `Write "*://example.com/a*b"`},
		{in: "*://example.com/a(b", want: `Write "*://example.com/a*b"`},
		{in: "*://example.com/wiki/Foo_(bar)", want: `Write "*://example.com/wiki/Foo_*bar*"`},
		{in: "*://example.com/a$", want: `Write "*://example.com/a*"`},
	}...))
}

func TestCheckValueFileNameRegexes(t *testing.T) {
	runValueCases(t, FileNameRegexes, []valueCase{
		{in: "anydesk"},
		{in: "^AnyDesk.*\\.exe$"},
		{in: "[Aa]ny[Dd]esk"},
		// Literal parentheses, written the way the API accepts them.
		{in: "^level[ ()0-9]*\\.msi$"},
		{in: "^a\\(b"},
		{in: "(?:x)+"},
		{in: "(?<=a)b"},
		{in: "(?i:abc)"},
		{in: "a{2,}"},
		{in: "a+?b*?"},
		{in: "\\d+\\.\\w{1,4}$"},
		{in: "a}+"},
		{in: "[(]"},
		{in: "[]a]"},

		{in: "", want: "empty"},

		// The API's structural check.
		{in: "(?:a(?:b))", want: "group inside a group"},
		{in: "^level( \\([0-9]+\\))?\\.msi$", want: "escaped `\\(`"},
		{in: "(a+)+", want: "`(a+)+`"},
		{in: "(\\w*)*", want: "`(a+)+`"},
		{in: "(a{2,}){2,}", want: "`(a+)+`"},

		// Syntax the API accepts and JavaScript cannot compile.
		{in: "(?i)anydesk", want: "`[Aa]ny[Dd]esk`"},
		{in: "(?P<n>anydesk)", want: "`(?P…`"},
		{in: "(?P=n)", want: "`(?P…`"},
		{in: "(?#note)anydesk", want: "`(?#…)`"},
		{in: "(?>a)", want: "`(?>…)`"},
		{in: "a++", want: "two quantifiers in a row"},
		{in: "a{2}+", want: "two quantifiers in a row"},
		{in: "a**", want: "two quantifiers in a row"},
		{in: "\\Aanydesk", want: "`^`"},
		{in: "anydesk\\Z", want: "`$`"},

		// JavaScript syntax the API rejects.
		{in: "(?<name>x)", want: "`(?<name>…)`"},

		// Rejected by both.
		{in: "*abc", want: "nothing to repeat"},
		{in: "(*a)", want: "nothing to repeat"},
		{in: "a|*b", want: "nothing to repeat"},
		{in: "$+", want: "nothing to repeat"},
		{in: "[abc", want: "never closes"},
		{in: "abc\\", want: "escapes nothing"},
		{in: "(abc", want: "without a matching `)`"},
		{in: "abc)", want: "without a matching `)`"},
		{in: "\\iabc", want: "does not accept as an escape"},
	})
}

func TestCheckValueLowercase(t *testing.T) {
	runValueCases(t, LowercaseValues, []valueCase{
		{in: "anydesk"},
		{in: "teamviewer_setup"},
		{in: "AnyDesk", want: `Write "anydesk"`},
	})
}

func TestCheckValueFileExtensions(t *testing.T) {
	runValueCases(t, FileExtensionValues, []valueCase{
		{in: ".exe"},
		{in: ".tar.gz"},
		{in: ".x-msdownload"},
		{in: ".EXE", want: `Write ".exe"`},
		{in: "exe", want: "a dot followed by"},
		{in: ".a.b.c", want: "a dot followed by"},
		{in: ".ex e", want: "a dot followed by"},
	})
}

// The API's domain check is loose on purpose: it lowercases, then rejects only
// whitespace, `@`, wildcards, a missing dot and anything over 253 characters.
func TestCheckValueDomains(t *testing.T) {
	runValueCases(t, DomainValues, []valueCase{
		{in: "example.com"},
		{in: "mail.example.co.uk"},
		{in: "xn--bcher-kva.example"},
		{in: "under_score.example.com"},
		{in: "Example.COM", want: `Write "example.com"`},
		{in: "localhost", want: "at least one dot"},
		{in: "*.example.com", want: "no wildcard"},
		{in: "user@example.com", want: "no wildcard, `@`"},
		{in: "example .com", want: "whitespace"},
		{in: "example.com\n", want: "whitespace"},
		{in: strings.Repeat("a", 250) + ".com", want: "at most 253"},
		{in: strings.Repeat("a", 249) + ".com"},
	})
}

func TestPlainValuesAreNotChecked(t *testing.T) {
	if p := (Criterion{Name: "employee_groups"}).CheckValue("Anything At All"); p != nil {
		t.Errorf("a criterion with no Values kind was checked: %+v", *p)
	}
}

// TestCriterionValueKinds pins which matcher each criterion's values go
// through. Getting one wrong would reject patterns that work or pass ones that
// never match.
func TestCriterionValueKinds(t *testing.T) {
	want := map[string]map[string]ValueKind{
		FileDownloadBlocking.TypeName: {
			"file_names":         LowercaseValues,
			"file_name_patterns": FileNameRegexes,
			"file_extensions":    FileExtensionValues,
			"url_patterns":       MatchPatternURLs,
		},
		FileUploadBlocking.TypeName: {
			"file_name_patterns": FileNameRegexes,
			"file_extensions":    FileExtensionValues,
			"url_patterns":       MatchPatternURLs,
		},
		ClipboardBlocking.TypeName:           {"url_patterns": GlobURLs},
		AppBannerURLPattern.TypeName:         {"url_patterns": GlobURLs},
		AccountConditionEnforcement.TypeName: {"login_domains": DomainValues},
	}

	for _, s := range All {
		for _, c := range s.Criteria {
			if got, wantKind := c.Values, want[s.TypeName][c.Name]; got != wantKind {
				t.Errorf("%s.%s has value kind %d, want %d", s.TypeName, c.Name, got, wantKind)
			}
		}
	}
}
