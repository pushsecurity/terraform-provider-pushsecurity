package provider

import (
	"strings"
	"testing"
)

// The first group of expectations was confirmed against a live tenant: each
// input was POSTed and the stored value read back. The rest follow the API's
// own splitting of a pattern. They are recorded as tests because the
// provider's conversion has to match how the API stores a pattern, and a
// change in that has to show up as a failure rather than as a permanent diff
// in someone's plan.
func TestCanonicalizeBlockedURL(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
		ok   bool
	}{
		// Confirmed against the API.
		{"example.com", "*://example.com/*", true},
		{"example.com/path", "*://example.com/path", true},
		{"example.com/path*", "*://example.com/path*", true},
		{"*.example.com", "*://*.example.com/*", true},
		{"sub.example.com/a/b", "*://sub.example.com/a/b", true},
		{"*.a.b.example.com/x/y*", "*://*.a.b.example.com/x/y*", true},
		// Both spellings mean the same thing to the API, which is why the
		// resource rejects having both in one configuration.
		{"example.com/*", "*://example.com/*", true},
		// The canonical form is accepted for comparison even though the API's
		// POST rejects it, so that state can be compared with configuration.
		{"*://example.com/*", "*://example.com/*", true},
		{"*://sub.example.com/a/b", "*://sub.example.com/a/b", true},
		// The API keeps a query string and fragment in the path, whether or
		// not a slash comes first.
		{"example.com?q=1", "*://example.com/?q=1", true},
		{"example.com#top", "*://example.com/#top", true},
		{"example.com/a?q=1#top", "*://example.com/a?q=1#top", true},
		{"example.com/?q=1", "*://example.com/?q=1", true},
		// An empty path, query string or fragment means every path.
		{"example.com/", "*://example.com/*", true},
		{"example.com//", "*://example.com/*", true},
		{"example.com?", "*://example.com/*", true},
		{"example.com//a", "*://example.com/a", true},
		// Wildcards may sit anywhere in a host label, and a host may carry a
		// port or be an IPv4 address.
		{"example.*", "*://example.*/*", true},
		{"*hello.*.com", "*://*hello.*.com/*", true},
		{"example.com*", "*://example.com*/*", true},
		{"intranet:8080/admin", "*://intranet:8080/admin", true},
		{"10.0.0.1", "*://10.0.0.1/*", true},
		{"*://example.com?q=1", "*://example.com/?q=1", true},
		// Rejected by the API.
		{"EXAMPLE.com", "", false},
		{"*.*", "", false},
		{"8080", "", false},
		{"-example.com", "", false},
		{"example.com:123456", "", false},
		{"example.com:", "", false},
		{"exa mple.com", "", false},
		{"example.com/a b", "", false},
		{"example.com/a|b", "", false},
		{"user@example.com", "", false},
		{"", "", false},
		{"   ", "", false},
		{"/path", "", false},
		{"*://", "", false},
	} {
		t.Run(tc.in, func(t *testing.T) {
			got, ok := canonicalizeBlockedURL(tc.in)
			if ok != tc.ok {
				t.Fatalf("canonicalizeBlockedURL(%q) ok = %v, want %v (got %q)", tc.in, ok, tc.ok, got)
			}
			if got != tc.want {
				t.Errorf("canonicalizeBlockedURL(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestBlockedURLRoundTrip is the property the resource depends on: the API
// rejects its own canonical form, so the provider must be able to turn a stored
// value back into something POST accepts, and that value must canonicalise to
// where it started. Verified live for each of these.
func TestBlockedURLRoundTrip(t *testing.T) {
	for _, canonical := range []string{
		"*://example.com/*",
		"*://example.com/path",
		"*://example.com/path*",
		"*://*.example.com/*",
		"*://sub.example.com/a/b",
		"*://*.a.b.example.com/x/y*",
		// A path ending in /* is not the bare host.
		"*://example.com/a/*",
		"*://example.com/?q=1",
		"*://example.com/#top",
		"*://intranet:8080/*",
	} {
		t.Run(canonical, func(t *testing.T) {
			pattern := blockedURLPattern(canonical)
			if pattern == canonical {
				t.Fatalf("blockedURLPattern(%q) returned the canonical form unchanged; the "+
					"API rejects that as input", canonical)
			}
			back, ok := canonicalizeBlockedURL(pattern)
			if !ok {
				t.Fatalf("blockedURLPattern(%q) = %q, which is not a valid pattern",
					canonical, pattern)
			}
			if back != canonical {
				t.Errorf("round trip: %q -> %q -> %q", canonical, pattern, back)
			}
		})
	}
}

func TestValidateBlockedURLPattern(t *testing.T) {
	for _, tc := range []struct {
		name, in string
		wantErr  bool
	}{
		{"host", "example.com", false},
		{"wildcard host", "*.example.com", false},
		{"host and path", "example.com/path*", false},
		{"empty", "", true},
		{"trailing slash", "example.com/", false},
		{"query string", "example.com?q=1", false},
		{"upper case", "Example.com", true},
		{"no letter", "123", true},
		{"IPv4", "192.168.0.1:8443", false},
		{"bad IPv4", "256.1.1.1", true},
		{"host too long", strings.Repeat("a", 72) + ".com", true},
		{"host at the limit", strings.Repeat("a", 71) + ".com", false},
		{"path too long", "example.com/" + strings.Repeat("a", 257), true},
		{"path at the limit", "example.com/" + strings.Repeat("a", 256), false},
		{"path characters", "example.com/a_b,c;d=e:f@g%h!i'j.k~l$m&n(o)p*q+r?s#t-u", false},
		// The API rejects a scheme with a 400.
		{"https scheme", "https://example.com", true},
		{"http scheme", "http://example.com/path", true},
		{"upper-case scheme", "HTTPS://example.com", true},
		{"URL in the query string", "example.com/go?to=https://example.org", false},
		{"canonical form", "*://example.com/*", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			problem := validateBlockedURLPattern(tc.in)
			if (problem != "") != tc.wantErr {
				t.Errorf("validateBlockedURLPattern(%q) = %q, wantErr = %v", tc.in, problem, tc.wantErr)
			}
		})
	}
}

func TestValidateBlockedURLPatternSuggestsTheFix(t *testing.T) {
	// The scheme message has to say what to write instead, or the practitioner
	// is left to work out the form the API accepts.
	problem := validateBlockedURLPattern("https://example.com/path")
	if problem == "" {
		t.Fatal("expected an error")
	}
	if !strings.Contains(problem, `"example.com/path"`) {
		t.Errorf("message does not suggest the corrected pattern: %q", problem)
	}
}

func TestValidateBlockedURLPatternSuggestsLowerCase(t *testing.T) {
	problem := validateBlockedURLPattern("Example.COM/Path")
	if !strings.Contains(problem, `"example.com"`) {
		t.Errorf("message does not suggest the lower-case host: %q", problem)
	}
}

func TestSameCanonicalSet(t *testing.T) {
	for _, tc := range []struct {
		name       string
		configured []string
		stored     []string
		want       bool
	}{
		{
			// The everyday case: what the practitioner wrote, and what the API
			// stored, are different strings for the same thing.
			name:       "different spellings of the same set",
			configured: []string{"example.com", "a.example.com/x*"},
			stored:     []string{"*://a.example.com/x*", "*://example.com/*"},
			want:       true,
		},
		{
			name:       "order does not matter",
			configured: []string{"a.example.com", "b.example.com"},
			stored:     []string{"*://b.example.com/*", "*://a.example.com/*"},
			want:       true,
		},
		{
			name:       "entry added outside terraform",
			configured: []string{"example.com"},
			stored:     []string{"*://example.com/*", "*://other.example.com/*"},
			want:       false,
		},
		{
			name:       "entry removed outside terraform",
			configured: []string{"example.com", "other.example.com"},
			stored:     []string{"*://example.com/*"},
			want:       false,
		},
		{
			name:       "different entry",
			configured: []string{"example.com"},
			stored:     []string{"*://elsewhere.example.com/*"},
			want:       false,
		},
		{
			name:       "trailing slash",
			configured: []string{"example.com/", "example.com?q=1"},
			stored:     []string{"*://example.com/*", "*://example.com/?q=1"},
			want:       true,
		},
		{name: "both empty", configured: nil, stored: nil, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := sameCanonicalSet(tc.configured, tc.stored); got != tc.want {
				t.Errorf("sameCanonicalSet(%v, %v) = %v, want %v",
					tc.configured, tc.stored, got, tc.want)
			}
		})
	}
}
