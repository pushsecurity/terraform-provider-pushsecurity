package controlspec

import (
	"slices"
	"strings"
	"testing"
)

func TestCheckText(t *testing.T) {
	title, _ := FileDownloadBlocking.Field("title")
	subtext, _ := FileDownloadBlocking.Field("subtext")
	operation, _ := ClipboardBlocking.Field("operation")
	capture, _ := ClipboardBlocking.Field("content_capture")

	for _, tc := range []struct {
		name  string
		field Field
		in    string
		// want is a substring of the summary, or "" for no problem.
		want string
	}{
		{"plain title", title, "Download blocked", ""},
		{"ampersand", title, "Terms & Conditions", "`&`"},
		{"less than", title, "Files < 10 MB only", "`<`"},
		{"greater than", title, "Files > 10 MB blocked", "`>`"},
		{"two characters", title, "Stop & think < twice", "`&` or `<`"},
		{"all three", title, "<b>Stop</b> & think", "`&`, `<` or `>`"},
		// What an adopted tenant holds once the API has escaped it.
		{"already escaped", title, "Terms &amp; Conditions", "`&`"},
		{"quotes are kept", title, `Don't "download" this`, ""},
		// subtext keeps its markdown as written.
		{"subtext ampersand", subtext, "Terms & Conditions apply", ""},
		{"subtext angle brackets", subtext, "See <https://example.com>", ""},
		// The banned word applies to every text field, subtext included.
		{"banned word", title, "Disable JavaScript", `"javascript"`},
		{"banned word in subtext", subtext, "javascript: links are not allowed", `"javascript"`},
		{"banned word in a URL", subtext, "[help](javascript:alert(1))", `"javascript"`},
		{"enum", operation, "COPY", ""},
		{"not text", capture, "a & b", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.field.CheckText(tc.in)
			if tc.want == "" {
				if p != nil {
					t.Errorf("CheckText(%q) = %+v, want nil", tc.in, p)
				}
				return
			}
			if p == nil {
				t.Fatalf("CheckText(%q) = nil, want a problem mentioning %s", tc.in, tc.want)
			}
			if p.Warning {
				t.Errorf("CheckText(%q) is a warning; the apply would fail, so it must be an error", tc.in)
			}
			if !strings.Contains(p.Summary, tc.want) {
				t.Errorf("summary = %q, want it to mention %s", p.Summary, tc.want)
			}
		})
	}
}

// TestCheckTextExplainsTheEscaping checks that the message says what the API
// does with the character, which is the part a practitioner cannot guess.
func TestCheckTextExplainsTheEscaping(t *testing.T) {
	title, _ := AppBanner.Field("title")
	p := title.CheckText("Terms & Conditions")
	if p == nil {
		t.Fatal("expected a problem")
	}
	for _, want := range []string{"HTML-escaped", "`&amp;`", "inconsistent result"} {
		if !strings.Contains(p.Detail, want) {
			t.Errorf("detail does not mention %s: %q", want, p.Detail)
		}
	}
	if strings.Contains(p.Detail, "adopted") {
		t.Errorf("detail mentions adopted text for text that is not escaped: %q", p.Detail)
	}

	p = title.CheckText("Terms &amp; Conditions")
	if p == nil || !strings.Contains(p.Detail, "adopted from the tenant") {
		t.Errorf("escaped text should be called out as such: %+v", p)
	}
}

// TestStoredEscapedFields pins which rule fields the API escapes: every text
// field but subtext, on every control and on custom detections.
func TestStoredEscapedFields(t *testing.T) {
	var escaped []string
	for _, s := range append(All, CustomDetectionRules) {
		for _, f := range s.Fields {
			if f.Type != TypeString {
				continue
			}
			if f.StoredEscaped() == (f.APIName == "subtext") {
				t.Errorf("%s.%s: StoredEscaped() = %v", s.TypeName, f.Name, f.StoredEscaped())
			}
			if f.StoredEscaped() {
				escaped = append(escaped, f.APIName)
			}
		}
	}
	for _, want := range []string{"title", "buttonText", "copyRedactedButtonText",
		"copyOriginalButtonText", "acknowledgeButtonText", "ignoreButtonText", "safeText",
		"terminateButtonText", "continueButtonText"} {
		if !slices.Contains(escaped, want) {
			t.Errorf("no spec has an escaped %s field", want)
		}
	}
}
