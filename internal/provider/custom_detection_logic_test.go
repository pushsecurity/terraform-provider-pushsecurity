package provider

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// TestYAMLDocumentCount pins the count to what a YAML multi-document load
// returns for each stream, which is what the API compares with its limit.
func TestYAMLDocumentCount(t *testing.T) {
	for _, tc := range []struct {
		name, in string
		want     int
	}{
		{"empty", "", 0},
		{"blank lines and comments only", "\n  \n# a comment\n", 0},
		{"one implicit document", "input: web_request\n", 1},
		{"one explicit document", "---\ninput: web_request\n", 1},
		{"comment before the marker", "# leading\n---\ninput: web_request\n", 1},
		{"implicit then explicit", "a: 1\n---\nb: 2\n", 2},
		{"explicit twice", "---\na: 1\n---\nb: 2\n", 2},
		// A marker with nothing after it is a document of its own: an
		// empty one, which a load returns as null.
		{"trailing marker", "a: 1\n---\n", 2},
		{"markers only", "---\n---\n", 2},
		{"marker without a final line break", "a: 1\n---", 2},
		{"content on the marker line", "--- # first\na: 1\n--- !!map\nb: 2\n", 2},
		{"document end then start", "a: 1\n...\n---\nb: 2\n", 2},
		{"directive", "%YAML 1.1\n---\na: 1\n", 1},
		{"byte order mark", "\uFEFF---\na: 1\n---\nb: 2\n", 2},
		{"CR LF", "a: 1\r\n---\r\nb: 2\r\n", 2},
		{"CR alone", "a: 1\r---\rb: 2\r", 2},
		{"Unicode line breaks", "a: 1\u0085---\u2028b: 2\u2029---\nc: 3", 3},
		// None of these is a marker, so each is part of the one document.
		{"indented", "a: |\n  ---\n  text\n", 1},
		{"four dashes", "----\n", 1},
		{"dashes then text", "---a\n", 1},
		{"in a comment", "a: 1\n# ---\n", 1},
		{"document end alone", "a: 1\n...\n", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := yamlDocumentCount(tc.in); got != tc.want {
				t.Errorf("yamlDocumentCount(%q) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

// TestDetectionLogicValidator checks each limit at its boundary: the most the
// API accepts passes, one more fails on the attribute.
func TestDetectionLogicValidator(t *testing.T) {
	doc := "input: web_request\n"
	documents := func(n int) string {
		return strings.Repeat("---\n"+doc, n)
	}
	// Multi-byte characters, so that a size check counting characters
	// rather than bytes would pass logic the API refuses.
	sized := func(n int) string {
		const comment = "# ünïcödé\n"
		s := strings.Repeat(comment, n/len(comment))
		return s + strings.Repeat("#", n-len(s))
	}

	for _, tc := range []struct {
		name, in, wantSummary string
	}{
		{"at the size limit", sized(detectionLogicByteLimit), ""},
		{"over the size limit", sized(detectionLogicByteLimit + 1), "Detection logic is too large"},
		{"at the document limit", documents(detectionLogicDocumentLimit), ""},
		{"over the document limit", documents(detectionLogicDocumentLimit + 1),
			"Detection logic holds too many documents"},
		// The API reports only the size, so this does too.
		{"over both", documents(detectionLogicByteLimit/len("---\n"+doc) + 1),
			"Detection logic is too large"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			at := path.Root("detection_logic")
			resp := &validator.StringResponse{}
			detectionLogicValidator{}.ValidateString(context.Background(), validator.StringRequest{
				Path: at, ConfigValue: types.StringValue(tc.in),
			}, resp)

			if tc.wantSummary == "" {
				if len(resp.Diagnostics) != 0 {
					t.Fatalf("diagnostics = %v, want none", resp.Diagnostics)
				}
				return
			}
			if len(resp.Diagnostics) != 1 {
				t.Fatalf("diagnostics = %v, want one", resp.Diagnostics)
			}
			d := resp.Diagnostics[0]
			if d.Severity() != diag.SeverityError || d.Summary() != tc.wantSummary {
				t.Errorf("diagnostic = %v %q, want error %q", d.Severity(), d.Summary(), tc.wantSummary)
			}
			if wp, ok := d.(diag.DiagnosticWithPath); !ok || !wp.Path().Equal(at) {
				t.Errorf("diagnostic is not on detection_logic: %v", d)
			}
		})
	}

	for _, v := range []types.String{types.StringNull(), types.StringUnknown()} {
		resp := &validator.StringResponse{}
		detectionLogicValidator{}.ValidateString(context.Background(), validator.StringRequest{
			Path: path.Root("detection_logic"), ConfigValue: v,
		}, resp)
		if len(resp.Diagnostics) != 0 {
			t.Errorf("%v: diagnostics = %v, want none", v, resp.Diagnostics)
		}
	}
}
