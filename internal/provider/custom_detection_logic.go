package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

// The limits the API puts on a custom detection's logic. It measures the size
// in bytes of UTF-8 and counts documents the way a YAML multi-document load
// does, refusing either excess with a 400.
const (
	detectionLogicByteLimit     = 10 * 1024
	detectionLogicDocumentLimit = 100
)

// detectionLogicValidator refuses detection logic over the API's limits, so
// that it fails the plan rather than the apply.
type detectionLogicValidator struct{}

func (detectionLogicValidator) Description(context.Context) string {
	return fmt.Sprintf("must be at most %d bytes and hold at most %d YAML documents",
		detectionLogicByteLimit, detectionLogicDocumentLimit)
}

func (v detectionLogicValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (detectionLogicValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	logic := req.ConfigValue.ValueString()

	// The API checks the size first and stops there, so this does too: a
	// document count from oversized logic would only be noise.
	if size := len(logic); size > detectionLogicByteLimit {
		resp.Diagnostics.AddAttributeError(req.Path, "Detection logic is too large",
			fmt.Sprintf("The detection logic is %d bytes; the Push API accepts at most %d "+
				"(10 KiB, counted as UTF-8).", size, detectionLogicByteLimit))
		return
	}
	if n := yamlDocumentCount(logic); n > detectionLogicDocumentLimit {
		resp.Diagnostics.AddAttributeError(req.Path, "Detection logic holds too many documents",
			fmt.Sprintf("The detection logic holds %d YAML documents; the Push API accepts at "+
				"most %d. Move some of them into another custom detection.",
				n, detectionLogicDocumentLimit))
	}
}

// yamlDocumentCount counts the documents in a YAML stream without parsing it:
// one for each document start marker (--- at the start of a line, followed by
// whitespace or the end of the line), plus one for a document that begins
// without a marker.
//
// For any stream a YAML parser loads, this is the parser's count. A marker
// cannot be inside a scalar or a collection: a quoted scalar or a flow
// collection spanning one fails to parse, a block scalar's lines are indented,
// and a plain scalar or a block collection ends there. Comments and blank lines
// before the first marker make no document of their own, and a directive (a
// line starting with %) means the first document starts with a marker. Logic
// that does not parse is refused by the API whatever this says.
func yamlDocumentCount(stream string) int {
	stream = strings.TrimPrefix(stream, "\uFEFF")

	count := 0
	sawContent := false
	for _, line := range yamlLines(stream) {
		trimmed := strings.TrimLeft(line, " \t")
		switch {
		case isDocumentStart(line):
			count++
			sawContent = true
		case sawContent, trimmed == "", strings.HasPrefix(trimmed, "#"):
		case strings.HasPrefix(line, "%"):
			// A directive: the document it applies to starts at the marker
			// after it, which is counted when it comes.
			sawContent = true
		default:
			// Content before any marker: the first document is implicit.
			count++
			sawContent = true
		}
	}
	return count
}

// isDocumentStart reports whether a line opens with a document start marker.
func isDocumentStart(line string) bool {
	rest, ok := strings.CutPrefix(line, "---")
	return ok && (rest == "" || rest[0] == ' ' || rest[0] == '\t')
}

// yamlLines splits a stream at every line break YAML recognises: CR LF, CR and
// LF, and the Unicode breaks NEL, LS and PS.
func yamlLines(stream string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(stream); {
		width := 0
		switch {
		case stream[i] == '\r' && strings.HasPrefix(stream[i:], "\r\n"):
			width = 2
		case stream[i] == '\r', stream[i] == '\n':
			width = 1
		case strings.HasPrefix(stream[i:], "\u0085"):
			width = len("\u0085")
		case strings.HasPrefix(stream[i:], "\u2028"), strings.HasPrefix(stream[i:], "\u2029"):
			width = len("\u2028")
		}
		if width == 0 {
			i++
			continue
		}
		lines = append(lines, stream[start:i])
		i += width
		start = i
	}
	return append(lines, stream[start:])
}
