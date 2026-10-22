package pushapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// APIError is a non-2xx response from the API.
type APIError struct {
	Method     string
	Path       string
	StatusCode int

	// Status is the machine-readable code the API sends on validation failures,
	// e.g. "INVALID_INPUT_PROVIDED". Empty when the response carries none, as on
	// authentication failures.
	Status string

	// Message is the human-readable summary. For validation failures the API
	// nests a second JSON document inside this field; when that parses,
	// FieldErrors is populated and Message holds the flattened summary.
	Message string

	// FieldErrors carries per-field validation failures, innermost first, e.g.
	// {Path: []string{"rules", "0"}, Field: "_schema", Message: "..."}.
	FieldErrors []FieldError

	// Body is the raw response body, kept for diagnostics when nothing parses.
	Body string

	// ErrorType is the kind of refusal the API names in the x-amzn-errortype
	// response header, such as "AccessDeniedException", with any detail after
	// a colon removed. Empty when the response carries none, as an error from
	// an endpoint itself does not. See Refused.
	ErrorType string
}

// FieldError is a single validation failure against one input field.
type FieldError struct {
	// Path locates the field, e.g. ["rules", "0"] for the first rule. Numeric
	// segments are list indices.
	Path []string
	// Field is the failing key within Path. The API uses "_schema" for errors
	// that belong to the object as a whole rather than one of its keys.
	Field   string
	Message string
}

// RuleIndex returns the index of the rule this error belongs to, or -1 when the
// error is not scoped to a single rule. Used to attach diagnostics to the right
// element of the `rules` list.
func (f FieldError) RuleIndex() int {
	for i, seg := range f.Path {
		if seg != "rules" || i+1 >= len(f.Path) {
			continue
		}
		if n, err := strconv.Atoi(f.Path[i+1]); err == nil {
			return n
		}
	}
	return -1
}

// AttributePath renders the error location the way a practitioner sees it in
// their configuration, e.g. `rules[0]` or `globals.ignoredHosts`.
func (f FieldError) AttributePath() string {
	var b strings.Builder
	for _, seg := range f.Path {
		if _, err := strconv.Atoi(seg); err == nil {
			b.WriteString("[" + seg + "]")
			continue
		}
		if b.Len() > 0 {
			b.WriteString(".")
		}
		b.WriteString(seg)
	}
	// "_schema" is the API's marker for "this object", so it is not part of the
	// path a user would recognise.
	if f.Field != "" && f.Field != "_schema" {
		if b.Len() > 0 {
			b.WriteString(".")
		}
		b.WriteString(f.Field)
	}
	return b.String()
}

// Error renders the request, the status and the message on one line.
func (e *APIError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s: HTTP %d", e.Method, e.Path, e.StatusCode)
	if e.Status != "" {
		fmt.Fprintf(&b, " (%s)", e.Status)
	}
	if e.Message != "" {
		fmt.Fprintf(&b, ": %s", e.Message)
	}
	return b.String()
}

// Retryable reports whether reissuing the identical request could succeed.
//
// Every other write in this client is idempotent (a whole-document PUT, or a
// PATCH of named fields), so retrying a 5xx or a conflict cannot duplicate
// anything. A POST is retried only when the server certainly did not act on
// it: a 429, which turns the request away before it is handled, and a 409
// CONCURRENT_MODIFICATION, which rejects the write whole. Anything else may
// have taken effect. POST /controls/customDetections, for one, creates a
// detection whose identifier is derived from its name, so a resend of a
// request the server had in fact completed is answered with a conflict. The
// transport-error branch of Client.do never resends a POST, for the same
// reason.
func (e *APIError) Retryable() bool {
	if e.Method == http.MethodPost {
		return e.StatusCode == http.StatusTooManyRequests ||
			(e.StatusCode == http.StatusConflict && e.Status == statusConcurrentModification)
	}
	return isRetryableStatus(e.StatusCode)
}

// statusConcurrentModification is the status of a 409 that rejected a write
// because another write to the same tenant was in flight.
const statusConcurrentModification = "CONCURRENT_MODIFICATION"

func isRetryableStatus(code int) bool {
	switch code {
	case http.StatusTooManyRequests,
		// The API serialises configuration writes per tenant and rejects
		// concurrent ones with 409 CONCURRENT_MODIFICATION. Terraform applies
		// independent resources in parallel — ten at a time by default — so a
		// configuration covering several controls hits this routinely. It is
		// transient by definition: the conflicting write has finished by the
		// time the retry lands.
		http.StatusConflict,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	}
	return false
}

// Conflict reports whether err is a 409, i.e. another write to the same tenant
// was in flight.
func Conflict(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusConflict
}

// NotFound reports whether err is a 404.
//
// The control configuration endpoints are singletons that always exist, so a
// 404 comes from an endpoint that names one item, such as a custom detection or
// an employee. A 403 is deliberately not treated as not-found: the API also
// answers a path it does not route with 403.
func NotFound(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound
}

// Refusal is why the API turned a request away before it reached an endpoint.
type Refusal int

const (
	// NotRefused: the error is not a refusal, or not from the API at all.
	NotRefused Refusal = iota

	// KeyRejected: a 401. The request carried no API key, or a value that is
	// not shaped like a Push API key, so the key was never looked up.
	KeyRejected

	// KeyRefused: a 403 naming AccessDeniedException. The key is well formed
	// but not accepted for this request: the API at this base URL does not
	// know it, it is disabled, or it is read-only and the request writes.
	KeyRefused

	// NoSuchEndpoint: a 403 naming MissingAuthenticationTokenException. The
	// API at this base URL serves no such path or method, and answers so
	// before it looks at the key, whatever the key.
	NoSuchEndpoint

	// Forbidden: any other 403, whose cause the response does not name.
	Forbidden
)

// Refused reports whether, and why, the API refused the request err came from.
//
// The status code alone cannot tell a refused key from an endpoint the API
// does not serve, as both are 403s. The kind the API names in the
// x-amzn-errortype header can, so a diagnostic can point at the key, or at
// the base URL and provider version, rather than guessing.
func Refused(err error) Refusal {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return NotRefused
	}
	switch apiErr.StatusCode {
	case http.StatusUnauthorized:
		return KeyRejected
	case http.StatusForbidden:
		switch apiErr.ErrorType {
		case "AccessDeniedException":
			return KeyRefused
		case "MissingAuthenticationTokenException":
			return NoSuchEndpoint
		}
		return Forbidden
	}
	return NotRefused
}

// Unauthorized reports whether err is a refusal of any kind: a 401 or a 403.
func Unauthorized(err error) bool {
	return Refused(err) != NotRefused
}

// TimedOut reports whether err means the request ran out of time rather than
// failed: a 504 from the API, or the client giving up waiting for an answer.
// Either way the server may still finish the request afterwards, so for a POST,
// which is not retried after either, nothing yet says whether it took effect.
func TimedOut(err error) bool {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode == http.StatusGatewayTimeout
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// Validation returns the field errors from a 400, and whether err was one.
func Validation(err error) ([]FieldError, bool) {
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusBadRequest {
		return nil, false
	}
	return apiErr.FieldErrors, true
}

// errorEnvelope is the outer error body: {"status": "...", "message": "..."}.
type errorEnvelope struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

func newAPIError(method, path string, code int, body []byte, header http.Header) *APIError {
	e := &APIError{Method: method, Path: path, StatusCode: code, Body: string(body)}
	if kind, _, _ := strings.Cut(header.Get("x-amzn-errortype"), ":"); kind != "" {
		e.ErrorType = strings.TrimSpace(kind)
	}

	var env errorEnvelope
	if err := json.Unmarshal(body, &env); err != nil || env.Message == "" {
		// Not JSON at all, or JSON without a message, such as {} or a body of
		// some other shape. Keep the body as the message so the diagnostic says
		// something, but cap it.
		e.Status = env.Status
		e.Message = truncate(strings.TrimSpace(string(body)), 512)
		return e
	}
	e.Status, e.Message = env.Status, env.Message

	// On validation failures the API double-encodes: `message` is itself a JSON
	// document of field errors. Unwrap it so callers can map errors onto
	// configuration attributes instead of showing a wall of escaped JSON.
	var nested any
	if err := json.Unmarshal([]byte(env.Message), &nested); err == nil {
		if fields := flattenFieldErrors(nil, nested); len(fields) > 0 {
			e.FieldErrors = fields
			e.Message = summarise(fields)
		}
	}
	return e
}

// flattenFieldErrors walks the server's nested validation document into a flat
// list. The shape is objects keyed by field name or list index, bottoming out in
// a list of message strings:
//
//	{"rules": {"0": {"_schema": ["title and subtext are required for mode BLOCK"]}}}
func flattenFieldErrors(path []string, node any) []FieldError {
	switch v := node.(type) {
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		var out []FieldError
		for _, k := range keys {
			switch child := v[k].(type) {
			case []any:
				for _, m := range child {
					if s, ok := m.(string); ok {
						out = append(out, FieldError{Path: path, Field: k, Message: s})
					}
				}
			case string:
				out = append(out, FieldError{Path: path, Field: k, Message: child})
			default:
				out = append(out, flattenFieldErrors(append(append([]string{}, path...), k), child)...)
			}
		}
		return out
	case []any:
		var out []FieldError
		for _, m := range v {
			if s, ok := m.(string); ok {
				out = append(out, FieldError{Path: path, Message: s})
			}
		}
		return out
	default:
		return nil
	}
}

func summarise(fields []FieldError) string {
	parts := make([]string, 0, len(fields))
	for _, f := range fields {
		if p := f.AttributePath(); p != "" {
			parts = append(parts, p+": "+f.Message)
			continue
		}
		parts = append(parts, f.Message)
	}
	return strings.Join(parts, "; ")
}

// truncate caps s at n bytes, cutting at a rune boundary so that a multi-byte
// character is never split into invalid UTF-8.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}
