package pushapi

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"
)

func TestValidationErrorUnwrapsNestedMessage(t *testing.T) {
	// Verbatim body from a live tenant: a 400 whose `message` is itself a JSON
	// document of field errors keyed by rule index.
	const body = `{"status": "INVALID_INPUT_PROVIDED", "message": "{\"rules\": {\"0\": {\"_schema\": [\"title and subtext are required for mode BLOCK\"]}}}"}`

	c := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(body))
	}))

	_, err := c.GetControlConfig(context.Background(), "fileDownloadBlocking")
	if err == nil {
		t.Fatal("expected an error")
	}
	fields, ok := Validation(err)
	if !ok {
		t.Fatalf("Validation() did not recognise the error: %v", err)
	}
	if len(fields) != 1 {
		t.Fatalf("got %d field errors, want 1: %+v", len(fields), fields)
	}
	f := fields[0]
	if want := "title and subtext are required for mode BLOCK"; f.Message != want {
		t.Errorf("Message = %q, want %q", f.Message, want)
	}
	if f.RuleIndex() != 0 {
		t.Errorf("RuleIndex() = %d, want 0", f.RuleIndex())
	}
	// "_schema" is the server's marker for "the object as a whole" and should
	// not leak into the path shown to a practitioner.
	if want := "rules[0]"; f.AttributePath() != want {
		t.Errorf("AttributePath() = %q, want %q", f.AttributePath(), want)
	}
	// The flattened summary replaces the escaped-JSON blob in the diagnostic.
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error is not an *APIError: %v", err)
	}
	if want := "rules[0]: title and subtext are required for mode BLOCK"; apiErr.Message != want {
		t.Errorf("Message = %q, want %q", apiErr.Message, want)
	}
}

func TestValidationErrorNamedFieldAndMultipleRules(t *testing.T) {
	const body = `{"status": "INVALID_INPUT_PROVIDED", "message": "{\"rules\": {\"0\": {\"buttonText\": [\"not permitted for mode BLOCK\"]}, \"2\": {\"_schema\": [\"severity is required\"]}}, \"globals\": {\"ignoredHosts\": [\"invalid host\"]}}"}`

	c := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(body))
	}))

	_, err := c.GetControlConfig(context.Background(), "x")
	fields, ok := Validation(err)
	if !ok {
		t.Fatalf("not recognised as validation error: %v", err)
	}
	got := map[string]string{}
	idx := map[string]int{}
	for _, f := range fields {
		got[f.AttributePath()] = f.Message
		idx[f.AttributePath()] = f.RuleIndex()
	}
	want := map[string]string{
		"globals.ignoredHosts": "invalid host",
		"rules[0].buttonText":  "not permitted for mode BLOCK",
		"rules[2]":             "severity is required",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("field errors =\n %v\nwant\n %v", got, want)
	}
	if idx["rules[2]"] != 2 {
		t.Errorf("RuleIndex for rules[2] = %d", idx["rules[2]"])
	}
	if idx["globals.ignoredHosts"] != -1 {
		t.Errorf("RuleIndex for a non-rule error = %d, want -1", idx["globals.ignoredHosts"])
	}
}

func TestRefusalsClassified(t *testing.T) {
	// The responses the API gives for a refused request, header and body as
	// it sends them.
	for _, tc := range []struct {
		name      string
		code      int
		errorType string
		body      string
		want      Refusal
	}{
		{"no key or a malformed one", http.StatusUnauthorized, "UnauthorizedException",
			`{"message":"Unauthorized"}`, KeyRejected},
		{"a key the API does not accept", http.StatusForbidden, "AccessDeniedException",
			`{"Message":"User is not authorized to access this resource with an explicit deny in an identity-based policy"}`,
			KeyRefused},
		{"an endpoint the API does not serve", http.StatusForbidden, "MissingAuthenticationTokenException",
			`{"message":"Missing Authentication Token"}`, NoSuchEndpoint},
		{"a kind given with detail", http.StatusForbidden, "AccessDeniedException:http://example.com/",
			`{"Message":"denied"}`, KeyRefused},
		{"a 403 that names no kind", http.StatusForbidden, "",
			`{"message":"Forbidden"}`, Forbidden},
		{"a 401 that names no kind", http.StatusUnauthorized, "",
			`{"message":"Unauthorized"}`, KeyRejected},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			c := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if tc.errorType != "" {
					w.Header().Set("x-amzn-errortype", tc.errorType)
				}
				w.WriteHeader(tc.code)
				_, _ = w.Write([]byte(tc.body))
			}))
			_, err := c.GetControlConfig(context.Background(), "x")
			if got := Refused(err); got != tc.want {
				t.Errorf("Refused() = %d, want %d: %v", got, tc.want, err)
			}
			if !Unauthorized(err) {
				t.Errorf("Unauthorized() = false for HTTP %d: %v", tc.code, err)
			}
			// Neither status can succeed on a second attempt.
			if n := calls.Load(); n != 1 {
				t.Errorf("the request was made %d times, want once", n)
			}
			// A 403 can mean "unknown path", so it must not be mistaken for a
			// missing resource.
			if NotFound(err) {
				t.Errorf("NotFound() = true for HTTP %d", tc.code)
			}
			// The body's message survives, whichever case its key is in.
			var apiErr *APIError
			if !errors.As(err, &apiErr) || apiErr.Message == "" {
				t.Errorf("the API's message was lost: %v", err)
			}
		})
	}
}

func TestRefusedIgnoresOtherErrors(t *testing.T) {
	for _, err := range []error{
		nil,
		errors.New("connection reset"),
		&APIError{StatusCode: http.StatusNotFound},
		&APIError{StatusCode: http.StatusBadRequest, ErrorType: "AccessDeniedException"},
	} {
		if got := Refused(err); got != NotRefused {
			t.Errorf("Refused(%v) = %d, want NotRefused", err, got)
		}
	}
}

func TestNotFoundOnlyFor404(t *testing.T) {
	c := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"Not Found"}`))
	}))
	_, err := c.GetCustomDetection(context.Background(), "CUSTOM_NOPE")
	if !NotFound(err) {
		t.Errorf("NotFound() = false: %v", err)
	}
}

func TestNonJSONErrorBodyKeptAsMessage(t *testing.T) {
	c := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("<html>502 Bad Gateway</html>"))
	}))
	_, err := c.GetControlConfig(context.Background(), "x")
	if err == nil {
		t.Fatal("expected an error")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error is not an *APIError: %v", err)
	}
	if apiErr.Message != "<html>502 Bad Gateway</html>" {
		t.Errorf("Message = %q", apiErr.Message)
	}
}

func TestRetriesRetryableStatuses(t *testing.T) {
	var calls int32
	c := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) < 3 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"globals":{},"rules":[]}`))
	}))
	if _, err := c.GetControlConfig(context.Background(), "x"); err != nil {
		t.Fatalf("expected success after retries: %v", err)
	}
	if calls != 3 {
		t.Errorf("calls = %d, want 3", calls)
	}
}

func TestDoesNotRetryValidationErrors(t *testing.T) {
	var calls int32
	c := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"status":"INVALID_INPUT_PROVIDED","message":"nope"}`))
	}))
	if _, err := c.GetControlConfig(context.Background(), "x"); err == nil {
		t.Fatal("expected an error")
	}
	if calls != 1 {
		t.Errorf("calls = %d, want 1: a 400 is not retryable", calls)
	}
}

func TestDoesNotRetryPOST(t *testing.T) {
	// A POST is not idempotent, so it must not be retried on a failure that
	// may have come after the server acted: the first attempt to create this
	// custom detection may have created it.
	t.Run("error response", func(t *testing.T) {
		var calls int32
		c := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&calls, 1)
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		if _, err := c.CreateCustomDetection(context.Background(), "n", "logic", []Rule{{Name: "r", Mode: "OFF"}}); err == nil {
			t.Fatal("expected an error")
		}
		if calls != 1 {
			t.Errorf("calls = %d, want 1: POST must not be retried", calls)
		}
	})

	t.Run("client timeout", func(t *testing.T) {
		// No response at all: the client gave up waiting. The server may
		// still be working on the create, so this is the case where a resend
		// does the most damage.
		c, seen := timeoutClient(t)
		_, err := c.CreateCustomDetection(context.Background(), "n", "logic", []Rule{{Name: "r", Mode: "OFF"}})
		if err == nil {
			t.Fatal("expected an error")
		}
		var apiErr *APIError
		if errors.As(err, &apiErr) {
			t.Fatalf("a timeout must surface as a transport error, got %v", err)
		}
		if calls := seen(); calls != 1 {
			t.Errorf("calls = %d, want 1: a POST that timed out must not be resent", calls)
		}
	})
}

func TestRetriesTransportErrorsForIdempotentRequests(t *testing.T) {
	// The other side of the rule: a GET that timed out is harmless to repeat,
	// so the retry budget applies to it.
	c, seen := timeoutClient(t)
	if _, err := c.GetControlConfig(context.Background(), "x"); err == nil {
		t.Fatal("expected an error")
	}
	// maxRetries is 2 here: the first attempt plus two retries.
	if calls := seen(); calls != 3 {
		t.Errorf("calls = %d, want 3", calls)
	}
}

// timeoutClient returns a client whose HTTP timeout is shorter than its
// server's handler, which holds every request open until the client gives up,
// and a function that reports how many requests the client sent.
//
// The count is taken on the client side. Counting at the server misses an
// attempt whose timeout runs out before the server's handler starts, which a
// loaded machine makes likely with a timeout this short.
func timeoutClient(t *testing.T) (*Client, func() int32) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The server only notices the client hanging up once the request body
		// has been read, so read it before waiting.
		_, _ = io.Copy(io.Discard, r.Body)
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}))
	t.Cleanup(srv.Close)
	transport := &countingTransport{next: srv.Client().Transport}
	c, err := New(srv.URL, "psak_test", WithHTTPClient(&http.Client{Timeout: 50 * time.Millisecond, Transport: transport}), WithMaxRetries(2))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c, func() int32 { return atomic.LoadInt32(&transport.calls) }
}

// countingTransport counts the requests a client sends, whether or not any of
// them reaches the server.
type countingTransport struct {
	next  http.RoundTripper
	calls int32
}

func (c *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	atomic.AddInt32(&c.calls, 1)
	return c.next.RoundTrip(r)
}

func TestContextCancellationIsNotRetried(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	c, err := New(srv.URL, "k", WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.GetControlConfig(ctx, "x"); err == nil {
		t.Fatal("expected an error")
	}
	if calls != 0 {
		t.Errorf("calls = %d, want 0", calls)
	}
}

func TestConflictIsRetryable(t *testing.T) {
	// The API serialises configuration writes per tenant and answers concurrent
	// ones with 409. Terraform applies resources in parallel, so this has to be
	// retried or a configuration covering several controls cannot be applied at
	// all.
	var calls int32
	c := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if atomic.AddInt32(&calls, 1) == 1 {
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"status": "CONCURRENT_MODIFICATION", "message": "Conflict occurred while updating the resource."}`))
			return
		}
		_, _ = w.Write([]byte(`{"globals":{},"rules":[]}`))
	}))

	if _, err := c.GetControlConfig(context.Background(), "x"); err != nil {
		t.Fatalf("expected the retry to succeed: %v", err)
	}
	if calls != 2 {
		t.Errorf("calls = %d, want 2", calls)
	}
}

func TestConflictClassified(t *testing.T) {
	c := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"status": "CONCURRENT_MODIFICATION", "message": "Conflict occurred while updating the resource."}`))
	}))
	// maxRetries exhausted, so the error surfaces.
	_, err := c.GetControlConfig(context.Background(), "x")
	if !Conflict(err) {
		t.Errorf("Conflict() = false: %v", err)
	}
	if Unauthorized(err) || NotFound(err) {
		t.Error("a 409 must not be classified as auth or not-found")
	}
}

func TestConflictNotRetriedForPOST(t *testing.T) {
	// A POST is not idempotent, and a conflict on creating a custom detection
	// might mean the detection was created.
	var calls int32
	c := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusConflict)
	}))
	if _, err := c.CreateCustomDetection(context.Background(), "n", "l", []Rule{{Name: "r", Mode: "OFF"}}); err == nil {
		t.Fatal("expected an error")
	}
	if calls != 1 {
		t.Errorf("calls = %d, want 1", calls)
	}
}

// TestRetriesPOSTTheServerDidNotAct: a 429 and a 409 CONCURRENT_MODIFICATION
// both mean the write was not made, so even a POST is safe to resend. Without
// this, one throttled POST midway through rewriting the blocked URL list
// leaves the list partly written.
func TestRetriesPOSTTheServerDidNotAct(t *testing.T) {
	for _, tc := range []struct {
		name string
		code int
		body string
	}{
		{"throttled", http.StatusTooManyRequests, `{"message": "Too Many Requests"}`},
		{"concurrent modification", http.StatusConflict,
			`{"status": "CONCURRENT_MODIFICATION", "message": "Conflict occurred while updating the resource."}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls int32
			c := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if atomic.AddInt32(&calls, 1) == 1 {
					w.WriteHeader(tc.code)
					_, _ = w.Write([]byte(tc.body))
					return
				}
				_, _ = w.Write([]byte(`{"result": "*://example.com/*"}`))
			}))
			if _, err := c.AddBlockedURL(context.Background(), "*://example.com/*"); err != nil {
				t.Fatalf("expected the retry to succeed: %v", err)
			}
			if calls != 2 {
				t.Errorf("calls = %d, want 2", calls)
			}
		})
	}
}

func TestTimedOutClassified(t *testing.T) {
	// TimedOut separates a create that may still land from one that certainly
	// did not, so it must hold for exactly the two ways a request runs out of
	// time, and for nothing else that can go wrong with a POST.
	create := func(c *Client) error {
		_, err := c.CreateCustomDetection(context.Background(), "n", "l", []Rule{{Name: "r", Mode: "OFF"}})
		return err
	}
	status := func(code int) *Client {
		return testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
			_, _ = w.Write([]byte(`{"message": "Request timed out"}`))
		}))
	}

	if err := create(status(http.StatusGatewayTimeout)); !TimedOut(err) {
		t.Errorf("a 504 is not classified as timed out: %v", err)
	}
	timeout, _ := timeoutClient(t)
	if err := create(timeout); !TimedOut(err) {
		t.Errorf("the client giving up is not classified as timed out: %v", err)
	}

	for _, code := range []int{http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusConflict} {
		if err := create(status(code)); TimedOut(err) {
			t.Errorf("HTTP %d is classified as timed out: %v", code, err)
		}
	}

	// A refused connection never reached the server, so nothing can land.
	srv := httptest.NewServer(http.NotFoundHandler())
	refused, err := New(srv.URL, "psak_test", WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv.Close()
	if err := create(refused); err == nil || TimedOut(err) {
		t.Errorf("a refused connection is classified as timed out: %v", err)
	}
}

func TestJSONErrorBodyWithoutMessageKeptAsMessage(t *testing.T) {
	// A JSON body with no message must not reduce the error to a bare status
	// code: the body is all there is to explain the failure.
	for _, body := range []string{`{}`, `{"error":"upstream unavailable"}`, `{"status":"EXAMPLE_STATUS"}`} {
		t.Run(body, func(t *testing.T) {
			e := newAPIError(http.MethodGet, "/v1/x", http.StatusInternalServerError, []byte(body), nil)
			if e.Message != body {
				t.Errorf("Message = %q, want the body %q", e.Message, body)
			}
			if !strings.HasSuffix(e.Error(), ": "+body) {
				t.Errorf("Error() = %q, want it to end with the body", e.Error())
			}
		})
	}

	// A status alongside the missing message is still kept.
	e := newAPIError(http.MethodGet, "/v1/x", http.StatusInternalServerError, []byte(`{"status":"EXAMPLE_STATUS"}`), nil)
	if e.Status != "EXAMPLE_STATUS" {
		t.Errorf("Status = %q", e.Status)
	}
}

func TestTruncateKeepsMultiByteTextValid(t *testing.T) {
	// Two bytes per rune, so a cut at an odd byte offset would land inside one.
	s := strings.Repeat("é", 300)
	got := truncate(s, 511)
	if !utf8.ValidString(got) {
		t.Fatalf("truncate produced invalid UTF-8: %q", got)
	}
	if want := strings.Repeat("é", 255) + "…"; got != want {
		t.Errorf("truncate = %q (%d bytes), want 255 runes and an ellipsis", got, len(got))
	}
	if got := truncate("short", 512); got != "short" {
		t.Errorf("truncate left a short string as %q", got)
	}

	// The same holds end to end, for a non-JSON body over the cap.
	e := newAPIError(http.MethodGet, "/v1/x", http.StatusBadGateway, []byte(strings.Repeat("€", 400)), nil)
	if !utf8.ValidString(e.Message) || !strings.HasSuffix(e.Message, "…") {
		t.Errorf("Message = %q, want valid UTF-8 ending in an ellipsis", e.Message)
	}
}
