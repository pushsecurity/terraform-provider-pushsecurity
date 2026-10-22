package pushapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testClient(t *testing.T, h http.Handler) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, "psak_test", WithHTTPClient(srv.Client()), WithMaxRetries(2))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// httptest serves plain HTTP on 127.0.0.1, which New permits for localhost.
	c.sleep = noWait
	return c
}

// noWait stands in for the backoff wait, so that retry tests do not sit
// through real delays. It still gives up on a cancelled context, as the real
// one does.
func noWait(ctx context.Context, _ time.Duration) error {
	return ctx.Err()
}

func TestNewRejectsBadInput(t *testing.T) {
	if _, err := New("https://api.example.com", ""); err == nil {
		t.Error("expected error for empty api key")
	}
	if _, err := New("http://api.example.com", "k"); err == nil {
		t.Error("expected error for non-https base url")
	}
	// Plain http is the one exception made for a local server; no other
	// scheme is.
	for _, u := range []string{"ftp://localhost", "file://127.0.0.1/x", "ws://localhost:8080"} {
		if _, err := New(u, "k"); err == nil {
			t.Errorf("expected error for base url %q", u)
		}
	}
	for _, u := range []string{"http://localhost:8080", "http://127.0.0.1:1234"} {
		if _, err := New(u, "k"); err != nil {
			t.Errorf("New(%q): %v", u, err)
		}
	}
	c, err := New("", "k")
	if err != nil {
		t.Fatalf("New with empty base url: %v", err)
	}
	if c.BaseURL() != DefaultBaseURL {
		t.Errorf("BaseURL = %q, want %q", c.BaseURL(), DefaultBaseURL)
	}
	c, err = New("https://api.example.com/", "k")
	if err != nil {
		t.Fatalf("New with trailing slash: %v", err)
	}
	if c.BaseURL() != "https://api.example.com" {
		t.Errorf("trailing slash not trimmed: %q", c.BaseURL())
	}
}

func TestGetControlConfigSendsAuthAndParses(t *testing.T) {
	var gotKey, gotPath, gotUA string
	c := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey, gotPath, gotUA = r.Header.Get("x-api-key"), r.URL.Path, r.Header.Get("User-Agent")
		w.Header().Set("Content-Type", "application/json")
		// Shape taken verbatim from a live tenant.
		_, _ = w.Write([]byte(`{"globals":{"ignoredHosts":[]},"rules":[
			{"id":"bfb05111","name":"Monitor: All employees","enabled":true,"criteria":{},"mode":"MONITOR"}]}`))
	}))

	cfg, err := c.GetControlConfig(context.Background(), "phishingToolDetection")
	if err != nil {
		t.Fatalf("GetControlConfig: %v", err)
	}
	if gotKey != "psak_test" {
		t.Errorf("x-api-key = %q", gotKey)
	}
	if want := "/v1/controls/phishingToolDetection/configuration"; gotPath != want {
		t.Errorf("path = %q, want %q", gotPath, want)
	}
	if gotUA != "terraform-provider-pushsecurity" {
		t.Errorf("User-Agent = %q", gotUA)
	}
	if len(cfg.Rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(cfg.Rules))
	}
	r := cfg.Rules[0]
	if r.ID != "bfb05111" || r.Name != "Monitor: All employees" || !r.Enabled || r.Mode != "MONITOR" {
		t.Errorf("rule mis-parsed: %+v", r)
	}
	if len(r.Criteria) != 0 {
		t.Errorf("criteria = %v, want empty", r.Criteria)
	}
}

func TestRuleRoundTripPreservesUnknownFields(t *testing.T) {
	// A rule the client has no named field for must survive a decode/encode
	// cycle, so that adding a control never requires a client change.
	in := []byte(`{"id":"abc","name":"n","enabled":true,"mode":"BLOCK",
		"title":"t","subtext":"s","operation":"COPY","contentCapture":true,
		"criteria":{"employeeGroups":{"matches":["Finance"],"action":"EXCLUDE"},
		            "urlPatterns":{"matches":["*://x.example.com/"]}}}`)

	var r Rule
	if err := json.Unmarshal(in, &r); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if r.Fields["operation"] != "COPY" || r.Fields["contentCapture"] != true {
		t.Errorf("extra fields lost: %v", r.Fields)
	}
	if got := r.Criteria["employeeGroups"]; got.Action != "EXCLUDE" || !reflect.DeepEqual(got.Matches, []string{"Finance"}) {
		t.Errorf("condition mis-parsed: %+v", got)
	}

	out, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var a, b map[string]any
	_ = json.Unmarshal(in, &a)
	if err := json.Unmarshal(out, &b); err != nil {
		t.Fatalf("re-Unmarshal: %v", err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Errorf("round trip changed the document:\n in: %v\nout: %v", a, b)
	}
}

func TestRuleMarshalOmitsEmptyIDAndNilFields(t *testing.T) {
	r := Rule{
		Name: "new", Enabled: true, Mode: "MONITOR",
		// A nil field means "absent from configuration". Several controls
		// require a text field to be omitted outside certain modes, so nils
		// must not become JSON null.
		Fields: map[string]any{"title": nil, "subtext": "keep"},
	}
	out, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if _, present := got["id"]; present {
		t.Error("empty id was sent; the API rejects it")
	}
	if _, present := got["title"]; present {
		t.Error("nil field was sent as null")
	}
	if got["subtext"] != "keep" {
		t.Errorf("subtext = %v", got["subtext"])
	}
	if _, present := got["criteria"]; !present {
		t.Error("criteria must always be sent, as an empty object when unset")
	}
}

func TestRuleMarshalRejectsReservedFieldCollision(t *testing.T) {
	r := Rule{Name: "n", Mode: "OFF", Fields: map[string]any{"mode": "BLOCK"}}
	if _, err := json.Marshal(r); err == nil {
		t.Error("expected an error when Fields shadows a reserved key")
	}
}

func TestPutControlConfigReadsBack(t *testing.T) {
	var puts, gets int32
	c := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodPut:
			atomic.AddInt32(&puts, 1)
			var body ControlConfig
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decoding PUT body: %v", err)
			}
			if body.Globals == nil {
				t.Error("globals sent as null; must be an empty object")
			}
			_, _ = w.Write([]byte(`{}`))
		case http.MethodGet:
			atomic.AddInt32(&gets, 1)
			// The read-back is where server-assigned ids come from.
			_, _ = w.Write([]byte(`{"globals":{},"rules":[{"id":"assigned","name":"n","enabled":true,"mode":"OFF","criteria":{}}]}`))
		}
	}))

	got, err := c.PutControlConfig(context.Background(), "fileDownloadBlocking",
		&ControlConfig{Rules: []Rule{{Name: "n", Enabled: true, Mode: "OFF"}}})
	if err != nil {
		t.Fatalf("PutControlConfig: %v", err)
	}
	if puts != 1 || gets != 1 {
		t.Errorf("puts=%d gets=%d, want 1 and 1", puts, gets)
	}
	if got.Rules[0].ID != "assigned" {
		t.Errorf("read-back id = %q", got.Rules[0].ID)
	}
}

func TestPutControlConfigNilMeansEmptyDocument(t *testing.T) {
	// Destroy is a PUT of an empty document, so nil must serialise to
	// {"globals":{},"rules":[]} rather than nulls.
	c := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			var raw map[string]json.RawMessage
			if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if string(raw["globals"]) != "{}" {
				t.Errorf("globals = %s, want {}", raw["globals"])
			}
			if string(raw["rules"]) != "[]" {
				t.Errorf("rules = %s, want []", raw["rules"])
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"globals":{},"rules":[]}`))
	}))
	if _, err := c.PutControlConfig(context.Background(), "fileDownloadBlocking", nil); err != nil {
		t.Fatalf("PutControlConfig(nil): %v", err)
	}
}

func TestListEmployeesFollowsPagination(t *testing.T) {
	// A half-read lookup table would silently produce the wrong plan, so
	// pagination has to be followed to the end.
	var seenTokens []string
	c := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenTokens = append(seenTokens, r.URL.Query().Get("nextToken"))
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("nextToken") {
		case "":
			_, _ = w.Write([]byte(`{"result":[{"id":"1","email":"a@example.com"}],
				"paging":{"moreResults":true,"nextToken":"page2"}}`))
		case "page2":
			_, _ = w.Write([]byte(`{"result":[{"id":"2","email":"b@example.com"}],
				"paging":{"moreResults":false,"nextToken":null}}`))
		default:
			t.Errorf("unexpected nextToken %q", r.URL.Query().Get("nextToken"))
		}
	}))

	got, err := c.ListEmployees(context.Background(), EmployeeFilter{})
	if err != nil {
		t.Fatalf("ListEmployees: %v", err)
	}
	if len(got) != 2 || got[0].ID != "1" || got[1].ID != "2" {
		t.Errorf("got %d employees: %+v", len(got), got)
	}
	if len(seenTokens) != 2 || seenTokens[0] != "" || seenTokens[1] != "page2" {
		t.Errorf("tokens = %v", seenTokens)
	}
}

func TestListEmployeesStopsWhenMoreResultsIsTrueButTokenIsEmpty(t *testing.T) {
	// Defensive: an inconsistent envelope must not loop forever.
	var calls int32
	c := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"result":[],"paging":{"moreResults":true,"nextToken":""}}`))
	}))
	if _, err := c.ListEmployees(context.Background(), EmployeeFilter{}); err != nil {
		t.Fatalf("ListEmployees: %v", err)
	}
	if calls != 1 {
		t.Errorf("calls = %d, want 1", calls)
	}
}

func TestListEmployeesBoundsRunawayPagination(t *testing.T) {
	// A cursor that never terminates has to fail rather than hang an apply.
	c := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"result":[],"paging":{"moreResults":true,"nextToken":"always"}}`))
	}))
	_, err := c.ListEmployees(context.Background(), EmployeeFilter{})
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "kept reporting more results") {
		t.Errorf("error = %v", err)
	}
}

func TestEmployeeFilterQuery(t *testing.T) {
	yes := true
	q := EmployeeFilter{
		Email:    "a@example.com",
		Groups:   []string{"Finance", "Engineering"},
		Licensed: &yes,
	}.query()

	if q.Get("email") != "a@example.com" {
		t.Errorf("email = %q", q.Get("email"))
	}
	// Repeated rather than comma-joined: the parameter is an array.
	if groups := q["groups"]; len(groups) != 2 || groups[0] != "Finance" {
		t.Errorf("groups = %v", groups)
	}
	if q.Get("licensed") != "true" {
		t.Errorf("licensed = %q", q.Get("licensed"))
	}
	// An unset pointer must be omitted, not sent as false.
	if _, present := q["chatopsEnabled"]; present {
		t.Error("chatopsEnabled sent when it was not set")
	}
}

func TestListAppsFollowsPaginationAndParsesCategories(t *testing.T) {
	c := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("nextToken") == "" {
			// Shape taken from a live tenant.
			_, _ = w.Write([]byte(`{"result":[{"id":"a1","type":"MIRO","friendlyName":"Miro",
				"approvalStatus":null,"labels":[],
				"categories":[{"code":34,"name":"Information Technology","group":"Technology"},
				              {"code":56,"name":"Productivity Applications","group":"Technology"}]}],
				"paging":{"moreResults":true,"nextToken":"p2"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"result":[{"id":"a2","type":"ZAPIER","labels":["reviewed"]}],
			"paging":{"moreResults":false}}`))
	}))

	got, err := c.ListApps(context.Background())
	if err != nil {
		t.Fatalf("ListApps: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d apps", len(got))
	}
	if len(got[0].Categories) != 2 || got[0].Categories[0].Code != 34 ||
		got[0].Categories[0].Name != "Information Technology" {
		t.Errorf("categories mis-parsed: %+v", got[0].Categories)
	}
	// approvalStatus is null on an unreviewed app and must not break decoding.
	if got[0].ApprovalStatus != "" {
		t.Errorf("ApprovalStatus = %q, want empty for null", got[0].ApprovalStatus)
	}
	if got[1].Type != "ZAPIER" || len(got[1].Labels) != 1 {
		t.Errorf("second app mis-parsed: %+v", got[1])
	}
}

func TestPutConfigLeavesTheCallersDocumentAlone(t *testing.T) {
	// The empty globals and rules a PUT needs are filled in on a copy: the
	// caller's document is what it planned, and must still read that way.
	var paths []string
	c := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"globals":{},"rules":[]}`))
	}))

	cfg := &ControlConfig{}
	if _, err := c.PutControlConfig(context.Background(), "fileDownloadBlocking", cfg); err != nil {
		t.Fatalf("PutControlConfig: %v", err)
	}
	if _, err := c.PutTelemetryConfig(context.Background(), "fileUpload", cfg); err != nil {
		t.Fatalf("PutTelemetryConfig: %v", err)
	}
	if cfg.Globals != nil || cfg.Rules != nil {
		t.Errorf("caller's document was changed: %+v", cfg)
	}
	want := []string{
		"PUT /v1/controls/fileDownloadBlocking/configuration",
		"GET /v1/controls/fileDownloadBlocking/configuration",
		"PUT /v1/telemetry/fileUpload/configuration",
		"GET /v1/telemetry/fileUpload/configuration",
	}
	if !reflect.DeepEqual(paths, want) {
		t.Errorf("requests = %v, want %v", paths, want)
	}
}

func TestDoReturnsTheFailureWhenCancelledDuringBackoff(t *testing.T) {
	// A cancellation that lands while waiting to retry must not replace the
	// error that caused the retry: that error is what explains the failure.
	var calls int32
	c := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"message":"Service Unavailable"}`))
	}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.sleep = func(ctx context.Context, _ time.Duration) error {
		cancel()
		// The real wait, which must notice the cancellation at once.
		return wait(ctx, time.Hour)
	}

	_, err := c.GetControlConfig(ctx, "x")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("err = %v, want the 503 that caused the retry", err)
	}
	if errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want the original failure rather than the cancellation", err)
	}
	if calls != 1 {
		t.Errorf("calls = %d, want 1", calls)
	}
}

func TestDoGivesUpWhenRetriesAreExhausted(t *testing.T) {
	var calls int32
	var waits []time.Duration
	c := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	c.sleep = func(_ context.Context, d time.Duration) error {
		waits = append(waits, d)
		return nil
	}

	_, err := c.GetControlConfig(context.Background(), "x")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("err = %v, want the last 503", err)
	}
	// maxRetries is 2 here: the first attempt plus two retries, with a wait
	// before each retry and none after the last attempt.
	if calls != 3 {
		t.Errorf("calls = %d, want 3", calls)
	}
	if len(waits) != 2 {
		t.Errorf("waited %d times, want 2", len(waits))
	}
}

func TestDoRetriesServerErrorsForIdempotentMethods(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPut} {
		for _, code := range []int{http.StatusInternalServerError, http.StatusBadGateway, http.StatusGatewayTimeout} {
			t.Run(fmt.Sprintf("%s %d", method, code), func(t *testing.T) {
				var calls int32
				c := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != method {
						t.Errorf("method = %s, want %s", r.Method, method)
					}
					if atomic.AddInt32(&calls, 1) == 1 {
						w.WriteHeader(code)
						return
					}
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(`{"result":"ok"}`))
				}))

				var body any
				if method == http.MethodPut {
					body = map[string]any{"globals": map[string]any{}}
				}
				var out struct{ Result string }
				if err := c.do(context.Background(), method, "/v1/x", body, &out); err != nil {
					t.Fatalf("expected the retry to succeed: %v", err)
				}
				if calls != 2 {
					t.Errorf("calls = %d, want 2", calls)
				}
				if out.Result != "ok" {
					t.Errorf("Result = %q", out.Result)
				}
			})
		}
	}
}

func TestDoReportsAnUndecodableSuccess(t *testing.T) {
	// A 2xx whose body does not decode is an error, and one that retrying the
	// same request cannot fix.
	var calls int32
	c := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`<html>not json</html>`))
	}))

	_, err := c.GetControlConfig(context.Background(), "x")
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %v, want an *APIError", err)
	}
	if apiErr.StatusCode != http.StatusOK || !strings.Contains(apiErr.Message, "decoding response body") {
		t.Errorf("err = %v, want a decoding failure on the 200", err)
	}
	if calls != 1 {
		t.Errorf("calls = %d, want 1", calls)
	}
}

func TestDoAcceptsNoContent(t *testing.T) {
	// A 204 has no body to decode, even when the caller asked for one.
	c := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	out := struct{ Result string }{Result: "untouched"}
	if err := c.do(context.Background(), http.MethodPut, "/v1/x", map[string]any{}, &out); err != nil {
		t.Fatalf("do: %v", err)
	}
	if out.Result != "untouched" {
		t.Errorf("Result = %q, want it left alone", out.Result)
	}
}

func TestBackoffHonoursRetryAfter(t *testing.T) {
	for _, tc := range []struct {
		header string
		want   time.Duration
	}{
		{"3", 3 * time.Second},
		{"60", 60 * time.Second},
	} {
		if got := backoff(0, tc.header); got != tc.want {
			t.Errorf("backoff(0, %q) = %s, want %s", tc.header, got, tc.want)
		}
	}
}

func TestBackoffIgnoresUnusableRetryAfter(t *testing.T) {
	// Anything that is not a positive number of seconds up to a minute falls
	// back to the client's own schedule: an HTTP date, which this client does
	// not parse, zero, a negative value, and a wait longer than the cap.
	for _, header := range []string{"Wed, 21 Oct 2015 07:28:00 GMT", "soon", "0", "-5", "61", "3600"} {
		got := backoff(0, header)
		if got < 250*time.Millisecond || got > 500*time.Millisecond {
			t.Errorf("backoff(0, %q) = %s, want the attempt-0 delay of 250ms to 500ms", header, got)
		}
	}
}

func TestBackoffJitterStaysInBounds(t *testing.T) {
	// The delay doubles from 500ms per attempt, capped at 8s, and jitter puts
	// each wait between half of it and all of it.
	for attempt, base := range []time.Duration{
		500 * time.Millisecond, time.Second, 2 * time.Second, 4 * time.Second,
		8 * time.Second, 8 * time.Second, 8 * time.Second,
	} {
		lo, hi := base/2, base
		seen := map[time.Duration]bool{}
		for range 200 {
			got := backoff(attempt, "")
			if got < lo || got > hi {
				t.Fatalf("backoff(%d) = %s, want between %s and %s", attempt, got, lo, hi)
			}
			seen[got] = true
		}
		// Without jitter contending writers retry in lockstep.
		if len(seen) < 2 {
			t.Errorf("backoff(%d) returned the same delay every time", attempt)
		}
	}
}

func TestListBlockedURLs(t *testing.T) {
	c := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/controls/blockedUrls" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"result":["*://b.example.com/*","*://a.example.com/*"]}`))
	}))
	got, err := c.ListBlockedURLs(context.Background())
	if err != nil {
		t.Fatalf("ListBlockedURLs: %v", err)
	}
	if want := []string{"*://b.example.com/*", "*://a.example.com/*"}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestDeleteAllBlockedURLs(t *testing.T) {
	var got string
	c := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Method + " " + r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	if err := c.DeleteAllBlockedURLs(context.Background()); err != nil {
		t.Fatalf("DeleteAllBlockedURLs: %v", err)
	}
	if want := "DELETE /v1/controls/blockedUrls"; got != want {
		t.Errorf("request = %q, want %q", got, want)
	}
}

func TestGetCustomDetection(t *testing.T) {
	c := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if want := "/v1/controls/customDetections/CUSTOM_MY_DETECTION"; r.URL.Path != want {
			t.Errorf("path = %q, want %q", r.URL.Path, want)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"detectionEventType":"CUSTOM_MY_DETECTION","detectionEventName":"My detection",
			"detectionLogic":"metadata:\n  name: x\n","rules":[{"id":"r1","name":"n","enabled":true,"mode":"MONITOR","criteria":{}}]}`))
	}))
	got, err := c.GetCustomDetection(context.Background(), "CUSTOM_MY_DETECTION")
	if err != nil {
		t.Fatalf("GetCustomDetection: %v", err)
	}
	if got.DetectionEventName != "My detection" || got.DetectionLogic != "metadata:\n  name: x\n" {
		t.Errorf("detection mis-parsed: %+v", got)
	}
	if len(got.Rules) != 1 || got.Rules[0].ID != "r1" {
		t.Errorf("rules = %+v", got.Rules)
	}
}

func TestUpdateCustomDetectionPutsAndReadsBack(t *testing.T) {
	var requests []string
	c := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPut {
			var raw map[string]json.RawMessage
			if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
				t.Errorf("decode: %v", err)
			}
			if string(raw["detectionEventType"]) != `"CUSTOM_X"` || string(raw["detectionLogic"]) != `"logic"` {
				t.Errorf("body = %v", raw)
			}
			// A nil rule list is an empty one, not null.
			if string(raw["rules"]) != "[]" {
				t.Errorf("rules = %s, want []", raw["rules"])
			}
			if _, present := raw["detectionEventName"]; present {
				t.Error("the name cannot be changed and must not be sent")
			}
			_, _ = w.Write([]byte(`{}`))
			return
		}
		_, _ = w.Write([]byte(`{"detectionEventType":"CUSTOM_X","detectionEventName":"X","detectionLogic":"logic","rules":[]}`))
	}))

	got, err := c.UpdateCustomDetection(context.Background(), "CUSTOM_X", "logic", nil)
	if err != nil {
		t.Fatalf("UpdateCustomDetection: %v", err)
	}
	want := []string{"PUT /v1/controls/customDetections/CUSTOM_X", "GET /v1/controls/customDetections/CUSTOM_X"}
	if !reflect.DeepEqual(requests, want) {
		t.Errorf("requests = %v, want %v", requests, want)
	}
	if got.DetectionEventName != "X" {
		t.Errorf("read-back = %+v", got)
	}
}

func TestGetEmployee(t *testing.T) {
	c := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The identifier is escaped into the path.
		if want := "/v1/employees/a%2Fb"; r.URL.EscapedPath() != want {
			t.Errorf("path = %q, want %q", r.URL.EscapedPath(), want)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"a/b","email":"a@example.com","knownEmails":["a@example.com","alias@example.com"],"licensed":true}`))
	}))
	got, err := c.GetEmployee(context.Background(), "a/b")
	if err != nil {
		t.Fatalf("GetEmployee: %v", err)
	}
	if got.Email != "a@example.com" || !got.Licensed ||
		!reflect.DeepEqual(got.KnownEmails, []string{"a@example.com", "alias@example.com"}) {
		t.Errorf("employee mis-parsed: %+v", got)
	}

	if _, err := c.GetEmployee(context.Background(), ""); err == nil {
		t.Error("expected an error for an empty id")
	}
}

func TestUpdateEmployeeSendsOnlySetFields(t *testing.T) {
	var got map[string]any
	var method, path string
	c := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, path = r.Method, r.URL.Path
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`null`))
	}))

	first := "Ada"
	if err := c.UpdateEmployee(context.Background(), "e1", EmployeeUpdate{FirstName: &first}); err != nil {
		t.Fatalf("UpdateEmployee: %v", err)
	}
	if method != http.MethodPatch || path != "/v1/employees/e1" {
		t.Errorf("request = %s %s", method, path)
	}
	if want := map[string]any{"firstName": "Ada"}; !reflect.DeepEqual(got, want) {
		t.Errorf("body = %v, want %v", got, want)
	}

	if err := c.UpdateEmployee(context.Background(), "", EmployeeUpdate{FirstName: &first}); err == nil {
		t.Error("expected an error for an empty id")
	}
}

func TestMergeEmployeesStopsAtTheFailingBatch(t *testing.T) {
	// Twelve secondaries go as batches of five, five and two. When the second
	// is refused, the error is returned and the third is never sent.
	var batches [][]string
	c := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/employees/p/merge" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		var body struct {
			SecondaryEmployeeIDs []string `json:"secondaryEmployeeIds"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode: %v", err)
		}
		batches = append(batches, body.SecondaryEmployeeIDs)
		w.Header().Set("Content-Type", "application/json")
		if len(batches) == 2 {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"status":"INVALID_INPUT_PROVIDED","message":"invalid"}`))
			return
		}
		_, _ = w.Write([]byte(`{"id":"p","email":"p@example.com"}`))
	}))

	var ids []string
	for i := range 12 {
		ids = append(ids, fmt.Sprintf("s%d", i))
	}
	got, err := c.MergeEmployees(context.Background(), "p", ids)
	if err == nil {
		t.Fatal("expected an error")
	}
	if got != nil {
		t.Errorf("got %+v, want nil alongside the error", got)
	}
	if want := [][]string{ids[0:5], ids[5:10]}; !reflect.DeepEqual(batches, want) {
		t.Errorf("batches = %v, want %v", batches, want)
	}
}
