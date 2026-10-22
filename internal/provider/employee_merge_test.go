package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"

	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/pushapi"
)

// mergeStub is a tenant that implements merging the way the real API does:
// the secondary's record disappears, the response says nothing useful, and a
// request naming an identifier that no longer exists is answered 200 anyway.
//
// linger names employees the stub keeps alive through a merge, which is how
// the "did not take effect" path is exercised. The real API has
// not been seen to do this; the provider checks because the response cannot
// tell the difference.
type mergeStub struct {
	mu       sync.Mutex
	byID     map[string]pushapi.Employee
	linger   map[string]bool
	requests [][]string // secondary identifiers, one entry per merge request
	// caseSensitiveFilter makes the stub's email filter miss an address
	// spelled in different case, as the API's can. Either way the filter
	// also returns addresses that merely contain the one asked for.
	caseSensitiveFilter bool
}

func newMergeStub(emails ...string) *mergeStub {
	s := &mergeStub{byID: map[string]pushapi.Employee{}, linger: map[string]bool{}, caseSensitiveFilter: true}
	for _, e := range emails {
		s.byID["id-"+e] = pushapi.Employee{ID: "id-" + e, Email: e}
	}
	return s
}

func (s *mergeStub) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")

		path := strings.TrimPrefix(r.URL.Path, "/v1/employees")
		switch {
		case r.Method == http.MethodGet && (path == "" || path == "/"):
			filter := r.URL.Query().Get("email")
			var out []pushapi.Employee
			for _, e := range s.byID {
				if filter == "" || (s.caseSensitiveFilter && strings.Contains(e.Email, filter)) ||
					(!s.caseSensitiveFilter && strings.Contains(strings.ToLower(e.Email), strings.ToLower(filter))) {
					out = append(out, e)
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"result": out,
				"paging": map[string]any{"moreResults": false, "nextToken": nil},
			})

		case r.Method == http.MethodPost && strings.HasSuffix(path, "/merge"):
			var body struct {
				SecondaryEmployeeIDs []string `json:"secondaryEmployeeIds"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			s.requests = append(s.requests, body.SecondaryEmployeeIDs)
			for _, id := range body.SecondaryEmployeeIDs {
				if !s.linger[id] {
					delete(s.byID, id)
				}
			}
			primary := strings.TrimSuffix(strings.TrimPrefix(path, "/"), "/merge")
			_ = json.NewEncoder(w).Encode(s.byID[primary])

		case r.Method == http.MethodGet:
			id := strings.TrimPrefix(path, "/")
			e, ok := s.byID[id]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"status": "RECORD_NOT_FOUND", "message": "This record does not exist.",
				})
				return
			}
			_ = json.NewEncoder(w).Encode(e)

		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	})
}

func testMergeClient(t *testing.T, stub *mergeStub) (*pushapi.Client, *employeeResolver) {
	t.Helper()
	srv := httptest.NewServer(stub.handler())
	t.Cleanup(srv.Close)
	client, err := pushapi.New(srv.URL, "k", pushapi.WithMaxRetries(0))
	if err != nil {
		t.Fatalf("pushapi.New: %v", err)
	}
	return client, newEmployeeResolver(client)
}

func match(primary, secondary string) aliasMatch {
	return aliasMatch{
		PrimaryEmail: primary, PrimaryID: "id-" + primary,
		SecondaryEmail: secondary, SecondaryID: "id-" + secondary,
	}
}

func TestPerformMergesGroupsAndChunks(t *testing.T) {
	// Seven addresses for one person and one for another: the API takes five
	// secondaries per request, so that is 5 + 2 + 1 requests, not eight.
	var matches []aliasMatch
	emails := []string{"a@example.org", "b@example.org"}
	for i, suffix := range []string{"admin", "support", "svc", "ops", "sec", "dev", "test"} {
		secondary := "a." + suffix + "@example.org"
		emails = append(emails, secondary)
		matches = append(matches, match("a@example.org", secondary))
		_ = i
	}
	matches = append(matches, match("b@example.org", "b.admin@example.org"))
	emails = append(emails, "b.admin@example.org")

	stub := newMergeStub(emails...)
	client, resolver := testMergeClient(t, stub)

	var diags diag.Diagnostics
	done := performMerges(context.Background(), client, resolver, matches, &diags)

	if diags.HasError() {
		t.Fatalf("performMerges: %v", diags.Errors())
	}
	if len(done) != 8 {
		t.Errorf("merged %d, want 8", len(done))
	}
	if len(stub.requests) != 3 {
		t.Fatalf("made %d requests, want 3: %v", len(stub.requests), stub.requests)
	}
	if len(stub.requests[0]) != pushapi.MaxMergeSecondaries {
		t.Errorf("first request carried %d secondaries, want %d",
			len(stub.requests[0]), pushapi.MaxMergeSecondaries)
	}
	if len(stub.requests[1]) != 2 || len(stub.requests[2]) != 1 {
		t.Errorf("request sizes = %d, %d; want 2 and 1", len(stub.requests[1]), len(stub.requests[2]))
	}
}

// The endpoint answers 200 whether or not it merged anything, so success is
// established by reading the secondary back and finding it gone.
func TestPerformMergesVerifiesTheSecondaryIsGone(t *testing.T) {
	stub := newMergeStub("a@example.org", "a.admin@example.org")
	stub.linger["id-a.admin@example.org"] = true
	client, resolver := testMergeClient(t, stub)

	var diags diag.Diagnostics
	done := performMerges(context.Background(), client, resolver,
		[]aliasMatch{match("a@example.org", "a.admin@example.org")}, &diags)

	if len(done) != 0 {
		t.Errorf("reported %d merges, want none", len(done))
	}
	if !diags.HasError() {
		t.Fatal("want an error when the secondary survives the merge")
	}
	if got := diags.Errors()[0].Summary(); !strings.Contains(got, "did not take effect") {
		t.Errorf("summary = %q", got)
	}
}

// A merged record is gone, so anything the resolver cached about it would
// otherwise be handed out for the rest of the run.
func TestPerformMergesEvictsTheResolverCache(t *testing.T) {
	stub := newMergeStub("a@example.org", "a.admin@example.org")
	client, resolver := testMergeClient(t, stub)
	ctx := context.Background()

	if _, found, err := resolver.Lookup(ctx, "a.admin@example.org"); err != nil || !found {
		t.Fatalf("Lookup before merge: found=%v err=%v", found, err)
	}

	var diags diag.Diagnostics
	performMerges(ctx, client, resolver, []aliasMatch{match("a@example.org", "a.admin@example.org")}, &diags)
	if diags.HasError() {
		t.Fatalf("performMerges: %v", diags.Errors())
	}

	_, found, err := resolver.Lookup(ctx, "a.admin@example.org")
	if err != nil {
		t.Fatalf("Lookup after merge: %v", err)
	}
	if found {
		t.Error("the resolver still resolves an address whose record was merged away")
	}
}

// The API's email filter can miss an address the tenant spells in different
// case from the configuration. The fallback enumeration is what stops that
// reading as "no such employee".
func TestResolverFindsAddressesTheFilterMisses(t *testing.T) {
	stub := newMergeStub("A.Person@example.org")
	_, resolver := testMergeClient(t, stub)

	id, found, err := resolver.Lookup(context.Background(), "a.person@example.org")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if !found {
		t.Fatal("did not find an address the tenant holds with different capitalisation")
	}
	if id != "id-A.Person@example.org" {
		t.Errorf("id = %q", id)
	}
}

func TestResolverReportsAbsenceWithoutAnError(t *testing.T) {
	stub := newMergeStub("a@example.org")
	_, resolver := testMergeClient(t, stub)

	id, found, err := resolver.Lookup(context.Background(), "nobody@example.org")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if found || id != "" {
		t.Errorf("Lookup = (%q, %v), want absent", id, found)
	}

	// The criteria paths still want the error, and still get it.
	if _, err := resolver.IDForEmail(context.Background(), "nobody@example.org"); err == nil {
		t.Error("IDForEmail reported no error for an address the tenant does not hold")
	}
}
