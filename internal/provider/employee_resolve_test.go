package provider

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/pushapi"
)

// employeeStub serves /v1/employees with an email filter that matches whole
// addresses ignoring case, and counts requests so the caching can be asserted.
// The API's own filter is modelled by tenantStub and mergeStub.
type employeeStub struct {
	employees []pushapi.Employee
	fail      bool  // serve 500 instead, for the transient-failure paths
	filtered  int32 // requests carrying an email filter
	listed    int32 // requests enumerating everybody
}

func (s *employeeStub) handler(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.fail {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		email := r.URL.Query().Get("email")
		out := make([]pushapi.Employee, 0, len(s.employees))
		if email == "" {
			atomic.AddInt32(&s.listed, 1)
			out = append(out, s.employees...)
		} else {
			atomic.AddInt32(&s.filtered, 1)
			for _, e := range s.employees {
				if strings.EqualFold(e.Email, email) {
					out = append(out, e)
				}
			}
		}

		w.Header().Set("Content-Type", "application/json")
		var b strings.Builder
		b.WriteString(`{"result":[`)
		for i, e := range out {
			if i > 0 {
				b.WriteString(",")
			}
			b.WriteString(`{"id":"` + e.ID + `","email":"` + e.Email + `"}`)
		}
		b.WriteString(`],"paging":{"moreResults":false,"nextToken":null}}`)
		_, _ = w.Write([]byte(b.String()))
	})
}

func testResolver(t *testing.T, stub *employeeStub) *employeeResolver {
	t.Helper()
	srv := httptest.NewServer(stub.handler(t))
	t.Cleanup(srv.Close)
	// No retries: a 500 is retryable, and these tests assert request counts
	// and should not spend the retry budget's backoff doing it.
	client, err := pushapi.New(srv.URL, "k", pushapi.WithMaxRetries(0))
	if err != nil {
		t.Fatalf("pushapi.New: %v", err)
	}
	return newEmployeeResolver(client)
}

var testEmployees = []pushapi.Employee{
	{ID: "id-adam", Email: "adam@example.com"},
	{ID: "id-jo", Email: "jo@example.com"},
}

func TestEmployeeResolverForwardUsesTheServerSideFilter(t *testing.T) {
	// A tenant can hold tens of thousands of people. Resolving one address
	// must not enumerate them.
	stub := &employeeStub{employees: testEmployees}
	res := testResolver(t, stub)

	id, err := res.IDForEmail(context.Background(), "adam@example.com")
	if err != nil {
		t.Fatalf("IDForEmail: %v", err)
	}
	if id != "id-adam" {
		t.Errorf("id = %q, want id-adam", id)
	}
	if stub.listed != 0 {
		t.Errorf("enumerated the tenant %d time(s) for a single lookup", stub.listed)
	}
}

func TestEmployeeResolverCachesForwardLookups(t *testing.T) {
	stub := &employeeStub{employees: testEmployees}
	res := testResolver(t, stub)

	for range 3 {
		if _, err := res.IDForEmail(context.Background(), "adam@example.com"); err != nil {
			t.Fatalf("IDForEmail: %v", err)
		}
	}
	if stub.filtered != 1 {
		t.Errorf("made %d requests for the same address, want 1", stub.filtered)
	}
}

func TestEmployeeResolverForwardIsCaseInsensitive(t *testing.T) {
	// Directories are inconsistent about case, and addresses are compared
	// without regard to it. Configuration that differs only in case must not
	// churn.
	stub := &employeeStub{employees: testEmployees}
	res := testResolver(t, stub)

	first, err := res.IDForEmail(context.Background(), "adam@example.com")
	if err != nil {
		t.Fatalf("IDForEmail: %v", err)
	}
	second, err := res.IDForEmail(context.Background(), "Adam@Example.com")
	if err != nil {
		t.Fatalf("IDForEmail mixed case: %v", err)
	}
	if first != second {
		t.Errorf("case changed the identifier: %q vs %q", first, second)
	}
}

func TestEmployeeResolverForwardReportsMissing(t *testing.T) {
	stub := &employeeStub{employees: testEmployees}
	res := testResolver(t, stub)

	_, err := res.IDForEmail(context.Background(), "nobody@example.com")
	var missing errNoSuchEmployee
	if !errors.As(err, &missing) {
		t.Fatalf("err = %v, want errNoSuchEmployee", err)
	}
	if missing.Email != "nobody@example.com" {
		t.Errorf("error names %q", missing.Email)
	}
}

func TestEmployeeResolverForwardReportsAmbiguity(t *testing.T) {
	// An address is expected to belong to one employee; if two ever matched,
	// picking one would target the wrong person.
	stub := &employeeStub{employees: []pushapi.Employee{
		{ID: "id-1", Email: "shared@example.com"},
		{ID: "id-2", Email: "shared@example.com"},
	}}
	res := testResolver(t, stub)

	_, err := res.IDForEmail(context.Background(), "shared@example.com")
	var ambiguous errAmbiguousEmployee
	if !errors.As(err, &ambiguous) {
		t.Fatalf("err = %v, want errAmbiguousEmployee", err)
	}
	if ambiguous.Count != 2 {
		t.Errorf("count = %d, want 2", ambiguous.Count)
	}
}

func TestEmployeeResolverReverseEnumeratesOnceOnly(t *testing.T) {
	// There is no lookup by identifier, so the reverse direction has to
	// enumerate — but only once per run, however many rules need it.
	stub := &employeeStub{employees: testEmployees}
	res := testResolver(t, stub)

	for _, want := range []struct{ id, email string }{
		{"id-adam", "adam@example.com"},
		{"id-jo", "jo@example.com"},
		{"id-adam", "adam@example.com"},
	} {
		email, ok, err := res.EmailForID(context.Background(), want.id)
		if err != nil {
			t.Fatalf("EmailForID(%s): %v", want.id, err)
		}
		if !ok || email != want.email {
			t.Errorf("EmailForID(%s) = (%q, %v), want (%q, true)", want.id, email, ok, want.email)
		}
	}
	if stub.listed != 1 {
		t.Errorf("enumerated the tenant %d times, want 1", stub.listed)
	}
}

func TestEmployeeResolverReverseReportsUnknownIdentifier(t *testing.T) {
	// An offboarded employee still named by a rule. Not an error: the rule is
	// real and has to remain visible.
	stub := &employeeStub{employees: testEmployees}
	res := testResolver(t, stub)

	email, ok, err := res.EmailForID(context.Background(), "id-departed")
	if err != nil {
		t.Fatalf("EmailForID: %v", err)
	}
	if ok || email != "" {
		t.Errorf("got (%q, %v), want (\"\", false)", email, ok)
	}
}

func TestEmployeeResolverTreatsCompletedEnumerationAsAuthoritative(t *testing.T) {
	// Once the whole tenant is known, a missing address needs no request.
	stub := &employeeStub{employees: testEmployees}
	res := testResolver(t, stub)

	if _, _, err := res.EmailForID(context.Background(), "id-departed"); err != nil {
		t.Fatalf("EmailForID: %v", err)
	}
	before := stub.filtered
	if _, err := res.IDForEmail(context.Background(), "nobody@example.com"); err == nil {
		t.Fatal("expected errNoSuchEmployee")
	}
	if stub.filtered != before {
		t.Errorf("asked the API again after a full enumeration (%d -> %d)", before, stub.filtered)
	}
}

func TestEmployeeResolverReverseUsesForwardCache(t *testing.T) {
	// A write resolves addresses forward; the state it produces then needs the
	// reverse direction for the same people. That must not enumerate.
	stub := &employeeStub{employees: testEmployees}
	res := testResolver(t, stub)

	if _, err := res.IDForEmail(context.Background(), "adam@example.com"); err != nil {
		t.Fatalf("IDForEmail: %v", err)
	}
	email, ok, err := res.EmailForID(context.Background(), "id-adam")
	if err != nil || !ok || email != "adam@example.com" {
		t.Fatalf("EmailForID = (%q, %v, %v)", email, ok, err)
	}
	if stub.listed != 0 {
		t.Errorf("enumerated the tenant despite a warm forward cache")
	}
}
