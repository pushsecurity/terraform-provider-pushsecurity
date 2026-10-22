package provider

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/pushapi"
)

// requestLog records the requests the provider makes and how each was
// answered. Neither the provider nor the client counts them, and what some
// tests need to know, such as whether a request was retried or whether the API
// ever answered 429, is only visible on the wire.
type requestLog struct {
	mu       sync.Mutex
	requests []loggedRequest
}

type loggedRequest struct {
	method, path string
	status       int
}

func (r loggedRequest) String() string {
	return fmt.Sprintf("%s %s: %d", r.method, r.path, r.status)
}

// logRequests puts a recording proxy between the provider and the tenant it
// is pointed at, a real one or tenantStub, and points the provider at the
// proxy for the rest of the test.
//
// Only the provider's own requests are recorded, told apart by the
// User-Agent the provider sets. The checks that read the tenant as plain JSON
// go through the proxy too, and are left out.
func logRequests(t *testing.T) *requestLog {
	t.Helper()
	upstream, err := url.Parse(firstNonEmpty(os.Getenv(envBaseURL), pushapi.DefaultBaseURL))
	if err != nil {
		t.Fatalf("parsing %s: %v", envBaseURL, err)
	}
	log := &requestLog{}
	proxy := &httputil.ReverseProxy{Rewrite: func(r *httputil.ProxyRequest) { r.SetURL(upstream) }}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		proxy.ServeHTTP(rec, r)
		if strings.HasPrefix(r.UserAgent(), "terraform-provider-pushsecurity/") {
			log.add(loggedRequest{method: r.Method, path: r.URL.Path, status: rec.status})
		}
	}))
	t.Cleanup(srv.Close)
	t.Setenv(envBaseURL, srv.URL)
	return log
}

func (l *requestLog) add(r loggedRequest) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.requests = append(l.requests, r)
}

// all returns every request recorded so far, in the order answered.
func (l *requestLog) all() []loggedRequest {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]loggedRequest(nil), l.requests...)
}

// answered counts the requests answered with this status.
func (l *requestLog) answered(status int) int {
	n := 0
	for _, r := range l.all() {
		if r.status == status {
			n++
		}
	}
	return n
}

// statusRecorder notes the status a handler answers with.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}
