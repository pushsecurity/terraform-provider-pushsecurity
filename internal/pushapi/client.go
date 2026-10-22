// Package pushapi is a hand-written client for the parts of the Push Security
// REST API v1 that the Terraform provider manages.
//
// It covers the control and telemetry configuration, custom detections,
// blocked URLs, tenant settings and employee management that the provider's
// resources write, and the app and employee inventory that its data sources
// read. The rest of the API is left out.
package pushapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultBaseURL is the production API endpoint.
const DefaultBaseURL = "https://api.pushsecurity.com"

const (
	defaultTimeout = 30 * time.Second
	// Generous, because the retry budget has to absorb contention rather than
	// just the occasional error. The API serialises configuration writes per
	// tenant and answers concurrent ones with 409, and Terraform applies
	// independent resources ten at a time by default, so a configuration
	// covering every control produces a burst of conflicting writes that have
	// to queue behind each other.
	defaultMaxRetries = 8
)

// Client talks to the Push Security REST API v1.
type Client struct {
	baseURL    *url.URL
	apiKey     string
	userAgent  string
	httpClient *http.Client
	maxRetries int
	// sleep waits out the backoff between attempts. Tests replace it so that
	// they can exercise retries without waiting through real delays.
	sleep func(ctx context.Context, d time.Duration) error
}

// Option customises a Client.
type Option func(*Client)

// WithHTTPClient replaces the underlying HTTP client. Used by tests.
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) { c.httpClient = h }
}

// WithUserAgent sets the User-Agent header. The provider sets it to its own
// name and version.
func WithUserAgent(ua string) Option {
	return func(c *Client) { c.userAgent = ua }
}

// WithMaxRetries sets how many times a retryable response is retried.
func WithMaxRetries(n int) Option {
	return func(c *Client) { c.maxRetries = n }
}

// New returns a Client for baseURL authenticating with apiKey.
//
// baseURL may be empty, in which case DefaultBaseURL is used. A trailing slash
// is tolerated. apiKey is required.
func New(baseURL, apiKey string, opts ...Option) (*Client, error) {
	if strings.TrimSpace(apiKey) == "" {
		return nil, errors.New("api key must not be empty")
	}
	if strings.TrimSpace(baseURL) == "" {
		baseURL = DefaultBaseURL
	}
	u, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("parsing base url %q: %w", baseURL, err)
	}
	// Plain http is accepted only for a server on this machine, which is what
	// a local test server or proxy looks like.
	local := u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1"
	if u.Scheme != "https" && (u.Scheme != "http" || !local) {
		return nil, fmt.Errorf("base url %q must use https", baseURL)
	}

	c := &Client{
		baseURL:    u,
		apiKey:     apiKey,
		userAgent:  "terraform-provider-pushsecurity",
		httpClient: &http.Client{Timeout: defaultTimeout},
		maxRetries: defaultMaxRetries,
		sleep:      wait,
	}
	for _, o := range opts {
		o(c)
	}
	return c, nil
}

// BaseURL returns the API endpoint the client sends requests to, without a
// trailing slash.
func (c *Client) BaseURL() string { return c.baseURL.String() }

// do issues a request against path, encoding body as JSON when non-nil and
// decoding the response into out when non-nil.
//
// Retryable failures are retried with exponential backoff, honouring
// Retry-After when the server sends one. A POST, which is not idempotent, is
// retried only on a response that says the server did not act on it (see
// APIError.Retryable).
func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var payload []byte
	if body != nil {
		var err error
		payload, err = json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encoding request body for %s %s: %w", method, path, err)
		}
	}

	for attempt := 0; ; attempt++ {
		apiErr, retryAfter, err := c.attempt(ctx, method, path, payload, out)
		switch {
		case err == nil && apiErr == nil:
			return nil

		case err != nil:
			// A transport error: no response at all, so nothing says whether
			// the server acted on the request before the connection failed. A
			// POST is never resent for exactly that reason, the same rule
			// APIError.Retryable applies to an error response: the client
			// timeout can fire after the server has acted on the request, and
			// a second POST creating the same custom detection would then be
			// answered with a conflict. Context cancellation is never worth
			// retrying either.
			if ctx.Err() != nil || method == http.MethodPost || attempt >= c.maxRetries {
				return err
			}

		default:
			if !apiErr.Retryable() || attempt >= c.maxRetries {
				return apiErr
			}
			err = apiErr
		}

		if werr := c.sleep(ctx, backoff(attempt, retryAfter)); werr != nil {
			// Return the failure that caused the retry, not the cancellation,
			// so the diagnostic explains what actually went wrong.
			return err
		}
	}
}

// attempt makes one request. It returns exactly one of: (nil, _, nil) on
// success, a non-nil *APIError for a non-2xx response, or a non-nil error for a
// transport failure. retryAfter carries the response header of the same name.
func (c *Client) attempt(ctx context.Context, method, path string, payload []byte, out any) (*APIError, string, error) {
	var reader io.Reader
	if payload != nil {
		reader = bytes.NewReader(payload)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL.String()+path, reader)
	if err != nil {
		return nil, "", fmt.Errorf("building request %s %s: %w", method, path, err)
	}
	req.Header.Set("x-api-key", c.apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer func() {
		// Drain before closing so the connection can be reused.
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if out == nil || resp.StatusCode == http.StatusNoContent {
			return nil, "", nil
		}
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return &APIError{
				Method: method, Path: path, StatusCode: resp.StatusCode,
				Message: fmt.Sprintf("decoding response body: %v", err),
			}, "", nil
		}
		return nil, "", nil
	}

	// Error bodies are small; read them whole so the message survives into the
	// Terraform diagnostic, which is the only place a practitioner sees it.
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return newAPIError(method, path, resp.StatusCode, raw, resp.Header), resp.Header.Get("Retry-After"), nil
}

func (c *Client) get(ctx context.Context, path string, out any) error {
	return c.do(ctx, http.MethodGet, path, nil, out)
}

func (c *Client) put(ctx context.Context, path string, body, out any) error {
	return c.do(ctx, http.MethodPut, path, body, out)
}

func (c *Client) post(ctx context.Context, path string, body, out any) error {
	return c.do(ctx, http.MethodPost, path, body, out)
}

func (c *Client) patch(ctx context.Context, path string, body, out any) error {
	return c.do(ctx, http.MethodPatch, path, body, out)
}

func (c *Client) delete(ctx context.Context, path string, body any) error {
	return c.do(ctx, http.MethodDelete, path, body, nil)
}

// backoff returns how long to wait before retry number attempt+1: the
// server's Retry-After, when it sends a usable one, and otherwise an
// exponential delay with jitter.
func backoff(attempt int, retryAfter string) time.Duration {
	if retryAfter != "" {
		if d, err := time.ParseDuration(retryAfter + "s"); err == nil && d > 0 && d <= 60*time.Second {
			return d
		}
	}
	d := time.Duration(1<<attempt) * 500 * time.Millisecond
	if d > 8*time.Second {
		d = 8 * time.Second
	}
	// Jitter matters more than the base delay here. Contending writers are
	// released by the same event and would otherwise back off in lockstep and
	// collide again on every attempt.
	return d/2 + time.Duration(rand.Int64N(int64(d/2)+1))
}

func wait(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
