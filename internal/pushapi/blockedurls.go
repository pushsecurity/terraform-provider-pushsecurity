package pushapi

import "context"

// The blocked URL endpoints do not follow the whole-document PUT pattern the
// rest of the control surface uses. There is a GET for the whole list, a POST
// that adds one entry, and a DELETE that removes every entry — no per-entry
// delete and no bulk replace. Converging therefore means DELETE-all followed by
// POST-per-entry, which is not atomic: blocking is degraded for the duration.
//
// Two behaviours matter to the resource layer:
//
//  1. The server normalises what it stores. POSTing "example.com" stores
//     "*://example.com/*", and {host, path} is folded into the same string
//     form. A resource must therefore compare against the normalised value or
//     it will show a diff on every plan.
//  2. GET does not return entries in insertion order. The list is a set, and a
//     resource must model it as one.

type blockedURLListResponse struct {
	Result []string `json:"result"`
}

type blockedURLPostResponse struct {
	Result string `json:"result"`
}

// ListBlockedURLs returns every blocked URL pattern in the tenant, in the
// server's own order, which is not insertion order.
func (c *Client) ListBlockedURLs(ctx context.Context) ([]string, error) {
	var out blockedURLListResponse
	if err := c.get(ctx, "/v1/controls/blockedUrls", &out); err != nil {
		return nil, err
	}
	return out.Result, nil
}

// AddBlockedURL adds one blocked URL pattern and returns the normalised form
// the server stored, which may differ from what was sent.
func (c *Client) AddBlockedURL(ctx context.Context, pattern string) (string, error) {
	var out blockedURLPostResponse
	body := struct {
		URL string `json:"url"`
	}{pattern}
	if err := c.post(ctx, "/v1/controls/blockedUrls", body, &out); err != nil {
		return "", err
	}
	return out.Result, nil
}

// DeleteAllBlockedURLs removes every blocked URL pattern. There is no API for
// removing a single entry.
func (c *Client) DeleteAllBlockedURLs(ctx context.Context) error {
	return c.delete(ctx, "/v1/controls/blockedUrls", nil)
}
