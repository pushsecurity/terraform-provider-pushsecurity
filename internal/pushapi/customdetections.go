package pushapi

import (
	"context"
	"net/url"
)

// CustomDetection is one custom detection in full.
//
// Identity is DetectionEventType, which the server derives from
// DetectionEventName on creation (uppercased, spaces to underscores, prefixed
// with CUSTOM_). Neither can be changed afterwards: a rename is a new
// detection, which the provider models as a resource replacement.
//
// DetectionLogic is stored and returned byte for byte, so it round-trips
// through state unchanged and needs no normalisation. That is what makes
// detection-as-code work: file("detections/x.yaml") in HCL compares equal to
// what the API returns.
type CustomDetection struct {
	DetectionEventType string `json:"detectionEventType,omitempty"`
	DetectionEventName string `json:"detectionEventName,omitempty"`
	DetectionLogic     string `json:"detectionLogic"`
	Rules              []Rule `json:"rules"`
}

// CustomDetectionSummary is one entry in the index. The list endpoint returns
// identity only — no detection logic, no rules — so enumerating everything in
// full costs one request per detection.
type CustomDetectionSummary struct {
	DetectionEventType string `json:"detectionEventType"`
	DetectionEventName string `json:"detectionEventName"`
}

type customDetectionListResponse struct {
	Result []CustomDetectionSummary `json:"result"`
}

// ListCustomDetections returns the index of custom detections: identity only.
func (c *Client) ListCustomDetections(ctx context.Context) ([]CustomDetectionSummary, error) {
	var out customDetectionListResponse
	if err := c.get(ctx, "/v1/controls/customDetections", &out); err != nil {
		return nil, err
	}
	return out.Result, nil
}

// GetCustomDetection reads one custom detection in full.
//
// Returns an *APIError with a 404 status when the detection does not exist;
// test with NotFound.
func (c *Client) GetCustomDetection(ctx context.Context, detectionEventType string) (*CustomDetection, error) {
	var out CustomDetection
	if err := c.get(ctx, customDetectionPath(detectionEventType), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CreateCustomDetection creates a custom detection and returns it as stored,
// including the server-derived detectionEventType and rule ids.
//
// The API requires at least one rule on creation, unlike the update path which
// accepts an empty list.
func (c *Client) CreateCustomDetection(ctx context.Context, name, logic string, rules []Rule) (*CustomDetection, error) {
	if rules == nil {
		rules = []Rule{}
	}
	body := struct {
		DetectionEventName string `json:"detectionEventName"`
		DetectionLogic     string `json:"detectionLogic"`
		Rules              []Rule `json:"rules"`
	}{name, logic, rules}

	var out CustomDetection
	if err := c.post(ctx, "/v1/controls/customDetections", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateCustomDetection replaces the detection logic and the whole rule list of
// an existing custom detection.
//
// The name cannot be changed and is not sent. As with the control endpoints,
// rules carrying an ID are updated in place and rules without one are created;
// anything omitted is deleted.
func (c *Client) UpdateCustomDetection(ctx context.Context, detectionEventType, logic string, rules []Rule) (*CustomDetection, error) {
	if rules == nil {
		rules = []Rule{}
	}
	body := struct {
		DetectionEventType string `json:"detectionEventType"`
		DetectionLogic     string `json:"detectionLogic"`
		Rules              []Rule `json:"rules"`
	}{detectionEventType, logic, rules}

	if err := c.put(ctx, customDetectionPath(detectionEventType), body, nil); err != nil {
		return nil, err
	}
	return c.GetCustomDetection(ctx, detectionEventType)
}

// DeleteCustomDetection removes a custom detection outright. Unlike the control
// configuration resources, this is a real delete rather than a PUT of an empty
// document.
func (c *Client) DeleteCustomDetection(ctx context.Context, detectionEventType string) error {
	return c.delete(ctx, customDetectionPath(detectionEventType), nil)
}

func customDetectionPath(detectionEventType string) string {
	return "/v1/controls/customDetections/" + url.PathEscape(detectionEventType)
}
