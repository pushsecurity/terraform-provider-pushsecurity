package pushapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
)

// Every control configuration endpoint shares one wire shape:
//
//	{ "globals": {...}, "rules": [ {id, name, enabled, mode, <text fields>, criteria}, ... ] }
//
// The differences between controls are which text fields and criteria keys are
// allowed, which the provider models per control rather than in this client.
// The client therefore keeps rules weakly typed — a map of the fields the
// resource layer chose to send — so that adding a control never means touching
// the client.
//
// Rules are positional: the API evaluates them in the order sent and the first
// match wins. Order is preserved end to end.

// ControlConfig is the whole document for one control configuration endpoint.
type ControlConfig struct {
	Globals map[string]any `json:"globals"`
	Rules   []Rule         `json:"rules"`
}

// Rule is one rule within a control configuration.
//
// The named fields are the ones every control has. Fields carries the rest —
// per-control text and behaviour fields such as title, subtext, buttonText,
// operation, contentCapture, severity — and is flattened into the same JSON
// object on the wire.
type Rule struct {
	// ID is server-assigned. Sending it updates that rule in place; omitting it
	// creates a new rule. It must be omitted, not empty, for creation.
	ID       string
	Name     string
	Enabled  bool
	Mode     string
	Criteria map[string]Condition
	Fields   map[string]any
}

// Condition narrows a rule to a set of values.
//
// Action is "INCLUDE" or "EXCLUDE" and defaults to INCLUDE server-side. Not
// every criteria key accepts it: the include-only conditions
// (fileNamePatterns, regexPatterns, urlPatterns, appCategories,
// browserExtensionProfile, profileScope) reject it. The provider decides which
// keys expose it; the client sends whatever it is given, omitting Action when
// empty.
type Condition struct {
	Matches []string `json:"matches"`
	Action  string   `json:"action,omitempty"`
}

// reservedRuleKeys are the fields Rule models explicitly. Fields must not
// shadow them.
var reservedRuleKeys = map[string]struct{}{
	"id": {}, "name": {}, "enabled": {}, "mode": {}, "criteria": {},
}

// MarshalJSON flattens Fields alongside the named members.
func (r Rule) MarshalJSON() ([]byte, error) {
	out := make(map[string]any, len(r.Fields)+5)
	for k, v := range r.Fields {
		if _, reserved := reservedRuleKeys[k]; reserved {
			return nil, fmt.Errorf("rule field %q collides with a reserved key", k)
		}
		// A nil value means "not set in configuration". The API distinguishes
		// absent from null for the conditionally-required text fields — several
		// controls require a field to be *omitted* outside certain modes — so
		// drop nils rather than sending JSON null.
		if v == nil {
			continue
		}
		out[k] = v
	}
	out["name"] = r.Name
	out["enabled"] = r.Enabled
	out["mode"] = r.Mode
	// Omit id when creating; the API rejects an empty string.
	if r.ID != "" {
		out["id"] = r.ID
	}
	// criteria is required on some controls (clipboardBlocking) and optional on
	// the rest, where an empty object is accepted and means "no restriction".
	if r.Criteria == nil {
		out["criteria"] = map[string]Condition{}
	} else {
		out["criteria"] = r.Criteria
	}
	return json.Marshal(out)
}

// UnmarshalJSON splits the flat wire object back into the named members and
// Fields.
func (r *Rule) UnmarshalJSON(data []byte) error {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	*r = Rule{Fields: map[string]any{}}
	for k, v := range raw {
		switch k {
		case "id":
			r.ID, _ = v.(string)
		case "name":
			r.Name, _ = v.(string)
		case "enabled":
			r.Enabled, _ = v.(bool)
		case "mode":
			r.Mode, _ = v.(string)
		case "criteria":
			obj, ok := v.(map[string]any)
			if !ok {
				continue
			}
			r.Criteria = make(map[string]Condition, len(obj))
			for ck, cv := range obj {
				cond, ok := cv.(map[string]any)
				if !ok {
					continue
				}
				var c Condition
				if ms, ok := cond["matches"].([]any); ok {
					for _, m := range ms {
						if s, ok := m.(string); ok {
							c.Matches = append(c.Matches, s)
						}
					}
				}
				c.Action, _ = cond["action"].(string)
				r.Criteria[ck] = c
			}
		default:
			r.Fields[k] = v
		}
	}
	return nil
}

// GetControlConfig reads one control configuration. control is the API's
// camelCase control name, e.g. "fileDownloadBlocking".
func (c *Client) GetControlConfig(ctx context.Context, control string) (*ControlConfig, error) {
	var out ControlConfig
	if err := c.get(ctx, controlPath(control), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// PutControlConfig replaces one control configuration and returns it as
// stored. It is a full replace, not a merge: anything omitted is deleted.
// Rules carrying an ID update that rule in place; rules without one are
// created.
func (c *Client) PutControlConfig(ctx context.Context, control string, cfg *ControlConfig) (*ControlConfig, error) {
	if err := c.putConfig(ctx, controlPath(control), cfg); err != nil {
		return nil, err
	}
	return c.GetControlConfig(ctx, control)
}

// GetTelemetryConfig reads one telemetry configuration. telemetry is
// "fileDownload" or "fileUpload". The document shape is identical to a control
// configuration.
func (c *Client) GetTelemetryConfig(ctx context.Context, telemetry string) (*ControlConfig, error) {
	var out ControlConfig
	if err := c.get(ctx, telemetryPath(telemetry), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// PutTelemetryConfig replaces one telemetry configuration and returns it as
// stored, with the same full-replace semantics as PutControlConfig.
func (c *Client) PutTelemetryConfig(ctx context.Context, telemetry string, cfg *ControlConfig) (*ControlConfig, error) {
	if err := c.putConfig(ctx, telemetryPath(telemetry), cfg); err != nil {
		return nil, err
	}
	return c.GetTelemetryConfig(ctx, telemetry)
}

// putConfig writes a configuration document to path. A nil cfg writes an
// empty document.
//
// The PUT response body is not documented as returning the stored document,
// so callers read back rather than trusting it. The read-back is also what
// supplies server-assigned ids for newly created rules.
func (c *Client) putConfig(ctx context.Context, path string, cfg *ControlConfig) error {
	// A copy, so that filling in the empty values below never changes the
	// caller's document.
	var body ControlConfig
	if cfg != nil {
		body = *cfg
	}
	// globals is required on the controls that define keys in it, and an empty
	// object is valid everywhere, so never send null.
	if body.Globals == nil {
		body.Globals = map[string]any{}
	}
	if body.Rules == nil {
		body.Rules = []Rule{}
	}
	return c.put(ctx, path, &body, nil)
}

func controlPath(control string) string {
	return "/v1/controls/" + url.PathEscape(control) + "/configuration"
}

func telemetryPath(telemetry string) string {
	return "/v1/telemetry/" + url.PathEscape(telemetry) + "/configuration"
}
