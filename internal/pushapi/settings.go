package pushapi

import (
	"context"
	"errors"
)

// Settings is the tenant-wide settings document: which domains Push monitors
// as belonging to the organisation.
//
// There is exactly one per tenant. It cannot be created or deleted, only read
// and changed, and a change touches only the fields it names.
type Settings struct {
	// MonitoredDomains is stored lower-cased and without duplicates. Its order
	// carries no meaning: the console adds and removes entries one at a time.
	MonitoredDomains []string `json:"monitoredDomains"`
	// MonitorAllDomains is whether every domain is monitored, not only
	// MonitoredDomains. A new tenant starts with it on.
	MonitorAllDomains bool `json:"monitorAllDomains"`
}

// SettingsUpdate names the fields a change sets. A nil field is left as the
// tenant has it, and at least one must be set.
type SettingsUpdate struct {
	// MonitoredDomains replaces the whole list; a pointer to an empty slice
	// clears it. It is more than a list: adding a domain marks the accounts
	// Push already holds on it as the organisation's, and removing one unmarks
	// them.
	MonitoredDomains  *[]string `json:"monitoredDomains,omitempty"`
	MonitorAllDomains *bool     `json:"monitorAllDomains,omitempty"`
}

// MaxMonitoredDomains is the most entries MonitoredDomains can hold.
const MaxMonitoredDomains = 100

const settingsPath = "/v1/settings"

// GetSettings reads the tenant's settings.
func (c *Client) GetSettings(ctx context.Context) (*Settings, error) {
	var out Settings
	if err := c.get(ctx, settingsPath, &out); err != nil {
		return nil, err
	}
	if out.MonitoredDomains == nil {
		out.MonitoredDomains = []string{}
	}
	return &out, nil
}

// UpdateSettings changes the fields u names and returns the settings as
// stored afterwards.
func (c *Client) UpdateSettings(ctx context.Context, u SettingsUpdate) (*Settings, error) {
	if u.MonitoredDomains == nil && u.MonitorAllDomains == nil {
		return nil, errors.New("a settings update must set at least one field")
	}
	// The API refuses null for the list, so an empty one has to go as [].
	if u.MonitoredDomains != nil && *u.MonitoredDomains == nil {
		u.MonitoredDomains = &[]string{}
	}

	var out Settings
	if err := c.patch(ctx, settingsPath, u, &out); err != nil {
		return nil, err
	}
	if out.MonitoredDomains == nil {
		out.MonitoredDomains = []string{}
	}
	return &out, nil
}
