package pushapi

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
)

// The inventory endpoints are read-only and paginated, and the provider uses
// them only to back data sources: looking up the employee identifiers, app
// types, labels and category codes that control criteria refer to.
//
// Paging is token-based. `paging.next` also exists but is deprecated in favour
// of `paging.nextToken`, so only the token is used. Every list method here
// follows the pages to the end: these are lookup tables for a configuration,
// and a half-read one would silently produce the wrong plan.

// maxPageRequests bounds pagination so a cursor that never ends cannot spin
// forever.
// At the API's maximum page size this is far more than any tenant holds.
const maxPageRequests = 200

// paging is the envelope every list endpoint returns.
type paging struct {
	MoreResults bool   `json:"moreResults"`
	NextToken   string `json:"nextToken"`
}

// Employee is one entry from the employee inventory.
type Employee struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	// KnownEmails holds the distinct addresses of the accounts this employee
	// owns. It is *not* a record of merged employees, and it is returned only
	// by GetEmployee — the list endpoint omits the field entirely.
	KnownEmails       []string `json:"knownEmails"`
	FirstName         string   `json:"firstName"`
	LastName          string   `json:"lastName"`
	Department        string   `json:"department"`
	Location          string   `json:"location"`
	Licensed          bool     `json:"licensed"`
	ChatopsEnabled    bool     `json:"chatopsEnabled"`
	Groups            []string `json:"groups"`
	CreationTimestamp int64    `json:"creationTimestamp"`
}

// EmployeeFilter narrows a ListEmployees call. Zero values are omitted, and
// filtering server-side rather than client-side keeps large tenants usable.
type EmployeeFilter struct {
	Email          string
	Groups         []string
	Licensed       *bool
	ChatopsEnabled *bool
}

func (f EmployeeFilter) query() url.Values {
	q := url.Values{}
	if f.Email != "" {
		q.Set("email", f.Email)
	}
	for _, g := range f.Groups {
		q.Add("groups", g)
	}
	if f.Licensed != nil {
		q.Set("licensed", strconv.FormatBool(*f.Licensed))
	}
	if f.ChatopsEnabled != nil {
		q.Set("chatopsEnabled", strconv.FormatBool(*f.ChatopsEnabled))
	}
	return q
}

type employeeListResponse struct {
	Result []Employee `json:"result"`
	Paging paging     `json:"paging"`
}

// ListEmployees returns every employee matching filter, following pagination.
func (c *Client) ListEmployees(ctx context.Context, filter EmployeeFilter) ([]Employee, error) {
	var out []Employee
	err := paginate(ctx, c, "/v1/employees", filter.query(), func(raw *employeeListResponse) paging {
		out = append(out, raw.Result...)
		return raw.Paging
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AppCategory is one of an app's categories. The code is what
// criteria.appCategories matches on; the name is what a person recognises.
type AppCategory struct {
	Code  int    `json:"code"`
	Name  string `json:"name"`
	Group string `json:"group"`
}

// App is one entry from the app inventory.
type App struct {
	ID                string        `json:"id"`
	Type              string        `json:"type"`
	FriendlyName      string        `json:"friendlyName"`
	ApprovalStatus    string        `json:"approvalStatus"`
	SensitivityLevel  string        `json:"sensitivityLevel"`
	OwnerID           string        `json:"ownerId"`
	Website           string        `json:"website"`
	Description       string        `json:"description"`
	Notes             string        `json:"notes"`
	Labels            []string      `json:"labels"`
	Categories        []AppCategory `json:"categories"`
	CreationTimestamp int64         `json:"creationTimestamp"`
}

type appListResponse struct {
	Result []App  `json:"result"`
	Paging paging `json:"paging"`
}

// ListApps returns every app in the tenant, following pagination.
//
// The endpoint offers only creation-timestamp filters, which are no use for
// looking things up by type or label, so filtering is left to the data source.
func (c *Client) ListApps(ctx context.Context) ([]App, error) {
	var out []App
	err := paginate(ctx, c, "/v1/apps", nil, func(raw *appListResponse) paging {
		out = append(out, raw.Result...)
		return raw.Paging
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// paginate walks a list endpoint to the end, calling collect for each page and
// using the paging value it returns to decide whether to continue.
//
// Generic over the response envelope so that each endpoint keeps its own typed
// shape rather than being decoded into map[string]any.
func paginate[T any](ctx context.Context, c *Client, path string, query url.Values, collect func(*T) paging) error {
	q := url.Values{}
	for k, vs := range query {
		q[k] = vs
	}

	for page := 0; ; page++ {
		if page >= maxPageRequests {
			return fmt.Errorf("%s: stopped after %d pages; the API kept reporting more results",
				path, maxPageRequests)
		}

		u := path
		if encoded := q.Encode(); encoded != "" {
			u += "?" + encoded
		}

		var raw T
		if err := c.get(ctx, u, &raw); err != nil {
			return err
		}

		p := collect(&raw)
		if !p.MoreResults || p.NextToken == "" {
			return nil
		}
		q.Set("nextToken", p.NextToken)
	}
}
