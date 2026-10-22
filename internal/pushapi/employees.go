package pushapi

import (
	"context"
	"errors"
	"net/url"
)

// Employee merging attaches one employee record to another: each secondary's
// accounts, and the findings raised against them, move onto the primary, and
// the secondary record is deleted.
//
// Three properties of the endpoint shape everything the provider does with it:
//
//   - The merge is not recorded as such. `knownEmails` is not merge history:
//     it holds the distinct addresses of the accounts the employee owns, so a
//     merged address appears there only if it had accounts of its own. The
//     one lasting sign of a merge is that the secondary is no longer an
//     employee.
//   - A merge response does not confirm that a merge happened. The endpoint
//     answers 200 with the primary's record for a secondary identifier that
//     has already been merged away, or that does not exist; it rejects only a
//     request that names the primary among the secondaries.
//   - It can be undone only in part. `/unmerge` takes an address that is among
//     the employee's `knownEmails` and is not its primary email, and splits it
//     out as a licensed employee with a new identifier (or onto an existing
//     record for that address), which needs a free licence seat. A merged
//     address that had no accounts is not among
//     `knownEmails`, so it cannot be split out.
//
// So the provider resolves addresses itself, and confirms a merge by reading
// the secondary back and expecting it to be gone.

// MaxMergeSecondaries is the number of secondary employees the merge endpoint
// accepts in one request. Larger sets are sent as several requests.
const MaxMergeSecondaries = 5

// GetEmployee reads one employee. Unlike the list endpoint, it populates
// KnownEmails.
func (c *Client) GetEmployee(ctx context.Context, id string) (*Employee, error) {
	if id == "" {
		return nil, errors.New("employee id is required")
	}
	var out Employee
	if err := c.get(ctx, "/v1/employees/"+url.PathEscape(id), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// MergeEmployees merges secondaryIDs into the employee identified by
// primaryID, in requests of at most MaxMergeSecondaries.
//
// The returned employee is the primary as the last request reported it. It is
// not evidence that anything was merged: see the note above.
func (c *Client) MergeEmployees(ctx context.Context, primaryID string, secondaryIDs []string) (*Employee, error) {
	if primaryID == "" {
		return nil, errors.New("primary employee id is required")
	}
	if len(secondaryIDs) == 0 {
		return nil, errors.New("at least one secondary employee id is required")
	}

	path := "/v1/employees/" + url.PathEscape(primaryID) + "/merge"
	var out Employee
	for start := 0; start < len(secondaryIDs); start += MaxMergeSecondaries {
		end := min(start+MaxMergeSecondaries, len(secondaryIDs))
		body := struct {
			SecondaryEmployeeIDs []string `json:"secondaryEmployeeIds"`
		}{SecondaryEmployeeIDs: secondaryIDs[start:end]}

		if err := c.post(ctx, path, body, &out); err != nil {
			return nil, err
		}
	}
	return &out, nil
}

// NewEmployee is the payload for creating an employee.
type NewEmployee struct {
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Email     string `json:"email"`
	// EnrolBrowser asks Push to email the person about installing the browser
	// extension. Anything automated should leave this false.
	EnrolBrowser bool `json:"enrolBrowser"`
}

// CreateEmployee creates an employee, which the API licenses automatically.
// pushsecurity_employee calls it for an address that is not yet in the tenant, and
// the merge acceptance tests use it for records of their own. The endpoint is
// an upsert: an address that already exists comes back with its existing
// identifier rather than an error.
func (c *Client) CreateEmployee(ctx context.Context, e NewEmployee) (*Employee, error) {
	var out Employee
	if err := c.post(ctx, "/v1/employees", e, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// EmployeeUpdate is the set of employee attributes that can be changed.
// Nil fields are left alone.
type EmployeeUpdate struct {
	FirstName *string `json:"firstName,omitempty"`
	LastName  *string `json:"lastName,omitempty"`
	// Licensed set to false is destructive: it deletes the employee record
	// together with its accounts, findings and browsers. The API answers 200
	// with a null body, and the identifier stops resolving. Nothing in this
	// provider sends it without the practitioner having asked for it by name.
	Licensed *bool `json:"licensed,omitempty"`
}

// UpdateEmployee changes the attributes u sets on one employee. It returns
// nothing: the API answers with a null body when Licensed is set to false, so
// the caller reads the employee back rather than trusting the response.
func (c *Client) UpdateEmployee(ctx context.Context, id string, u EmployeeUpdate) error {
	if id == "" {
		return errors.New("employee id is required")
	}
	return c.patch(ctx, "/v1/employees/"+url.PathEscape(id), u, nil)
}
