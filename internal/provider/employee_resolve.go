package provider

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/provider/controlspec"
	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/pushapi"
)

// employeeResolver translates between the email addresses configuration is
// written in and the opaque identifiers the API's employeeIds criterion
// matches on. A configuration that hard-codes UUIDs copied out of the console
// is neither readable nor reviewable in a pull request, which is the whole
// point of managing controls in version control.
//
// One resolver is shared by every resource in a run, because the reverse
// direction has no by-identifier endpoint and must enumerate the tenant. The
// enumeration happens at most once, and only if some identifier is not already
// known from a forward lookup.
type employeeResolver struct {
	client *pushapi.Client

	mu      sync.Mutex
	byEmail map[string]string // lowercased email -> identifier
	byID    map[string]string // identifier -> email, spelled as the API spells it
	listed  bool              // the whole tenant has been enumerated
}

func newEmployeeResolver(client *pushapi.Client) *employeeResolver {
	return &employeeResolver{
		client:  client,
		byEmail: map[string]string{},
		byID:    map[string]string{},
	}
}

// errNoSuchEmployee reports an email address the tenant does not hold. It is a
// configuration error: the address is a typo, or the person has left.
type errNoSuchEmployee struct{ Email string }

func (e errNoSuchEmployee) Error() string {
	return fmt.Sprintf("no employee has the email address %q", e.Email)
}

// errAmbiguousEmployee reports an email address that more than one employee
// holds exactly. An address is expected to belong to one employee, so this
// should not happen; it is checked rather than assumed because picking one
// would target the wrong person.
type errAmbiguousEmployee struct {
	Email string
	Count int
}

func (e errAmbiguousEmployee) Error() string {
	return fmt.Sprintf("%d employees have the email address %q", e.Count, e.Email)
}

// providerClients recovers the client and the shared resolver, which the
// resources that name employees need together. Both are nil until the
// provider is configured, as under `terraform validate`.
func providerClients(data any, diags *diag.Diagnostics) (*pushapi.Client, *employeeResolver) {
	d, err := unwrapProviderData(data)
	if err != nil {
		diags.AddError("Unexpected provider data", err.Error())
		return nil, nil
	}
	if d == nil {
		return nil, nil
	}
	return d.client, d.resolver
}

// IDForEmail resolves an address to its identifier, reporting one the tenant
// does not hold as errNoSuchEmployee. It costs what Lookup costs: usually one
// filtered request per distinct address, and one enumeration of the tenant
// when the filter does not find it.
func (r *employeeResolver) IDForEmail(ctx context.Context, email string) (string, error) {
	id, found, err := r.Lookup(ctx, email)
	switch {
	case err != nil:
		return "", err
	case !found:
		return "", errNoSuchEmployee{Email: email}
	}
	return id, nil
}

// Lookup resolves an email address, reporting a tenant that does not hold it
// as found=false rather than as an error.
//
// Merging needs that distinction: an address that is not an employee is the
// normal, satisfied state of a merge that has already happened, not a
// configuration mistake. IDForEmail keeps the error for the criteria paths,
// where it is one.
//
// The API filters by email, so an address the filter finds costs a single
// request however large the tenant is. The filter can miss an address the
// configuration spells in different case from the tenant, so one it does not
// find falls back to one enumeration of the tenant, which is cached for the
// rest of the run.
func (r *employeeResolver) Lookup(ctx context.Context, email string) (string, bool, error) {
	key := strings.ToLower(strings.TrimSpace(email))
	if key == "" {
		return "", false, nil
	}

	r.mu.Lock()
	if id, ok := r.byEmail[key]; ok {
		r.mu.Unlock()
		return id, true, nil
	}
	listed := r.listed
	r.mu.Unlock()

	// A completed enumeration is authoritative: if the address were held, it
	// would already be cached, so there is no point asking again.
	if listed {
		return "", false, nil
	}

	// Ask with the address lower-cased. A spelling the filter misses is
	// caught by the enumeration below.
	employees, err := r.client.ListEmployees(ctx, pushapi.EmployeeFilter{Email: key})
	if err != nil {
		return "", false, err
	}

	// The filter can return employees other than this one, so compare the
	// whole address.
	matches := withAddress(employees, key)

	switch len(matches) {
	case 1:
		r.mu.Lock()
		defer r.mu.Unlock()
		r.remember(matches[0])
		return matches[0].ID, true, nil

	case 0:
		// Not found by filter. Before concluding the tenant does not hold the
		// address, enumerate once: an address the tenant spells with capitals
		// can be missed by the filter but is present in the full list.
		if err := r.loadAll(ctx); err != nil {
			return "", false, err
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		id, ok := r.byEmail[key]
		return id, ok, nil

	default:
		return "", false, errAmbiguousEmployee{Email: email, Count: len(matches)}
	}
}

// withAddress returns the employees whose address is email, compared whole and
// ignoring case: what the API's email filter, which matches part of an address
// and minds its case, cannot be relied on to return by itself.
func withAddress(employees []pushapi.Employee, email string) []pushapi.Employee {
	var out []pushapi.Employee
	for _, e := range employees {
		if strings.EqualFold(e.Email, email) {
			out = append(out, e)
		}
	}
	return out
}

// Remember records an employee created during the run. Without it, a run that
// has already enumerated the tenant would report the new address as not held.
func (r *employeeResolver) Remember(e pushapi.Employee) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.remember(e)
}

// Forget exists because a merge destroys the secondary's record: anything
// resolved before it would otherwise be handed out afterwards as though the
// employee still existed.
func (r *employeeResolver) Forget(id, email string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.byID, id)
	delete(r.byEmail, strings.ToLower(strings.TrimSpace(email)))
	// The enumeration is no longer complete, so absence must be re-checked
	// against the API rather than inferred from the cache.
	r.listed = false
}

// EmailForID reports found=false for an identifier the tenant no longer
// holds, which is what an offboarded employee still named by a rule looks
// like. That is a warning rather than an error: the rule is real and still in
// force, and failing the refresh would leave no way to see or repair it.
func (r *employeeResolver) EmailForID(ctx context.Context, id string) (string, bool, error) {
	r.mu.Lock()
	if email, ok := r.byID[id]; ok {
		r.mu.Unlock()
		return email, true, nil
	}
	listed := r.listed
	r.mu.Unlock()

	if listed {
		return "", false, nil
	}

	if err := r.loadAll(ctx); err != nil {
		return "", false, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	email, ok := r.byID[id]
	return email, ok, nil
}

// loadAll is needed only by the reverse direction: the API offers no lookup
// by identifier.
func (r *employeeResolver) loadAll(ctx context.Context) error {
	employees, err := r.client.ListEmployees(ctx, pushapi.EmployeeFilter{})
	if err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range employees {
		r.remember(e)
	}
	r.listed = true
	return nil
}

// remember is called with the lock held.
func (r *employeeResolver) remember(e pushapi.Employee) {
	if e.ID == "" || e.Email == "" {
		return
	}
	r.byEmail[strings.ToLower(e.Email)] = e.ID
	r.byID[e.ID] = e.Email
}

// validateEmployeeEmails makes an address the tenant does not hold fail during
// plan rather than as a rejected write. The API has no dry-run endpoint, which
// is why the cross-field constraints are mirrored client-side; an unresolvable
// address is the same class of problem and is caught the same way. Resolutions
// are cached, so the apply that follows re-uses them.
//
// It does nothing when the provider is unconfigured, which is the case under
// `terraform validate`: there is no client to ask, and an offline check should
// not fail for it.
func validateEmployeeEmails(ctx context.Context, s controlspec.Spec, res *employeeResolver, rules types.List) diag.Diagnostics {
	var diags diag.Diagnostics
	if res == nil || rules.IsNull() || rules.IsUnknown() {
		return diags
	}

	criterion, ok := emailCriterion(s)
	if !ok {
		return diags
	}

	for i, e := range rules.Elements() {
		rule, ok := e.(types.Object)
		if !ok || rule.IsNull() || rule.IsUnknown() {
			continue
		}
		crit, ok := rule.Attributes()["criteria"].(types.Object)
		if !ok || crit.IsNull() || crit.IsUnknown() {
			continue
		}
		cond, ok := crit.Attributes()[criterion.Name].(types.Object)
		if !ok || cond.IsNull() || cond.IsUnknown() {
			continue
		}
		matches, ok := cond.Attributes()["matches"].(types.Set)
		if !ok || matches.IsNull() || matches.IsUnknown() {
			continue
		}

		emails := stringCollection(matches)
		if len(emails) == 0 {
			continue
		}
		at := path.Root("rules").AtListIndex(i).
			AtName("criteria").AtName(criterion.Name).AtName("matches")
		_, d := resolveEmails(ctx, res, emails, at)
		diags.Append(d...)
	}

	return diags
}

func emailCriterion(s controlspec.Spec) (controlspec.Criterion, bool) {
	for _, c := range s.Criteria {
		if c.ResolvesEmails() {
			return c, true
		}
	}
	return controlspec.Criterion{}, false
}
