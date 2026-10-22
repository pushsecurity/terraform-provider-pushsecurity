package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/pushapi"
)

// employeeMergeResource implements pushsecurity_employee_merge: one person's second,
// third and fourth addresses attached to the record that represents them.
//
// The declarative reading of a merge cannot be "these records were merged",
// because the merge response does not say so (see employee_merge.go). It is
// **these addresses are not separate employees**. That invariant is
// observable, it is what a merge achieves, and it is what this resource
// enforces: if an address that was merged is created again by an HR sync or a
// new sign-in, the next plan proposes to merge it again rather than reporting
// that everything is fine.
//
// Destroying the resource does not undo the merge, and says so.
type employeeMergeResource struct {
	client   *pushapi.Client
	resolver *employeeResolver
}

var (
	_ resource.Resource                   = &employeeMergeResource{}
	_ resource.ResourceWithConfigure      = &employeeMergeResource{}
	_ resource.ResourceWithImportState    = &employeeMergeResource{}
	_ resource.ResourceWithModifyPlan     = &employeeMergeResource{}
	_ resource.ResourceWithValidateConfig = &employeeMergeResource{}
)

func newEmployeeMergeResource() resource.Resource { return &employeeMergeResource{} }

type employeeMergeModel struct {
	PrimaryEmail      types.String `tfsdk:"primary_email"`
	SecondaryEmails   types.Set    `tfsdk:"secondary_emails"`
	PrimaryEmployeeID types.String `tfsdk:"primary_employee_id"`
	PendingMerges     types.Set    `tfsdk:"pending_merges"`
}

func (r *employeeMergeResource) Metadata(_ context.Context, _ resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = "pushsecurity_employee_merge"
}

func (r *employeeMergeResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Merges an employee's other addresses — `.admin`, `.support`, a " +
			"personal alias, an address from a previous domain — into the record that " +
			"represents them, so that detections and controls see one person rather than " +
			"several.\n\n" +
			"~> **Terraform does not undo a merge.** `terraform destroy`, or removing an " +
			"address from `secondary_emails`, stops Terraform tracking the merge but leaves " +
			"the records merged. An address that had accounts of its own can be split out " +
			"again, as a new employee with a new identifier; an address that had none cannot. " +
			"Treat this resource as append-only.\n\n" +
			"A merge leaves no record of itself, so what this resource asserts is " +
			"that the addresses in `secondary_emails` **do not exist as separate employees**. " +
			"That is what a merge leaves behind, and it is checked on every refresh: an address " +
			"that comes back — recreated by an HR sync, or by somebody signing in with it — " +
			"appears in `pending_merges` and the next apply merges it again.",
		Attributes: map[string]schema.Attribute{
			"primary_email": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "The address of the employee everything else is merged into. " +
					"This record survives the merge; the others do not.\n\n" +
					"Changing it replaces the resource, which merges the same addresses into " +
					"somebody else. It does not move them back.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{emailLike()},
			},
			"secondary_emails": schema.SetAttribute{
				ElementType: types.StringType,
				Required:    true,
				MarkdownDescription: "The addresses to merge into `primary_email`. Addresses the " +
					"tenant does not hold are accepted and reported as a warning: after a merge " +
					"that is exactly what an address looks like, so it cannot be distinguished " +
					"from a typo.\n\n" +
					"The API merges five at a time; longer lists are sent as several requests.",
				Validators: []validator.Set{
					setvalidator.SizeBetween(1, 50),
					setvalidator.ValueStringsAre(emailLike()),
				},
			},
			"primary_employee_id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The identifier of the surviving employee record.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"pending_merges": schema.SetAttribute{
				ElementType: types.StringType,
				Computed:    true,
				MarkdownDescription: "The addresses from `secondary_emails` that currently exist " +
					"as separate employees, and will be merged by the next apply. Empty once the " +
					"merge has been performed, so a plan that shows an entry here is telling you " +
					"an address has come back.",
			},
		},
	}
}

func (r *employeeMergeResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client, r.resolver = providerClients(req.ProviderData, &resp.Diagnostics)
}

func (r *employeeMergeResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var cfg employeeMergeModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if cfg.PrimaryEmail.IsNull() || cfg.PrimaryEmail.IsUnknown() || cfg.SecondaryEmails.IsUnknown() {
		return
	}

	primary := normaliseEmail(cfg.PrimaryEmail.ValueString())
	for _, s := range stringCollection(cfg.SecondaryEmails) {
		if normaliseEmail(s) == primary {
			// The API rejects this outright, and it is worth catching at
			// validate: it usually means the wrong address was copied.
			resp.Diagnostics.AddAttributeError(
				path.Root("secondary_emails"),
				"An employee cannot be merged into themselves",
				fmt.Sprintf("%q is also primary_email.", s),
			)
		}
	}
}

func (r *employeeMergeResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	// Destroy, or create: nothing in state to reconcile against.
	if req.Plan.Raw.IsNull() || req.State.Raw.IsNull() {
		return
	}

	// After an apply nothing is outstanding. Planning that explicitly is what
	// turns an address that has come back into a visible change: refresh puts
	// it in pending_merges, and this plans it away again.
	empty, diags := stringSet(nil)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("pending_merges"), empty)...)
}

func (r *employeeMergeResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Provider not configured", "The Push API client is unavailable.")
		return
	}

	var plan employeeMergeModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	primaryID, matches, ok := r.resolve(ctx, plan, &resp.Diagnostics, true)
	if !ok {
		return
	}

	performMerges(ctx, r.client, r.resolver, matches, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.PrimaryEmployeeID = types.StringValue(primaryID)
	pending, diags := stringSet(nil)
	resp.Diagnostics.Append(diags...)
	plan.PendingMerges = pending
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *employeeMergeResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Provider not configured", "The Push API client is unavailable.")
		return
	}

	var state employeeMergeModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	primaryID, found, err := r.resolver.Lookup(ctx, state.PrimaryEmail.ValueString())
	if err != nil {
		addMergeAPIError(&resp.Diagnostics, state.PrimaryEmail.ValueString(), err)
		return
	}
	if !found {
		// The surviving record is gone: the employee was deleted, or merged
		// into somebody else. Either way this resource no longer describes
		// anything, and a plan should offer to start again.
		resp.State.RemoveResource(ctx)
		return
	}

	var outstanding []string
	for _, addr := range stringCollection(state.SecondaryEmails) {
		id, found, err := r.resolver.Lookup(ctx, addr)
		if err != nil {
			addMergeAPIError(&resp.Diagnostics, addr, err)
			return
		}
		if found && id != primaryID {
			outstanding = append(outstanding, addr)
		}
	}

	pending, diags := stringSet(outstanding)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	state.PrimaryEmployeeID = types.StringValue(primaryID)
	state.PendingMerges = pending
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *employeeMergeResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Provider not configured", "The Push API client is unavailable.")
		return
	}

	var plan, state employeeMergeModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// An address dropped from the configuration stays merged. Say so rather
	// than reporting a change that did not happen.
	if dropped := missingFrom(stringCollection(state.SecondaryEmails), stringCollection(plan.SecondaryEmails)); len(dropped) > 0 {
		resp.Diagnostics.AddAttributeWarning(
			path.Root("secondary_emails"),
			"Removed addresses stay merged",
			fmt.Sprintf("%s is no longer configured, but remains merged into %s.\n\n%s",
				strings.Join(dropped, ", "), plan.PrimaryEmail.ValueString(), mergeIrreversibleDetail),
		)
	}

	// Only addresses new to the configuration are worth a "not an employee"
	// warning: the ones already in state are absent because they were merged.
	added := missingFrom(stringCollection(plan.SecondaryEmails), stringCollection(state.SecondaryEmails))
	primaryID, matches, ok := r.resolve(ctx, plan, &resp.Diagnostics, false)
	if !ok {
		return
	}
	r.warnAbsent(&resp.Diagnostics, added, matches)

	performMerges(ctx, r.client, r.resolver, matches, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.PrimaryEmployeeID = types.StringValue(primaryID)
	pending, diags := stringSet(nil)
	resp.Diagnostics.Append(diags...)
	plan.PendingMerges = pending
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *employeeMergeResource) Delete(_ context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	// Nothing to call: Terraform does not undo a merge. The warning is the
	// whole of the delete, so that a destroy says it changed nothing.
	resp.Diagnostics.AddWarning("The employees stay merged", mergeIrreversibleDetail)
}

func (r *employeeMergeResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := strings.TrimSpace(req.ID)
	if !strings.Contains(id, "@") {
		resp.Diagnostics.AddError(
			"Invalid import identifier",
			"Import a merge by the primary employee's email address, for example "+
				"ada.lovelace@example.com.",
		)
		return
	}

	// An import cannot tell which addresses this resource is meant to cover,
	// so it adopts the primary, and the first plan merges whatever the
	// configuration names — which is a no-op for addresses that are already
	// merged.
	empty, diags := stringSet(nil)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("primary_email"), id)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("secondary_emails"), empty)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("pending_merges"), empty)...)
}

// resolve turns the configuration into the merges that are actually
// outstanding: the primary's identifier, and one match per secondary address
// that still exists as its own employee.
//
// warnAbsentAll reports every address the tenant does not hold, which is what
// a create wants; an update narrows that to the addresses it has just added.
func (r *employeeMergeResource) resolve(
	ctx context.Context,
	model employeeMergeModel,
	diags *diag.Diagnostics,
	warnAbsentAll bool,
) (string, []aliasMatch, bool) {
	primaryEmail := model.PrimaryEmail.ValueString()
	primaryID, found, err := r.resolver.Lookup(ctx, primaryEmail)
	if err != nil {
		addMergeAPIError(diags, primaryEmail, err)
		return "", nil, false
	}
	if !found {
		diags.AddAttributeError(
			path.Root("primary_email"),
			"No employee has this email address",
			fmt.Sprintf("%q is not an employee in this tenant. The primary is the record that "+
				"survives the merge, so it must exist.\n\nIf this address was itself merged into "+
				"somebody else, name that person as the primary instead.", primaryEmail),
		)
		return "", nil, false
	}

	secondaries := stringCollection(model.SecondaryEmails)
	var matches []aliasMatch
	for _, addr := range secondaries {
		id, found, err := r.resolver.Lookup(ctx, addr)
		if err != nil {
			addMergeAPIError(diags, addr, err)
			return "", nil, false
		}
		if !found || id == primaryID {
			// Already merged, or never existed. Both are the satisfied state.
			continue
		}
		matches = append(matches, aliasMatch{
			PrimaryEmail:   normaliseEmail(primaryEmail),
			PrimaryID:      primaryID,
			SecondaryEmail: normaliseEmail(addr),
			SecondaryID:    id,
		})
	}

	if warnAbsentAll {
		r.warnAbsent(diags, secondaries, matches)
	}
	return primaryID, matches, true
}

// warnAbsent reports configured addresses that are not employees.
//
// It cannot say whether they were merged already or misspelt — both leave no
// separate employee behind — so the warning says both.
func (r *employeeMergeResource) warnAbsent(diags *diag.Diagnostics, candidates []string, matches []aliasMatch) {
	mergeable := map[string]bool{}
	for _, m := range matches {
		mergeable[m.SecondaryEmail] = true
	}
	var absent []string
	for _, addr := range candidates {
		if !mergeable[normaliseEmail(addr)] {
			absent = append(absent, addr)
		}
	}
	if len(absent) == 0 {
		return
	}
	diags.AddAttributeWarning(
		path.Root("secondary_emails"),
		"Nothing to merge for some addresses",
		fmt.Sprintf("%s is not a separate employee in this tenant.\n\n"+
			"That is what an address looks like once it has been merged, so this is expected "+
			"for a merge that has already happened. It is also what a misspelt address looks "+
			"like, and the two cannot be told apart from the tenant. Check "+
			"the spelling if you expected work to be done.", strings.Join(absent, ", ")),
	)
}

// missingFrom compares addresses case-insensitively.
func missingFrom(a, b []string) []string {
	have := make(map[string]bool, len(b))
	for _, v := range b {
		have[normaliseEmail(v)] = true
	}
	var out []string
	for _, v := range a {
		if !have[normaliseEmail(v)] {
			out = append(out, v)
		}
	}
	return out
}

func normaliseEmail(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
