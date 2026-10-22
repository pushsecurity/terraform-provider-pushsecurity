package provider

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/pushapi"
)

// employeeResource implements pushsecurity_employee: an employee record, and whether
// they hold a licence.
//
// Licensing is the whole point of the resource, and it is asymmetric in a way
// that decides the design. Granting a licence is ordinary. **Removing one
// deletes the employee record together with the employee's accounts, the
// findings raised against them and their browsers.** That is data loss no plan
// output makes obvious, and an ordinary Terraform resource reaches it two ways
// without anybody typing it: `terraform destroy`, and a resource dropped from
// the configuration.
//
// So this resource does not treat unlicensing as the inverse of licensing:
//
//   - Destroy never unlicenses. It stops managing the employee and says so.
//   - `licensed = false` is refused unless `allow_unlicense = true` is set
//     alongside it, which is a sentence somebody has to write on purpose.
//
// What it will do freely is adopt an existing employee, grant a licence, and
// correct a name — none of which destroys anything.
type employeeResource struct {
	client   *pushapi.Client
	resolver *employeeResolver
}

var (
	_ resource.Resource                   = &employeeResource{}
	_ resource.ResourceWithConfigure      = &employeeResource{}
	_ resource.ResourceWithImportState    = &employeeResource{}
	_ resource.ResourceWithValidateConfig = &employeeResource{}
)

func newEmployeeResource() resource.Resource { return &employeeResource{} }

type employeeModel struct {
	Email          types.String `tfsdk:"email"`
	FirstName      types.String `tfsdk:"first_name"`
	LastName       types.String `tfsdk:"last_name"`
	Licensed       types.Bool   `tfsdk:"licensed"`
	AllowUnlicense types.Bool   `tfsdk:"allow_unlicense"`
	EmployeeID     types.String `tfsdk:"employee_id"`
	Groups         types.Set    `tfsdk:"groups"`
}

func (r *employeeResource) Metadata(_ context.Context, _ resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = "pushsecurity_employee"
}

func (r *employeeResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages an employee record and whether they hold a Push licence.\n\n" +
			"An address the tenant already holds is **adopted**: the resource takes over the " +
			"attributes you set and leaves the rest alone. An address it does not hold is " +
			"created, which needs `first_name` and `last_name` and consumes a licence — the " +
			"API licenses new employees automatically. The one address that is neither " +
			"adopted nor created is one the tenant does not hold and `licensed = false` " +
			"describes: nothing is sent, `employee_id` stays null, and a warning says the " +
			"block can be removed.\n\n" +
			"~> **Removing a licence destroys data.** It deletes the employee record, the " +
			"employee's accounts, the findings raised against them and their browsers. So " +
			"`licensed = false` needs `allow_unlicense = true` beside it, and " +
			"`terraform destroy` never unlicenses anybody — it stops managing them and warns. " +
			"Removing this resource from your configuration leaves the employee exactly as " +
			"they are.",
		Attributes: map[string]schema.Attribute{
			"email": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "The employee's primary email address, which is how this " +
					"resource finds them, compared ignoring case. Changing it replaces the " +
					"resource: it adopts or creates a different person, and leaves the previous " +
					"one untouched. Changing only its case does not.",
				PlanModifiers: []planmodifier.String{
					// The tenant compares addresses ignoring case, so respelling
					// one, or importing it as the console spells it, is the same
					// person and an update in place.
					stringplanmodifier.RequiresReplaceIf(
						func(_ context.Context, req planmodifier.StringRequest, resp *stringplanmodifier.RequiresReplaceIfFuncResponse) {
							resp.RequiresReplace = normaliseEmail(req.StateValue.ValueString()) !=
								normaliseEmail(req.PlanValue.ValueString())
						},
						"Replaces the resource when the address changes other than in case.",
						"Replaces the resource when the address changes other than in case.",
					),
				},
				Validators: []validator.String{emailLike()},
			},
			"licensed": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				MarkdownDescription: "Whether the employee holds a licence. Leave it unset to " +
					"adopt whatever the tenant has without managing it.\n\n" +
					"Setting it to `false` deletes the employee record along with their " +
					"accounts, findings and browsers, so it is refused unless `allow_unlicense` " +
					"is also `true`. Once applied, the address is no longer in the tenant, and an " +
					"address the tenant does not hold is left that way: the resource then " +
					"holds no `employee_id`, plans nothing, and can be removed.",
				PlanModifiers: []planmodifier.Bool{fromStateWhileHeld{}},
			},
			"allow_unlicense": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
				MarkdownDescription: "Permits `licensed = false` to be applied. Without it, a " +
					"configuration that would remove a licence fails during plan, naming what " +
					"would be deleted.\n\n" +
					"It never causes anything on its own: it only unlocks a `licensed = false` " +
					"you have already written.",
			},
			"first_name": schema.StringAttribute{
				Optional: true,
				Computed: true,
				MarkdownDescription: "The employee's first name. Required when the address is " +
					"not already in the tenant, because creating an employee needs one.",
				PlanModifiers: []planmodifier.String{fromStateWhileHeld{}},
			},
			"last_name": schema.StringAttribute{
				Optional: true,
				Computed: true,
				MarkdownDescription: "The employee's last name. Required when the address is " +
					"not already in the tenant.",
				PlanModifiers: []planmodifier.String{fromStateWhileHeld{}},
			},
			"employee_id": schema.StringAttribute{
				Computed: true,
				MarkdownDescription: "The identifier the API holds for this employee. Null " +
					"when there is no record to identify: an address `licensed = false` " +
					"describes that the tenant does not hold, which is where unlicensing " +
					"leaves an employee. After an apply that unlicenses, it is cleared by the " +
					"next refresh.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"groups": schema.SetAttribute{
				ElementType: types.StringType,
				Computed:    true,
				MarkdownDescription: "The groups the employee is in, as used by the " +
					"`employee_groups` criterion. Read-only here: groups come from the " +
					"tenant's directory integrations, and this provider does not overwrite them.",
				PlanModifiers: []planmodifier.Set{fromStateWhileHeld{}},
			},
		},
	}
}

func (r *employeeResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client, r.resolver = providerClients(req.ProviderData, &resp.Diagnostics)
}

func (r *employeeResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var cfg employeeModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Caught here rather than at apply, so that the answer arrives while
	// somebody is reading a plan rather than after the accounts are gone.
	if cfg.Licensed.Equal(types.BoolValue(false)) && !cfg.AllowUnlicense.Equal(types.BoolValue(true)) {
		resp.Diagnostics.AddAttributeError(
			path.Root("licensed"),
			"Removing a licence deletes the employee, their accounts and their findings",
			"licensed = false does not simply free a seat: the API deletes every account "+
				"Push holds for this employee, every finding raised against them, their "+
				"browsers, and the employee record itself. None of it comes back.\n\n"+
				"If that is what you want, say so explicitly:\n\n"+
				"    licensed        = false\n"+
				"    allow_unlicense = true\n",
		)
	}
}

func (r *employeeResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Provider not configured", "The Push API client is unavailable.")
		return
	}

	var plan employeeModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	r.ensure(ctx, &plan, employeeModel{}, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *employeeResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Provider not configured", "The Push API client is unavailable.")
		return
	}

	var state employeeModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	id := state.EmployeeID.ValueString()
	if id == "" {
		var found bool
		var err error
		id, found, err = r.resolver.Lookup(ctx, state.Email.ValueString())
		if err != nil {
			addEmployeeAPIError(&resp.Diagnostics, state.Email.ValueString(), err)
			return
		}
		if !found {
			r.readAbsent(ctx, state, resp)
			return
		}
	}

	employee, err := r.client.GetEmployee(ctx, id)
	if err != nil {
		if pushapi.NotFound(err) {
			r.readAbsent(ctx, state, resp)
			return
		}
		addEmployeeAPIError(&resp.Diagnostics, state.Email.ValueString(), err)
		return
	}

	resp.Diagnostics.Append(setEmployeeState(&state, employee)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// readAbsent refreshes a resource whose employee the tenant no longer holds.
//
// Usually that means the record is gone for a reason this resource was not
// told about — unlicensed in the console, or merged into somebody else — and
// the resource is removed so that the next plan says so.
//
// The exception is an employee the state already records as unlicensed.
// Unlicensing deletes the employee record, so "absent" is what
// `licensed = false` looks like once it has been applied, and the resource is
// satisfied rather than drifted. Removing it would make the next
// plan propose creating them, only for the apply to find the address absent
// again, and that on every run. The state is kept, with no identifier because
// there is no record; readInto could not do the same on the apply itself,
// because the identifier was already known to the plan.
//
// Read has the state and not the configuration, so an employee adopted while
// unlicensed whose record then disappears is kept too. That costs nothing: a
// plan for them is empty, and a later `licensed = true` finds no record and
// creates one.
func (r *employeeResource) readAbsent(ctx context.Context, state employeeModel, resp *resource.ReadResponse) {
	if !state.Licensed.Equal(types.BoolValue(false)) {
		resp.State.RemoveResource(ctx)
		return
	}
	state.EmployeeID = types.StringNull()
	resp.Diagnostics.Append(markAbsent(&state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *employeeResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Provider not configured", "The Push API client is unavailable.")
		return
	}

	var config, plan, state employeeModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	planned := plan
	r.ensure(ctx, &plan, state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	keepUnconfigured(&plan, planned, config)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// keepUnconfigured restores the planned value of each attribute the
// configuration leaves out, which fromStateWhileHeld planned as the value in
// state. A change made in the console, or by a directory sync, between plan
// and apply then surfaces on the next refresh instead of failing this apply as
// an inconsistent result. A configured attribute keeps what the tenant holds,
// so a value it did not take is reported rather than hidden.
func keepUnconfigured(model *employeeModel, planned, config employeeModel) {
	if config.FirstName.IsNull() && !planned.FirstName.IsUnknown() {
		model.FirstName = planned.FirstName
	}
	if config.LastName.IsNull() && !planned.LastName.IsUnknown() {
		model.LastName = planned.LastName
	}
	if config.Licensed.IsNull() && !planned.Licensed.IsUnknown() {
		model.Licensed = planned.Licensed
	}
	if !planned.Groups.IsUnknown() {
		model.Groups = planned.Groups
	}
}

// ensure brings the tenant into line with plan and fills in plan's computed
// attributes from the result. prior is the state being updated from, or the
// zero value on create.
//
// Create and Update share it because the difference between them is not where
// the record is: a resource in state can describe an employee the tenant does
// not hold (see readAbsent), and a resource being created can describe one it
// already does. What matters is whether the address resolves.
func (r *employeeResource) ensure(ctx context.Context, plan *employeeModel, prior employeeModel, diags *diag.Diagnostics) {
	email := plan.Email.ValueString()

	id := prior.EmployeeID.ValueString()
	if id == "" {
		var found bool
		var err error
		id, found, err = r.resolver.Lookup(ctx, email)
		if err != nil {
			addEmployeeAPIError(diags, email, err)
			return
		}
		if !found {
			if wantsUnlicensed(*plan) {
				// The record would only be created to be deleted again: the
				// API licenses a new employee, and unlicensing deletes the
				// record. Nothing is sent, and the resource
				// records what the tenant holds, which is nothing. The opt-in
				// is still required, so that the rule stays one rule.
				if !plan.AllowUnlicense.ValueBool() {
					diags.AddAttributeError(
						path.Root("licensed"),
						"Removing a licence deletes the employee's accounts and findings",
						"Set allow_unlicense = true to permit it.",
					)
					return
				}
				plan.EmployeeID = types.StringNull()
				diags.Append(markAbsent(plan)...)
				diags.AddWarning(
					"This employee does not exist, so there is nothing to unlicense",
					fmt.Sprintf("%q is not in the tenant, and licensed = false asks for exactly "+
						"that, so no request was made and employee_id is null.\n\nThis resource "+
						"block can be removed. While it stays, an employee who reappears at this "+
						"address will be unlicensed again by the next apply.", email),
				)
				return
			}
			var ok bool
			if id, ok = r.create(ctx, *plan, diags); !ok {
				return
			}
		}
	}

	r.applyAttributes(ctx, id, *plan, prior, diags)
	if diags.HasError() {
		return
	}
	diags.Append(r.readInto(ctx, id, plan)...)
}

// create makes the employee plan describes, which needs a name, and returns
// the new identifier. The API licenses new employees automatically.
func (r *employeeResource) create(ctx context.Context, plan employeeModel, diags *diag.Diagnostics) (string, bool) {
	email := plan.Email.ValueString()
	if plan.FirstName.IsNull() || plan.FirstName.IsUnknown() ||
		plan.LastName.IsNull() || plan.LastName.IsUnknown() {
		diags.AddAttributeError(
			path.Root("first_name"),
			"This employee does not exist yet, so creating them needs a name",
			fmt.Sprintf("%q is not in the tenant. To create them, set first_name and "+
				"last_name. To adopt somebody who is already there, check the address.",
				email),
		)
		return "", false
	}
	created, err := r.client.CreateEmployee(ctx, pushapi.NewEmployee{
		FirstName: plan.FirstName.ValueString(),
		LastName:  plan.LastName.ValueString(),
		Email:     email,
		// Never true. An apply that emails people is not something a plan
		// shows, and this provider does not send mail.
		EnrolBrowser: false,
	})
	if err != nil {
		addEmployeeAPIError(diags, email, err)
		return "", false
	}
	remembered := *created
	if remembered.Email == "" {
		remembered.Email = email
	}
	r.resolver.Remember(remembered)
	diags.AddWarning(
		"Created a new employee",
		fmt.Sprintf("%q was not in the tenant, so it was created. The API licenses a new "+
			"employee automatically, which uses a seat.", email),
	)
	return created.ID, true
}

// wantsUnlicensed reports whether plan asks, in so many words, for the
// employee not to hold a licence. An unset `licensed` does not count: it means
// adopt whatever the tenant has.
func wantsUnlicensed(plan employeeModel) bool {
	return plan.Licensed.Equal(types.BoolValue(false))
}

// markAbsent fills a model's computed attributes for an employee the tenant
// does not hold: no licence, no groups, and whatever names were given. The
// identifier is the caller's to set, because what it may be depends on
// whether the plan already fixed it.
func markAbsent(model *employeeModel) diag.Diagnostics {
	var diags diag.Diagnostics
	if model.Licensed.IsUnknown() {
		model.Licensed = types.BoolValue(false)
	}
	if model.Groups.IsNull() || model.Groups.IsUnknown() {
		groups, d := stringSet(nil)
		diags.Append(d...)
		model.Groups = groups
	}
	if model.FirstName.IsUnknown() {
		model.FirstName = types.StringValue("")
	}
	if model.LastName.IsUnknown() {
		model.LastName = types.StringValue("")
	}
	return diags
}

// Delete stops managing the employee. It deliberately calls nothing.
//
// The only "delete" this API has is unlicensing, which deletes the employee
// record together with its accounts, findings and browsers.
// Reaching that by removing a resource block, or by a destroy that was meant
// to clean up some other part of a configuration, is not a trade anybody would
// make on purpose.
func (r *employeeResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state employeeModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	resp.Diagnostics.AddWarning(
		"The employee is left exactly as they are",
		fmt.Sprintf("Terraform has stopped managing %s. Their licence, accounts and findings "+
			"are untouched.\n\nThis provider will not unlicense an employee on destroy: that "+
			"deletes every account Push holds for them, every finding raised against them and "+
			"their browsers. To do it deliberately, set licensed = false with "+
			"allow_unlicense = true and apply that before removing the resource.", state.Email.ValueString()),
	)
}

func (r *employeeResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("email"), req, resp)
	// allow_unlicense is provider-side only, so the read that follows cannot
	// supply it. Left null, the first plan after an import would be an update
	// that sets it to its default and changes nothing.
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("allow_unlicense"), types.BoolValue(false))...)
}

// applyAttributes sends the attributes that differ from what the tenant holds.
//
// prior is the state being updated from, or the zero value on create; it is
// only used to avoid sending a PATCH that would change nothing.
func (r *employeeResource) applyAttributes(ctx context.Context, id string, plan, prior employeeModel, diags *diag.Diagnostics) {
	var update pushapi.EmployeeUpdate
	changed := false

	if !plan.FirstName.IsNull() && !plan.FirstName.IsUnknown() && !plan.FirstName.Equal(prior.FirstName) {
		v := plan.FirstName.ValueString()
		update.FirstName = &v
		changed = true
	}
	if !plan.LastName.IsNull() && !plan.LastName.IsUnknown() && !plan.LastName.Equal(prior.LastName) {
		v := plan.LastName.ValueString()
		update.LastName = &v
		changed = true
	}
	if !plan.Licensed.IsNull() && !plan.Licensed.IsUnknown() && !plan.Licensed.Equal(prior.Licensed) {
		v := plan.Licensed.ValueBool()
		if !v && !plan.AllowUnlicense.ValueBool() {
			// ValidateConfig catches this while it is still configuration;
			// this is the belt to that pair of braces, for a value that
			// arrives from an interpolation.
			diags.AddAttributeError(
				path.Root("licensed"),
				"Removing a licence deletes the employee, their accounts and their findings",
				"Set allow_unlicense = true to permit it.",
			)
			return
		}
		if !v {
			// Unlicensing goes alone. The API deletes the record on a PATCH
			// that carries licensed = false and applies nothing else in the
			// same body, so a name sent alongside would be dropped, and there
			// would be no record left to hold it anyway.
			update = pushapi.EmployeeUpdate{Licensed: &v}
		} else {
			update.Licensed = &v
		}
		changed = true
	}

	if !changed {
		return
	}
	if err := r.client.UpdateEmployee(ctx, id, update); err != nil {
		addEmployeeAPIError(diags, plan.Email.ValueString(), err)
		return
	}

	if update.Licensed != nil && !*update.Licensed {
		// The record is gone, so the run must not hand out its identifier.
		r.resolver.Forget(id, plan.Email.ValueString())
		diags.AddWarning(
			"Licence removed, and with it the employee, their accounts and their findings",
			fmt.Sprintf("%s has been unlicensed. Push has deleted the employee record, the "+
				"accounts it held for them, the findings raised against them and their browsers. "+
				"The resource stays, satisfied; the next refresh clears its employee_id, and "+
				"the block can be removed.",
				plan.Email.ValueString()),
		)
	}
}

// readInto tolerates an employee that has just been unlicensed, and so no
// longer exists: the attributes keep the values that were applied, and the
// identifier stays what the plan said it would be. The next refresh notices
// the record is gone and keeps the resource as satisfied (see readAbsent).
func (r *employeeResource) readInto(ctx context.Context, id string, model *employeeModel) diag.Diagnostics {
	var diags diag.Diagnostics
	employee, err := r.client.GetEmployee(ctx, id)
	if err != nil {
		if pushapi.NotFound(err) {
			model.EmployeeID = types.StringValue(id)
			diags.Append(markAbsent(model)...)
			return diags
		}
		addEmployeeAPIError(&diags, model.Email.ValueString(), err)
		return diags
	}
	diags.Append(setEmployeeState(model, employee)...)
	return diags
}

// setEmployeeState copies an employee onto the model, leaving `email` as the
// configuration spells it so that an apply does not report a change nobody
// made.
func setEmployeeState(model *employeeModel, e *pushapi.Employee) diag.Diagnostics {
	var diags diag.Diagnostics
	model.EmployeeID = types.StringValue(e.ID)
	model.FirstName = types.StringValue(e.FirstName)
	model.LastName = types.StringValue(e.LastName)
	model.Licensed = types.BoolValue(e.Licensed)

	elems := make([]attr.Value, 0, len(e.Groups))
	for _, g := range e.Groups {
		elems = append(elems, types.StringValue(g))
	}
	groups, d := types.SetValue(types.StringType, elems)
	diags.Append(d...)
	model.Groups = groups
	return diags
}

func addEmployeeAPIError(diags *diag.Diagnostics, subject string, err error) {
	var apiErr *pushapi.APIError
	if errors.As(err, &apiErr) && apiErr.Status == "EXCEEDED_MAX_LICENSED_EMPLOYEES" {
		// Both granting a licence and creating an employee (whom the API
		// licenses automatically) are refused once the tenant's seats are
		// all taken, and the API checks that before looking at the address.
		diags.AddAttributeError(path.Root("licensed"), "The tenant has no licence seats left",
			fmt.Sprintf("Could not manage %q: %v\n\nEvery licence the tenant holds is in use, "+
				"so neither licensing this employee nor creating them is possible until a "+
				"seat is freed or more are added.", subject, err))
		return
	}
	if fields, ok := pushapi.Validation(err); ok && len(fields) > 0 {
		addFieldErrors(diags, "Push API rejected the employee", fields, map[string]string{
			"email":     "email",
			"firstName": "first_name",
			"lastName":  "last_name",
			"licensed":  "licensed",
		})
		return
	}
	addRequestFailure(diags, fmt.Sprintf("manage %q", subject), err)
}

// fromStateWhileHeld plans an attribute the configuration leaves out as the
// value in state, rather than as unknown, while the state names an employee
// record, so that an update shows only what it changes.
//
// It holds only while there is a record. An update of an employee the state
// identifies sends nothing for an attribute that is not configured, so the
// attribute changes only if the tenant changes it. Without a record, the
// update looks the address up afresh and may create the employee, which sets
// every one of these anew.
type fromStateWhileHeld struct{}

func (fromStateWhileHeld) Description(context.Context) string {
	return "Keeps the value in state while the resource identifies an employee record."
}

func (m fromStateWhileHeld) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (fromStateWhileHeld) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	if req.PlanValue.IsUnknown() && !req.ConfigValue.IsUnknown() && !req.StateValue.IsNull() && recordHeld(ctx, req.State) {
		resp.PlanValue = req.StateValue
	}
}

func (fromStateWhileHeld) PlanModifyBool(ctx context.Context, req planmodifier.BoolRequest, resp *planmodifier.BoolResponse) {
	if req.PlanValue.IsUnknown() && !req.ConfigValue.IsUnknown() && !req.StateValue.IsNull() && recordHeld(ctx, req.State) {
		resp.PlanValue = req.StateValue
	}
}

func (fromStateWhileHeld) PlanModifySet(ctx context.Context, req planmodifier.SetRequest, resp *planmodifier.SetResponse) {
	if req.PlanValue.IsUnknown() && !req.ConfigValue.IsUnknown() && !req.StateValue.IsNull() && recordHeld(ctx, req.State) {
		resp.PlanValue = req.StateValue
	}
}

// recordHeld reports whether the state identifies an employee record.
func recordHeld(ctx context.Context, state tfsdk.State) bool {
	if state.Raw.IsNull() {
		return false
	}
	var id types.String
	if diags := state.GetAttribute(ctx, path.Root("employee_id"), &id); diags.HasError() {
		return false
	}
	return !id.IsNull() && !id.IsUnknown() && id.ValueString() != ""
}
