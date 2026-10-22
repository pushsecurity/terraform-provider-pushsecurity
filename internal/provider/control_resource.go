package provider

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/provider/controlspec"
	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/pushapi"
)

// controlResource implements every rule-based control configuration resource.
// One instance per Spec; the behaviour is identical across all sixteen.
type controlResource struct {
	spec     controlspec.Spec
	client   *pushapi.Client
	resolver *employeeResolver
}

var (
	_ resource.Resource                   = &controlResource{}
	_ resource.ResourceWithConfigure      = &controlResource{}
	_ resource.ResourceWithImportState    = &controlResource{}
	_ resource.ResourceWithValidateConfig = &controlResource{}
)

func newControlResource(spec controlspec.Spec) func() resource.Resource {
	return func() resource.Resource { return &controlResource{spec: spec} }
}

func (r *controlResource) Metadata(_ context.Context, _ resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = r.spec.ResourceName()
}

func (r *controlResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = buildSchema(r.spec)
}

func (r *controlResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	client, err := clientFromProviderData(req.ProviderData)
	if err != nil {
		resp.Diagnostics.AddError("Unexpected provider data", err.Error())
		return
	}
	// nil on the framework's first Configure pass, before the provider itself
	// is configured. Not an error.
	r.client = client

	resolver, err := resolverFromProviderData(req.ProviderData)
	if err != nil {
		resp.Diagnostics.AddError("Unexpected provider data", err.Error())
		return
	}
	// Shared across every resource in the run: reversing an identifier has to
	// enumerate the tenant, and once is enough.
	r.resolver = resolver
}

// ValidateConfig mirrors the API's cross-field rules, which has no dry-run
// endpoint: without this, a configuration that violates a mode-dependent
// requirement is only rejected at apply — which, in the pipeline this provider
// exists to enable, is after the pull request has merged.
func (r *controlResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	if len(r.spec.Globals) > 0 {
		var globals types.Object
		resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("globals"), &globals)...)
		if resp.Diagnostics.HasError() {
			return
		}
		resp.Diagnostics.Append(validateGlobals(r.spec, globals)...)
	}

	var rules types.List
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("rules"), &rules)...)
	if resp.Diagnostics.HasError() || rules.IsNull() || rules.IsUnknown() {
		return
	}
	resp.Diagnostics.Append(validateRules(r.spec, rules)...)
	resp.Diagnostics.Append(validateKeysUnique(rules)...)
	resp.Diagnostics.Append(validateEmployeeEmails(ctx, r.spec, r.resolver, rules)...)
}

func (r *controlResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	// Create and Update are the same operation: the API has only PUT, and it
	// replaces the whole document. The one difference is that there is no prior
	// state to carry identifiers from, so every rule is created.
	r.write(ctx, req.Plan, nil, &resp.State, &resp.Diagnostics)
}

func (r *controlResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	prior, diags := priorRulesFromState(ctx, r.spec, req.State)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.write(ctx, req.Plan, prior, &resp.State, &resp.Diagnostics)
}

func (r *controlResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Provider not configured", "The Push API client is unavailable.")
		return
	}

	prior, diags := priorRulesFromState(ctx, r.spec, req.State)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	// Keys live only in state; the API does not store them. Preserve them
	// across a refresh by identifier.
	keys := make(map[string]string, len(prior))
	// Email addresses are state's spelling of what the API stores as
	// identifiers, and the only record of an employee the tenant has since
	// dropped. Carry them the same way.
	emails := make(map[string][]string, len(prior))
	for _, p := range prior {
		if p.ID == "" {
			continue
		}
		if p.Key != "" {
			keys[p.ID] = p.Key
		}
		if len(p.Emails) > 0 {
			emails[p.ID] = p.Emails
		}
	}

	cfg, err := r.get(ctx)
	if err != nil {
		r.addAPIError(&resp.Diagnostics, "read", err)
		return
	}

	resp.Diagnostics.Append(r.setState(ctx, &resp.State, cfg, keys, emails)...)
}

func (r *controlResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Provider not configured", "The Push API client is unavailable.")
		return
	}

	// A control cannot be removed, only emptied. Destroying the resource writes
	// an empty document: no rules, default control-wide settings. This is
	// documented on every resource page because it is not what destroy usually
	// implies.
	tflog.Debug(ctx, "emptying control configuration", map[string]any{"control": r.spec.APIName})
	if _, err := r.put(ctx, &pushapi.ControlConfig{}); err != nil {
		r.addAPIError(&resp.Diagnostics, "delete", err)
	}
}

func (r *controlResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Configuration resources are singletons: there is one configuration per
	// control per tenant, so there is nothing to identify. The identifier is
	// accepted and ignored; the documented convention is "default".
	//
	// Setting one attribute makes the imported state non-null, after which the
	// framework calls Read to populate the rest.
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("rules"),
		types.ListValueMust(ruleObjectType(r.spec), nil))...)
}

func (r *controlResource) write(ctx context.Context, plan planGetter, prior []priorRule, state stateSetter, diags *diag.Diagnostics) {
	if r.client == nil {
		diags.AddError("Provider not configured", "The Push API client is unavailable.")
		return
	}

	var rules types.List
	diags.Append(plan.GetAttribute(ctx, path.Root("rules"), &rules)...)
	if diags.HasError() {
		return
	}

	planned, d := rulesFromPlan(ctx, r.spec, r.resolver, rules)
	diags.Append(d...)
	if diags.HasError() {
		return
	}

	diags.Append(carryIDs(planned, prior, r.spec.TypeName)...)

	cfg := &pushapi.ControlConfig{Rules: make([]pushapi.Rule, len(planned))}
	for i, p := range planned {
		cfg.Rules[i] = p.Rule
	}

	if len(r.spec.Globals) > 0 {
		var globals types.Object
		diags.Append(plan.GetAttribute(ctx, path.Root("globals"), &globals)...)
		if diags.HasError() {
			return
		}
		g, d := globalsFromPlan(ctx, r.spec, globals)
		diags.Append(d...)
		if diags.HasError() {
			return
		}
		cfg.Globals = g
	}

	tflog.Debug(ctx, "writing control configuration", map[string]any{
		"control": r.spec.APIName,
		"rules":   len(cfg.Rules),
	})

	stored, err := r.put(ctx, cfg)
	if err != nil {
		r.addAPIError(diags, "write", err)
		return
	}

	returned := returnedIDs(stored.Rules)
	diags.Append(r.setState(ctx, state, stored,
		keyByID(planned, returned), emailsByID(planned, returned))...)
}

func (r *controlResource) setState(ctx context.Context, state stateSetter, cfg *pushapi.ControlConfig, keys map[string]string, emails map[string][]string) diag.Diagnostics {
	var diags diag.Diagnostics

	rules, d := rulesToState(ctx, r.spec, r.resolver, cfg.Rules, keys, emails)
	diags.Append(d...)
	diags.Append(state.SetAttribute(ctx, path.Root("rules"), rules)...)

	if len(r.spec.Globals) > 0 {
		g, d := globalsToState(r.spec, cfg.Globals)
		diags.Append(d...)
		diags.Append(state.SetAttribute(ctx, path.Root("globals"), g)...)
	}

	return diags
}

// attrNames maps the API's wire names to this control's attribute names, so
// that a rejected write points at the right part of the configuration.
func (r *controlResource) attrNames() map[string]string {
	out := make(map[string]string, len(r.spec.Fields)+len(r.spec.Globals)+1)
	for _, f := range r.spec.Fields {
		out[f.APIName] = f.Name
	}
	for _, g := range r.spec.Globals {
		out[g.APIName] = g.Name
	}
	out["globals"] = "globals"
	out["criteria"] = "criteria"
	return out
}

func (r *controlResource) get(ctx context.Context) (*pushapi.ControlConfig, error) {
	if r.spec.Endpoint == controlspec.Telemetry {
		return r.client.GetTelemetryConfig(ctx, r.spec.APIName)
	}
	return r.client.GetControlConfig(ctx, r.spec.APIName)
}

func (r *controlResource) put(ctx context.Context, cfg *pushapi.ControlConfig) (*pushapi.ControlConfig, error) {
	if r.spec.Endpoint == controlspec.Telemetry {
		return r.client.PutTelemetryConfig(ctx, r.spec.APIName, cfg)
	}
	return r.client.PutControlConfig(ctx, r.spec.APIName, cfg)
}

// addAPIError attaches validation failures to the configuration attribute that
// caused them.
func (r *controlResource) addAPIError(diags *diag.Diagnostics, op string, err error) {
	if fields, ok := pushapi.Validation(err); ok && len(fields) > 0 {
		addFieldErrors(diags, "Push API rejected the configuration", fields, r.attrNames())
		diags.AddWarning("Validation happened at apply time",
			"The Push API has no dry-run endpoint, so some rules can only be checked by "+
				"attempting the write. The configuration was rejected and nothing was changed.")
		return
	}

	if addRefusal(diags, fmt.Sprintf("%s the %s configuration", op, r.spec.APIName), err) {
		return
	}

	var apiErr *pushapi.APIError
	summary := "Push API request failed"
	if errors.As(err, &apiErr) {
		summary = fmt.Sprintf("Push API returned HTTP %d", apiErr.StatusCode)
	}
	diags.AddError(summary, fmt.Sprintf("Could not %s the %s configuration: %v", op, r.spec.APIName, err))
}

// priorRulesFromState reads state's key and identifier for each rule, which is
// where rule identity is carried between applies.
func priorRulesFromState(ctx context.Context, s controlspec.Spec, state tfsdk.State) ([]priorRule, diag.Diagnostics) {
	var diags diag.Diagnostics

	var rules types.List
	diags.Append(state.GetAttribute(ctx, path.Root("rules"), &rules)...)
	if diags.HasError() || rules.IsNull() || rules.IsUnknown() {
		return nil, diags
	}

	out := make([]priorRule, 0, len(rules.Elements()))
	for _, e := range rules.Elements() {
		obj, ok := e.(types.Object)
		if !ok {
			continue
		}
		attrs := obj.Attributes()
		out = append(out, priorRule{
			Key:    stringOrEmpty(attrs["key"]),
			ID:     stringOrEmpty(attrs["id"]),
			Emails: priorEmailsFromRule(s, attrs),
		})
	}
	return out, diags
}

// priorEmailsFromRule is nil when the rule does not restrict by employee.
func priorEmailsFromRule(s controlspec.Spec, attrs map[string]attr.Value) []string {
	crit, ok := attrs["criteria"].(types.Object)
	if !ok || crit.IsNull() || crit.IsUnknown() {
		return nil
	}
	for _, c := range s.Criteria {
		if !c.ResolvesEmails() {
			continue
		}
		cond, ok := crit.Attributes()[c.Name].(types.Object)
		if !ok || cond.IsNull() || cond.IsUnknown() {
			return nil
		}
		return stringCollection(cond.Attributes()["matches"])
	}
	return nil
}

// The framework's plan, state and config wrappers share these methods but have
// no common interface, so the shared write path takes these instead.
type (
	planGetter interface {
		GetAttribute(context.Context, path.Path, any) diag.Diagnostics
	}
	stateSetter interface {
		SetAttribute(context.Context, path.Path, any) diag.Diagnostics
	}
)
