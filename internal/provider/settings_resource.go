package provider

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/resourcevalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/pushapi"
)

// settingsResource implements pushsecurity_settings: the tenant-wide settings that
// decide which domains Push monitors as the organisation's.
//
// There is one settings document per tenant and the API cannot delete it, so
// this is a singleton like the control resources. Two things set it apart
// from them:
//
//   - The API changes only the fields a request names. Each attribute is
//     therefore managed only while it is configured; one left out is read
//     from the tenant and left to the console.
//   - Destroy resets nothing. The monitored domains are more than a list:
//     Push marks the accounts it holds on them as the organisation's, and
//     clearing the list unmarks every one. That is too much for a destroy to
//     do as a side effect, so it stops managing the settings and says so, as
//     pushsecurity_employee does.
type settingsResource struct {
	client *pushapi.Client
}

var (
	_ resource.Resource                     = &settingsResource{}
	_ resource.ResourceWithConfigure        = &settingsResource{}
	_ resource.ResourceWithIdentity         = &settingsResource{}
	_ resource.ResourceWithImportState      = &settingsResource{}
	_ resource.ResourceWithConfigValidators = &settingsResource{}
	_ resource.ResourceWithModifyPlan       = &settingsResource{}
)

func newSettingsResource() resource.Resource { return &settingsResource{} }

type settingsModel struct {
	MonitoredDomains  types.Set  `tfsdk:"monitored_domains"`
	MonitorAllDomains types.Bool `tfsdk:"monitor_all_domains"`
}

func (r *settingsResource) Metadata(_ context.Context, _ resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = "pushsecurity_settings"
}

func (r *settingsResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages the tenant's settings: the domains Push monitors as " +
			"belonging to your organisation, and whether it monitors every domain.\n\n" +
			"There is one settings document per tenant. Each attribute is managed only " +
			"while it is set: leave one out and the provider reads it, and leaves it to the " +
			"console.\n\n" +
			"~> **Destroying this resource changes nothing.** The settings cannot be " +
			"deleted, and resetting them would unmark every account on the monitored " +
			"domains, so `terraform destroy` stops managing them and warns. Removing the " +
			"resource from your configuration does the same.",
		Attributes: map[string]schema.Attribute{
			"monitored_domains": schema.SetAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Computed:    true,
				MarkdownDescription: "The domains monitored as belonging to your " +
					"organisation, such as `example.com`. At most 100, in lower case.\n\n" +
					"This is the complete list: an apply removes any domain that is not here, " +
					"including one added in the console. Adding a domain marks the accounts " +
					"Push already holds on it as your organisation's, and removing one unmarks " +
					"them, so a plan that removes a domain warns and names it. An empty list " +
					"clears them all.\n\n" +
					"Each entry is checked during plan against the API's own rule: labels of " +
					"letters, digits and hyphens, separated by dots, ending in a top-level " +
					"domain of 2 to 15 letters. Wildcards, schemes, paths and a trailing dot " +
					"are not accepted. The API returns domains in lower case, so an entry with " +
					"capitals would differ from the stored list on every plan, and is " +
					"rejected instead.",
				PlanModifiers: []planmodifier.Set{
					// Unset, the attribute is the tenant's business; a plan
					// should not call it unknown on every change to the other.
					setplanmodifier.UseStateForUnknown(),
				},
				Validators: []validator.Set{
					setvalidator.SizeAtMost(pushapi.MaxMonitoredDomains),
					setvalidator.ValueStringsAre(monitoredDomainValidator{}),
				},
			},
			"monitor_all_domains": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				MarkdownDescription: "Whether Push monitors every domain, not only " +
					"`monitored_domains`. A new tenant starts with it on.",
				PlanModifiers: []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()},
			},
		},
	}
}

func (r *settingsResource) ConfigValidators(context.Context) []resource.ConfigValidator {
	return []resource.ConfigValidator{
		// The API refuses a change that names neither, and a resource that
		// manages nothing is a mistake rather than a choice.
		resourcevalidator.AtLeastOneOf(
			path.MatchRoot("monitored_domains"),
			path.MatchRoot("monitor_all_domains"),
		),
	}
}

func (r *settingsResource) IdentitySchema(ctx context.Context, req resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	singletonIdentitySchema(ctx, req, resp)
}

func (r *settingsResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	client, err := clientFromProviderData(req.ProviderData)
	if err != nil {
		resp.Diagnostics.AddError("Unexpected provider data", err.Error())
		return
	}
	r.client = client
}

// ModifyPlan warns when a plan removes monitored domains, because what that
// does to the tenant's accounts is nowhere in the diff.
//
// A create needs this most. It adopts settings the tenant already has, and its
// plan shows only the configured list, not the domains the apply will remove
// from it. So for a create the comparison is with the tenant as it is now.
func (r *settingsResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() || r.client == nil {
		// A destroy, which changes nothing, or a plan made before the
		// provider is configured.
		return
	}

	var planned types.Set
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("monitored_domains"), &planned)...)
	if resp.Diagnostics.HasError() {
		return
	}
	wanted, known := knownStrings(planned)
	if !known {
		return
	}

	creating := req.State.Raw.IsNull()
	var current []string
	if creating {
		stored, err := r.client.GetSettings(ctx)
		if err != nil {
			// A warning is not worth failing a plan over; the apply will
			// report the same error if it persists.
			tflog.Debug(ctx, "could not read settings to compare monitored domains",
				map[string]any{"error": err.Error()})
			return
		}
		current = stored.MonitoredDomains
	} else {
		var prior types.Set
		resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("monitored_domains"), &prior)...)
		if resp.Diagnostics.HasError() {
			return
		}
		current, _ = knownStrings(prior)
	}

	removed := domainsDropped(current, wanted)
	if len(removed) == 0 {
		return
	}

	detail := fmt.Sprintf("This apply removes %s from the monitored domains. Push marks the "+
		"accounts it holds on a monitored domain as your organisation's, so removing a domain "+
		"unmarks every account on it.", quotedList(removed))
	if creating {
		detail += "\n\nThe tenant holds these domains now and your configuration does not list " +
			"them. If they should stay, add them to monitored_domains. Importing the settings " +
			"before the first apply makes the plan show the whole list."
	}
	resp.Diagnostics.AddAttributeWarning(path.Root("monitored_domains"),
		"Monitored domains will be removed", detail)
}

func (r *settingsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var config, plan settingsModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(setSingletonIdentity(ctx, resp.Identity)...)
	r.write(ctx, config, plan, nil, &resp.State, &resp.Diagnostics)
}

func (r *settingsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var config, plan, prior settingsModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &prior)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(setSingletonIdentity(ctx, resp.Identity)...)
	r.write(ctx, config, plan, &prior, &resp.State, &resp.Diagnostics)
}

func (r *settingsResource) Read(ctx context.Context, _ resource.ReadRequest, resp *resource.ReadResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Provider not configured", "The Push API client is unavailable.")
		return
	}
	resp.Diagnostics.Append(setSingletonIdentity(ctx, resp.Identity)...)
	stored, err := r.client.GetSettings(ctx)
	if err != nil {
		r.addAPIError(&resp.Diagnostics, "read", err)
		return
	}
	model, diags := storedSettings(ctx, stored)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, model)...)
}

// storedSettings is the settings as the tenant holds them.
func storedSettings(ctx context.Context, stored *pushapi.Settings) (settingsModel, diag.Diagnostics) {
	domains, diags := types.SetValueFrom(ctx, types.StringType, stored.MonitoredDomains)
	return settingsModel{
		MonitoredDomains:  domains,
		MonitorAllDomains: types.BoolValue(stored.MonitorAllDomains),
	}, diags
}

func (r *settingsResource) Delete(_ context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	resp.Diagnostics.AddWarning(
		"The settings are left as they are",
		"Terraform has stopped managing the tenant's settings. The monitored domains and "+
			"monitor_all_domains are unchanged.\n\n"+
			"The settings cannot be deleted, and this provider does not reset them on destroy: "+
			"clearing the monitored domains would unmark every account Push holds on them. To "+
			"change them deliberately, apply the values you want before removing the resource.",
	)
}

func (r *settingsResource) ImportState(ctx context.Context, _ resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// One settings document per tenant, so there is nothing to identify; the
	// identifier and any identity are ignored, and the documented convention
	// is "default".
	// Setting one attribute makes the imported state non-null, after which
	// the framework calls Read to fill in the rest.
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("monitored_domains"),
		types.SetValueMust(types.StringType, nil))...)
	resp.Diagnostics.Append(setSingletonIdentity(ctx, resp.Identity)...)
}

// write sends the configured attributes that differ from prior, and records
// what the tenant holds afterwards. prior is nil on create, which sends every
// configured attribute.
func (r *settingsResource) write(ctx context.Context, config, plan settingsModel, prior *settingsModel, state *tfsdk.State, diags *diag.Diagnostics) {
	if r.client == nil {
		diags.AddError("Provider not configured", "The Push API client is unavailable.")
		return
	}

	var update pushapi.SettingsUpdate
	if !config.MonitoredDomains.IsNull() && (prior == nil || !config.MonitoredDomains.Equal(prior.MonitoredDomains)) {
		var domains []string
		diags.Append(config.MonitoredDomains.ElementsAs(ctx, &domains, false)...)
		if diags.HasError() {
			return
		}
		sort.Strings(domains)
		update.MonitoredDomains = &domains
	}
	if !config.MonitorAllDomains.IsNull() && (prior == nil || !config.MonitorAllDomains.Equal(prior.MonitorAllDomains)) {
		v := config.MonitorAllDomains.ValueBool()
		update.MonitorAllDomains = &v
	}

	var stored *pushapi.Settings
	var err error
	if update.MonitoredDomains == nil && update.MonitorAllDomains == nil {
		// Nothing configured differs from what the tenant held, and the API
		// refuses an empty change, so read instead.
		stored, err = r.client.GetSettings(ctx)
	} else {
		tflog.Debug(ctx, "updating settings", map[string]any{
			"monitored_domains":   update.MonitoredDomains != nil,
			"monitor_all_domains": update.MonitorAllDomains != nil,
		})
		stored, err = r.client.UpdateSettings(ctx, update)
	}
	if err != nil {
		r.addAPIError(diags, "update", err)
		return
	}

	domains, d := types.SetValueFrom(ctx, types.StringType, stored.MonitoredDomains)
	diags.Append(d...)
	if diags.HasError() {
		return
	}
	result := settingsModel{
		MonitoredDomains:  domains,
		MonitorAllDomains: types.BoolValue(stored.MonitorAllDomains),
	}
	// An attribute left out of configuration was planned as the value in
	// state. Keep that, so that a console change landing between plan and
	// apply surfaces on the next refresh instead of failing this apply as an
	// inconsistent result. A configured attribute takes what the API stored,
	// so a value it did not accept is reported rather than hidden.
	if config.MonitoredDomains.IsNull() && !plan.MonitoredDomains.IsUnknown() {
		result.MonitoredDomains = plan.MonitoredDomains
	}
	if config.MonitorAllDomains.IsNull() && !plan.MonitorAllDomains.IsUnknown() {
		result.MonitorAllDomains = plan.MonitorAllDomains
	}
	diags.Append(state.Set(ctx, result)...)
}

func (r *settingsResource) addAPIError(diags *diag.Diagnostics, op string, err error) {
	if fields, ok := pushapi.Validation(err); ok && len(fields) > 0 {
		addFieldErrors(diags, "Push API rejected the settings", fields, map[string]string{
			"monitoredDomains":  "monitored_domains",
			"monitorAllDomains": "monitor_all_domains",
		})
		return
	}
	addRequestFailure(diags, op+" the settings", err)
}

// knownStrings returns a set's elements, and false when the set or any element
// is not yet known.
func knownStrings(s types.Set) ([]string, bool) {
	if s.IsNull() || s.IsUnknown() {
		return nil, false
	}
	out := make([]string, 0, len(s.Elements()))
	for _, e := range s.Elements() {
		v, ok := e.(types.String)
		if !ok || v.IsUnknown() || v.IsNull() {
			return nil, false
		}
		out = append(out, v.ValueString())
	}
	return out, true
}

// domainsDropped returns the entries of have that want lacks, sorted.
func domainsDropped(have, want []string) []string {
	keep := make(map[string]struct{}, len(want))
	for _, w := range want {
		keep[w] = struct{}{}
	}
	var out []string
	for _, h := range have {
		if _, ok := keep[h]; !ok {
			out = append(out, h)
		}
	}
	sort.Strings(out)
	return out
}

func quotedList(vals []string) string {
	q := make([]string, len(vals))
	for i, v := range vals {
		q[i] = fmt.Sprintf("%q", v)
	}
	return strings.Join(q, ", ")
}

// monitoredDomainValidator checks one monitored domain during plan, so that an
// entry the API would refuse fails before anything is sent.
type monitoredDomainValidator struct{}

func (monitoredDomainValidator) Description(context.Context) string {
	return "must be a domain such as example.com, in lower case"
}

func (v monitoredDomainValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (monitoredDomainValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	d := req.ConfigValue.ValueString()
	if !validMonitoredDomain(d) {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid monitored domain",
			fmt.Sprintf("%q is not a domain the API accepts. Write a domain such as example.com: "+
				"labels of letters, digits and hyphens separated by dots, none longer than 63 "+
				"characters or starting or ending with a hyphen, and a top-level domain of 2 to "+
				"15 letters. Wildcards, schemes, paths and a trailing dot are not accepted.", d))
		return
	}
	if lower := strings.ToLower(d); lower != d {
		resp.Diagnostics.AddAttributeError(req.Path, "Monitored domain must be lower case",
			fmt.Sprintf("Write %q as %q. The API returns domains in lower case, so %q would differ "+
				"from the stored list on every plan.", d, lower, d))
	}
}

var (
	domainLabel    = regexp.MustCompile(`^[A-Za-z0-9-]{1,63}$`)
	topLevelDomain = regexp.MustCompile(`^[A-Za-z]{2,15}$`)
)

// validMonitoredDomain is the API's rule for a monitored domain: one or more
// labels of letters, digits and hyphens, each followed by a dot and none
// starting or ending with a hyphen, then a top-level domain of 2 to 15
// letters. Like the API, it does not know about public suffixes, so `co.uk`
// passes. Case is checked separately.
func validMonitoredDomain(d string) bool {
	labels := strings.Split(d, ".")
	if len(labels) < 2 || !topLevelDomain.MatchString(labels[len(labels)-1]) {
		return false
	}
	for _, l := range labels[:len(labels)-1] {
		if !domainLabel.MatchString(l) || strings.HasPrefix(l, "-") || strings.HasSuffix(l, "-") {
			return false
		}
	}
	return true
}
