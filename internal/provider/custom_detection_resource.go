package provider

import (
	"context"
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/provider/controlspec"
	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/pushapi"
)

// customDetectionResource implements pushsecurity_custom_detection.
//
// Unlike the control resources this is real CRUD with real identity, so it
// behaves like an ordinary Terraform resource: creating one creates a
// detection, destroying one deletes it. It shares the rule schema, conversion
// and key-based identity machinery with the control resources.
type customDetectionResource struct {
	client   *pushapi.Client
	resolver *employeeResolver
}

var (
	_ resource.Resource                   = &customDetectionResource{}
	_ resource.ResourceWithConfigure      = &customDetectionResource{}
	_ resource.ResourceWithImportState    = &customDetectionResource{}
	_ resource.ResourceWithValidateConfig = &customDetectionResource{}
)

func newCustomDetectionResource() resource.Resource { return &customDetectionResource{} }

// ruleSpec is the shared rule shape for custom detection rules.
var ruleSpec = controlspec.CustomDetectionRules

func (r *customDetectionResource) Metadata(_ context.Context, _ resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = "pushsecurity_custom_detection"
}

func (r *customDetectionResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a custom detection: the detection logic the browser " +
			"extension evaluates, and the rules that decide what happens when it matches.\n\n" +
			"`detection_logic` is stored and returned byte for byte, so keeping it in a file " +
			"and reading it with `file()` gives you detection-as-code with no normalisation " +
			"surprises.\n\n" +
			"A create the API does not answer in time may still finish afterwards, so the " +
			"provider then waits up to two minutes for the detection to appear, and adopts " +
			"it if it holds the planned logic and rules.",
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "The detection's name. May contain only letters, numbers, " +
					"spaces and underscores.\n\n" +
					"~> A detection cannot be renamed: the API derives its permanent " +
					"identifier from the name, and neither can change afterwards. Changing " +
					"`name` therefore replaces the detection: it is destroyed and recreated, " +
					"and the rules inside it are recreated too and get new identifiers.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 75),
					// Mirrors the documented character set. The derived
					// identifier would otherwise be unpredictable.
					stringvalidator.RegexMatches(
						nameCharacters,
						"may contain only letters, numbers, spaces and underscores",
					),
				},
			},
			"detection_event_type": schema.StringAttribute{
				Computed: true,
				MarkdownDescription: "The detection's permanent identifier, derived by the API " +
					"from `name`: upper-cased, spaces replaced with underscores, prefixed with " +
					"`CUSTOM_`. This is the identifier to use when importing.",
				PlanModifiers: []planmodifier.String{
					// Derived from name, and name forces replacement, so the
					// value in state is correct for as long as the resource
					// lives.
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"detection_logic": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "The detection logic: one or more YAML documents describing " +
					"what the browser extension matches on, separated by the standard YAML " +
					"document separator (`---`). Stored and returned verbatim.\n\n" +
					"The API accepts at most 10 KiB (10,240 bytes of UTF-8) and at most 100 " +
					"documents, and plan checks both.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
					detectionLogicValidator{},
				},
			},
			"rules": schema.ListNestedAttribute{
				Required: true,
				MarkdownDescription: "The detection's rules, in evaluation order: the first rule " +
					"that matches wins.\n\n" +
					"At least one rule is required. This list is the complete set: an apply " +
					"deletes any rule that is not here.",
				Validators: []validator.List{
					// The API requires at least one rule on creation. It
					// accepts an empty list on update, but a detection with no
					// rules does nothing, so the stricter rule is the useful
					// one and it fails at plan rather than on the create call.
					listvalidator.SizeBetween(1, controlspec.MaxRules),
				},
				NestedObject: schema.NestedAttributeObject{
					Attributes: buildRuleAttributes(ruleSpec),
				},
			},
		},
	}
}

func (r *customDetectionResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client, r.resolver = providerClients(req.ProviderData, &resp.Diagnostics)
}

func (r *customDetectionResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var rules types.List
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("rules"), &rules)...)
	if resp.Diagnostics.HasError() || rules.IsNull() || rules.IsUnknown() {
		return
	}
	resp.Diagnostics.Append(validateRules(ruleSpec, rules)...)
	resp.Diagnostics.Append(validateKeysUnique(rules)...)
	resp.Diagnostics.Append(validateEmployeeEmails(ctx, ruleSpec, r.resolver, rules)...)
}

func (r *customDetectionResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Provider not configured", "The Push API client is unavailable.")
		return
	}

	var name, logic types.String
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("name"), &name)...)
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("detection_logic"), &logic)...)

	var rules types.List
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("rules"), &rules)...)
	if resp.Diagnostics.HasError() {
		return
	}

	planned, diags := rulesFromPlan(ctx, ruleSpec, r.resolver, rules)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "creating custom detection", map[string]any{"name": name.ValueString()})

	stored, err := r.client.CreateCustomDetection(ctx, name.ValueString(), logic.ValueString(), apiRules(planned))
	if err != nil {
		if !pushapi.TimedOut(err) {
			r.addAPIError(&resp.Diagnostics, "create", name.ValueString(), err)
			return
		}
		if stored = r.awaitTimedOutCreate(ctx, &resp.Diagnostics, name.ValueString(),
			logic.ValueString(), planned, err); stored == nil {
			return
		}
	}

	ids := returnedIDs(stored.Rules)
	resp.Diagnostics.Append(r.setState(ctx, &resp.State, stored,
		keyByID(planned, ids), emailsByID(planned, ids))...)
}

// timedOutCreateWait is how long a create that timed out is given to land, and
// timedOutCreatePoll how often it is looked for meanwhile. Variables so that
// the tests can shorten them.
var (
	timedOutCreateWait = 2 * time.Minute
	timedOutCreatePoll = 5 * time.Second
)

// awaitTimedOutCreate resolves a create that ran out of time. The API can
// answer 504, or the client can give up waiting, while the server is still
// working on the create, and the POST is never resent because a resend of one
// that did land is refused as a conflict. So the detection is looked for by
// the identifier the API derives from its name until it appears or
// timedOutCreateWait passes.
//
// It returns the detection to adopt when one appears holding what was planned,
// with a warning saying so. Otherwise it adds an error and returns nil.
func (r *customDetectionResource) awaitTimedOutCreate(ctx context.Context, diags *diag.Diagnostics, name, logic string, planned []planRule, createErr error) *pushapi.CustomDetection {
	eventType := derivedEventType(name)
	tflog.Warn(ctx, "custom detection create timed out; waiting for it to land", map[string]any{
		"detection_event_type": eventType, "error": createErr.Error(),
	})

	deadline := time.Now().Add(timedOutCreateWait)
	for {
		stored, err := r.client.GetCustomDetection(ctx, eventType)
		switch {
		case err == nil && createdAsPlanned(stored, name, logic, planned):
			diags.AddWarning("Custom detection created after the request timed out",
				fmt.Sprintf("The create of %q timed out (%v), but the detection then appeared "+
					"holding the planned logic and rules, so it has been adopted.", name, createErr))
			return stored

		case err == nil:
			diags.AddAttributeError(path.Root("name"),
				"A custom detection with this name already exists",
				fmt.Sprintf("The create of %q timed out (%v), and the detection that then "+
					"appeared as %s does not hold the planned logic and rules, so it is not "+
					"this apply's to adopt. If it should be managed here, import it:\n\n%s",
					name, createErr, eventType, importBlock(eventType)))
			return nil

		case !pushapi.NotFound(err):
			addCreateUnconfirmed(diags, name, eventType, createErr,
				fmt.Sprintf("Reading it back failed too: %v", err))
			return nil
		}

		if !time.Now().Before(deadline) || wait(ctx, timedOutCreatePoll) != nil {
			addCreateUnconfirmed(diags, name, eventType, createErr,
				fmt.Sprintf("It had not appeared %s later.", timedOutCreateWait))
			return nil
		}
	}
}

// createdAsPlanned reports whether a detection that appeared after a create
// timed out is the one that create sent: the same name and logic, and rules
// that agree with the plan position by position, in who they apply to and in
// what they do. Whatever the API fills in that the plan did not say is not
// compared, any more than after a create that answered in time: a field the
// plan left out, or the action of a condition the plan gave none.
func createdAsPlanned(stored *pushapi.CustomDetection, name, logic string, planned []planRule) bool {
	if stored.DetectionEventName != name || stored.DetectionLogic != logic ||
		len(stored.Rules) != len(planned) {
		return false
	}
	for i, p := range planned {
		s := stored.Rules[i]
		if s.Name != p.Rule.Name || s.Mode != p.Rule.Mode || s.Enabled != p.Rule.Enabled ||
			!sameCriteria(s.Criteria, p.Rule.Criteria) || !holdsFields(s.Fields, p.Rule.Fields) {
			return false
		}
	}
	return true
}

// sameCriteria compares each condition's values as a set, because nothing
// says the API keeps them in the order they were sent.
func sameCriteria(stored, planned map[string]pushapi.Condition) bool {
	if len(stored) != len(planned) {
		return false
	}
	for key, p := range planned {
		s, ok := stored[key]
		if !ok || (p.Action != "" && s.Action != p.Action) ||
			!slices.Equal(slices.Sorted(slices.Values(s.Matches)), slices.Sorted(slices.Values(p.Matches))) {
			return false
		}
	}
	return true
}

// holdsFields reports whether stored holds every field the plan sent, with the
// value it was sent. A list is compared as a set, for the reason sameCriteria
// gives.
func holdsFields(stored, planned map[string]any) bool {
	for key, p := range planned {
		s, ok := stored[key]
		if !ok {
			return false
		}
		if list, isList := p.([]string); isList {
			items, _ := s.([]any)
			got := make([]string, 0, len(items))
			for _, it := range items {
				str, _ := it.(string)
				got = append(got, str)
			}
			if !slices.Equal(slices.Sorted(slices.Values(got)), slices.Sorted(slices.Values(list))) {
				return false
			}
			continue
		}
		if !reflect.DeepEqual(s, p) {
			return false
		}
	}
	return true
}

// addCreateUnconfirmed reports a create that timed out and could not be
// confirmed either way.
func addCreateUnconfirmed(diags *diag.Diagnostics, name, eventType string, createErr error, outcome string) {
	diags.AddError("Custom detection create timed out",
		fmt.Sprintf("Could not create %q: %v\n\n"+
			"The request ran out of time, which does not mean it failed: the API can still "+
			"finish the create afterwards. %s\n\n"+
			"If it appears later, adopt it rather than recreating it, or the next apply will "+
			"fail because the name is taken:\n\n%s",
			name, createErr, outcome, importBlock(eventType)))
}

// importBlock is the import block that adopts the detection with this
// identifier, for diagnostics to quote.
func importBlock(eventType string) string {
	return fmt.Sprintf("    import {\n"+
		"      to = pushsecurity_custom_detection.<name>\n"+
		"      id = %q\n"+
		"    }\n", eventType)
}

// wait sleeps for d, or until ctx is done, in which case it returns ctx's
// error.
func wait(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (r *customDetectionResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Provider not configured", "The Push API client is unavailable.")
		return
	}

	var det types.String
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("detection_event_type"), &det)...)
	if resp.Diagnostics.HasError() {
		return
	}

	prior, diags := priorRulesFromState(ctx, ruleSpec, req.State)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	keys := make(map[string]string, len(prior))
	emails := make(map[string][]string, len(prior))
	for _, p := range prior {
		if p.ID != "" && len(p.Emails) > 0 {
			emails[p.ID] = p.Emails
		}
		if p.Key != "" && p.ID != "" {
			keys[p.ID] = p.Key
		}
	}

	stored, err := r.client.GetCustomDetection(ctx, det.ValueString())
	if err != nil {
		if pushapi.NotFound(err) {
			// Deleted outside Terraform: drop it from state so the next plan
			// offers to recreate it.
			resp.State.RemoveResource(ctx)
			return
		}
		r.addAPIError(&resp.Diagnostics, "read", det.ValueString(), err)
		return
	}

	resp.Diagnostics.Append(r.setState(ctx, &resp.State, stored, keys, emails)...)
}

func (r *customDetectionResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Provider not configured", "The Push API client is unavailable.")
		return
	}

	// name changes force replacement, so the identifier in state is still
	// current here.
	var det, logic types.String
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("detection_event_type"), &det)...)
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("detection_logic"), &logic)...)

	var rules types.List
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("rules"), &rules)...)
	if resp.Diagnostics.HasError() {
		return
	}

	prior, diags := priorRulesFromState(ctx, ruleSpec, req.State)
	resp.Diagnostics.Append(diags...)
	planned, diags := rulesFromPlan(ctx, ruleSpec, r.resolver, rules)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(carryIDs(planned, prior, "custom_detection")...)

	stored, err := r.client.UpdateCustomDetection(ctx, det.ValueString(), logic.ValueString(), apiRules(planned))
	if err != nil {
		r.addAPIError(&resp.Diagnostics, "update", det.ValueString(), err)
		return
	}

	ids := returnedIDs(stored.Rules)
	resp.Diagnostics.Append(r.setState(ctx, &resp.State, stored,
		keyByID(planned, ids), emailsByID(planned, ids))...)
}

func (r *customDetectionResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Provider not configured", "The Push API client is unavailable.")
		return
	}

	var det types.String
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("detection_event_type"), &det)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.client.DeleteCustomDetection(ctx, det.ValueString()); err != nil {
		if pushapi.NotFound(err) {
			// Already gone; nothing to do.
			return
		}
		r.addAPIError(&resp.Diagnostics, "delete", det.ValueString(), err)
	}
}

func (r *customDetectionResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Custom detections have real identity, so the import identifier is the
	// detectionEventType, e.g. CUSTOM_TORRENT_WEBSITE_VISIT.
	id := strings.TrimSpace(req.ID)
	if id == "" {
		resp.Diagnostics.AddError(
			"Missing import identifier",
			"Import a custom detection by its detection event type, for example "+
				"CUSTOM_TORRENT_WEBSITE_VISIT.",
		)
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("detection_event_type"), id)...)
}

func (r *customDetectionResource) setState(ctx context.Context, state stateSetter, det *pushapi.CustomDetection, keys map[string]string, emails map[string][]string) diag.Diagnostics {
	diags := diag.Diagnostics{}
	diags.Append(state.SetAttribute(ctx, path.Root("name"), det.DetectionEventName)...)
	diags.Append(state.SetAttribute(ctx, path.Root("detection_event_type"), det.DetectionEventType)...)
	diags.Append(state.SetAttribute(ctx, path.Root("detection_logic"), det.DetectionLogic)...)

	rules, d := rulesToState(ctx, ruleSpec, r.resolver, det.Rules, keys, emails)
	diags.Append(d...)
	diags.Append(state.SetAttribute(ctx, path.Root("rules"), rules)...)
	return diags
}

func (r *customDetectionResource) addAPIError(diags *diag.Diagnostics, op, subject string, err error) {
	if fields, ok := pushapi.Validation(err); ok && len(fields) > 0 {
		addFieldErrors(diags, "Push API rejected the custom detection", fields, customDetectionAttrNames())
		return
	}

	if pushapi.Conflict(err) && op == "create" {
		// A conflict on create means a detection with this derived identifier
		// already exists. That is a configuration problem, not the transient
		// write contention the client retries.
		//
		// It is also what a timed-out create looks like on the next apply when
		// the detection landed only after awaitTimedOutCreate stopped looking
		// for it. The detection then exists but Terraform does not know about
		// it, so the actionable answer is always to import.
		diags.AddAttributeError(path.Root("name"),
			"A custom detection with this name already exists",
			fmt.Sprintf("Could not %s %q: %v\n\n"+
				"The API derives the identifier from the name, so two detections cannot share "+
				"one, and it is not possible to create this one again.\n\n"+
				"If you did not expect it to exist, a previous apply may have timed out after "+
				"the detection was created. Either way, adopt it rather than recreating it:\n\n%s",
				op, subject, err, importBlock(derivedEventType(subject))),
		)
		return
	}

	if pushapi.Conflict(err) {
		// Anywhere else a conflict is the write contention the client retries,
		// still there when the retries ran out. The detection exists, which is
		// all a name conflict could say, so importing it would be no answer.
		diags.AddError("Push API refused the write as a conflict",
			fmt.Sprintf("Could not %s %q: %v\n\n"+
				"The API refuses a write while another write to the tenant is in progress, and "+
				"it was still refusing this one when the provider stopped retrying. Apply again "+
				"once the other change has finished.", op, subject, err))
		return
	}

	addRequestFailure(diags, fmt.Sprintf("%s %q", op, subject), err)
}

// customDetectionAttrNames maps the API's wire names to attribute names. The
// API validates the detection logic, so its errors are common and must point
// at detection_logic rather than at the rules.
func customDetectionAttrNames() map[string]string {
	out := map[string]string{
		"detectionLogic":     "detection_logic",
		"detectionEventName": "name",
		"criteria":           "criteria",
	}
	for _, f := range ruleSpec.Fields {
		out[f.APIName] = f.Name
	}
	return out
}

// derivedEventType reproduces the API's derivation of the permanent identifier
// from the name — upper-cased, spaces to underscores, CUSTOM_ prefix — so that
// diagnostics can name the identifier to import even when the provider never
// saw it. Confirmed against the API: "Tf probe detection" becomes
// CUSTOM_TF_PROBE_DETECTION.
func derivedEventType(name string) string {
	return "CUSTOM_" + strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(name), " ", "_"))
}

func apiRules(planned []planRule) []pushapi.Rule {
	out := make([]pushapi.Rule, len(planned))
	for i, p := range planned {
		out[i] = p.Rule
	}
	return out
}

func returnedIDs(rules []pushapi.Rule) []string {
	out := make([]string, len(rules))
	for i, r := range rules {
		out[i] = r.ID
	}
	return out
}

// nameCharacters mirrors the API's documented character set for a custom
// detection name. The identifier is derived from the name, so anything outside
// this set makes the derivation unpredictable.
var nameCharacters = regexp.MustCompile(`^[A-Za-z0-9 _]+$`)
