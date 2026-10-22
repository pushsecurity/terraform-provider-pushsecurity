package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/pushapi"
)

// employeeMergeRuleResource implements pushsecurity_employee_merge_rule: the same
// merge, expressed as a shape rather than as a list of people.
//
// A rule says "wherever somebody has a `.admin` address, it belongs to them".
// It applies to whoever is in the tenant when it runs, which is the point —
// the `.admin` account created next month is merged by the plan that follows
// it, with nobody editing the configuration.
//
// The cost of that is a resource whose effects are not written down in the
// configuration, and the provider pays it back in the plan: `pending_merges`
// is refreshed from the tenant, so the plan names every pair it is about to
// merge and a reviewer sees the same list the apply will act on. `max_merges`
// bounds what a mistaken pattern can do in one apply, because Terraform does
// not undo a merge and only some merged addresses can be split out again.
type employeeMergeRuleResource struct {
	client   *pushapi.Client
	resolver *employeeResolver
}

var (
	_ resource.Resource                   = &employeeMergeRuleResource{}
	_ resource.ResourceWithConfigure      = &employeeMergeRuleResource{}
	_ resource.ResourceWithModifyPlan     = &employeeMergeRuleResource{}
	_ resource.ResourceWithValidateConfig = &employeeMergeRuleResource{}
)

func newEmployeeMergeRuleResource() resource.Resource { return &employeeMergeRuleResource{} }

// defaultMaxMerges is deliberately small. A pattern that matches more than
// this in one apply is more likely to be wrong than to be a backlog, and a
// mistaken merge is hard to reverse.
const defaultMaxMerges = 25

type employeeMergeRuleModel struct {
	Patterns      types.Set   `tfsdk:"patterns"`
	Domains       types.Set   `tfsdk:"domains"`
	ExcludeEmails types.Set   `tfsdk:"exclude_emails"`
	MaxMerges     types.Int64 `tfsdk:"max_merges"`
	PendingMerges types.Set   `tfsdk:"pending_merges"`
	Merged        types.Set   `tfsdk:"merged"`
}

func (r *employeeMergeRuleResource) Metadata(_ context.Context, _ resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = "pushsecurity_employee_merge_rule"
}

func (r *employeeMergeRuleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Merges employees by the shape of their addresses rather than by " +
			"naming them: wherever an employee has a second address matching one of " +
			"`patterns`, it is merged into them.\n\n" +
			"```terraform\n" +
			"resource \"pushsecurity_employee_merge_rule\" \"admin_aliases\" {\n" +
			"  patterns = [\"{local}.admin@{domain}\", \"{local}.support@{domain}\"]\n" +
			"}\n" +
			"```\n\n" +
			"A pattern is filled in from each employee's own address — `{local}` and " +
			"`{domain}` — and the result is looked for in the tenant. Matching in that " +
			"direction is what lets a match say whose address it is, which a wildcard could " +
			"not.\n\n" +
			"~> **Terraform does not undo a merge**, and an address that had no accounts cannot " +
			"be split out again at all, so a mistaken pattern cannot always be put right. " +
			"`max_merges` caps one apply, `pending_merges` shows exactly which " +
			"pairs the apply will merge, and destroying the rule leaves everything it merged " +
			"merged.\n\n" +
			"Employees whose own address matches a pattern are never treated as a primary, so " +
			"aliases do not chain. An address that two people could claim is reported as an " +
			"error rather than merged into one of them.",
		Attributes: map[string]schema.Attribute{
			"patterns": schema.SetAttribute{
				ElementType: types.StringType,
				Required:    true,
				MarkdownDescription: "The address shapes to merge, written with the placeholders " +
					"`{local}` and `{domain}`: `{local}.admin@{domain}`, " +
					"`{local}+svc@{domain}`, `{local}@admin.{domain}`. At least one placeholder " +
					"is required — a pattern without one names a single fixed address, which is " +
					"what `pushsecurity_employee_merge` is for.",
				Validators: []validator.Set{
					setvalidator.SizeBetween(1, 20),
					setvalidator.ValueStringsAre(stringvalidator.LengthAtLeast(3)),
				},
			},
			"domains": schema.SetAttribute{
				ElementType: types.StringType,
				Optional:    true,
				MarkdownDescription: "Only consider employees whose own address is in one of " +
					"these domains as a primary. Unset means every domain the tenant holds, " +
					"which on a tenant with contractor or test domains is rarely what is wanted.",
				Validators: []validator.Set{
					setvalidator.ValueStringsAre(stringvalidator.LengthAtLeast(3)),
				},
			},
			"exclude_emails": schema.SetAttribute{
				ElementType: types.StringType,
				Optional:    true,
				MarkdownDescription: "Addresses this rule never touches, on either side of a " +
					"pair. Shared mailboxes that follow the same naming convention as a " +
					"person's alias belong here.",
				Validators: []validator.Set{
					setvalidator.ValueStringsAre(emailLike()),
				},
			},
			"max_merges": schema.Int64Attribute{
				Optional: true,
				Computed: true,
				Default:  int64default.StaticInt64(defaultMaxMerges),
				MarkdownDescription: fmt.Sprintf("The most merges one apply may perform. "+
					"Defaults to %d. A plan that would exceed it fails, naming the count: a "+
					"pattern that matches far more than expected is the one mistake this "+
					"resource cannot walk back.", defaultMaxMerges),
			},
			"pending_merges": schema.SetAttribute{
				ElementType: types.StringType,
				Computed:    true,
				MarkdownDescription: "The pairs the next apply will merge, as " +
					"`secondary -> primary`, refreshed from the tenant on every plan. Empty " +
					"when the tenant already satisfies the rule.",
			},
			"merged": schema.SetAttribute{
				ElementType: types.StringType,
				Computed:    true,
				MarkdownDescription: "Every pair this rule has merged, as `secondary -> " +
					"primary`, and the pairs the next apply will add — which is how a plan " +
					"shows who a rule is about to merge before it does it.\n\n" +
					"It only grows. It records what the provider did: a merged address leaves " +
					"no separate employee behind, so the tenant cannot confirm it afterwards.",
			},
		},
	}
}

func (r *employeeMergeRuleResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client, r.resolver = providerClients(req.ProviderData, &resp.Diagnostics)
}

func (r *employeeMergeRuleResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var cfg employeeMergeRuleModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() || cfg.Patterns.IsUnknown() {
		return
	}
	// Patterns are checked offline, so `terraform validate` catches a typo in
	// a placeholder without a tenant to ask.
	_, diags := parsePatterns(cfg.Patterns)
	resp.Diagnostics.Append(diags...)
}

// ModifyPlan exists because Terraform will not call Update for a computed
// attribute that changed during refresh, so a rule whose tenant has drifted
// would otherwise plan empty and never run. Planning pending_merges back to the
// empty set, and merged as the pairs found now added to what is in state, is
// what makes drift actionable, and what puts the pairs in front of a reviewer.
func (r *employeeMergeRuleResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		// Destroy. Nothing to compute, and the warning belongs to Delete.
		return
	}
	if r.client == nil {
		// `terraform validate`, or a provider that failed to configure. The
		// plan stays unknown rather than claiming there is nothing to do.
		return
	}

	var cfg employeeMergeRuleModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if cfg.Patterns.IsUnknown() || cfg.Domains.IsUnknown() || cfg.ExcludeEmails.IsUnknown() {
		// Scope not known until apply. pending_merges and merged stay
		// unknown, and apply finds and merges the pairs itself.
		return
	}

	matches, ok := r.scan(ctx, cfg, &resp.Diagnostics)
	if !ok {
		return
	}

	if !checkMaxMerges(cfg.MaxMerges, matches, &resp.Diagnostics) {
		return
	}

	// What the apply will have achieved: nothing outstanding, and every pair
	// found now recorded as merged. Both are planned as the values the apply
	// will produce, because a computed attribute planned as one value and
	// applied as another is rejected by Terraform as an inconsistent result.
	// That is why the outstanding work is not planned into pending_merges.
	//
	// The reviewable list is in `merged`, where the new pairs appear as
	// additions. `pending_merges` is what makes drift a change at all: the
	// refresh puts a returning address in it, and this plans it back to empty.
	empty, diags := stringSet(nil)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("pending_merges"), empty)...)

	var priorMerged []string
	if !req.State.Raw.IsNull() {
		var state employeeMergeRuleModel
		resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
		if resp.Diagnostics.HasError() {
			return
		}
		priorMerged = stringCollection(state.Merged)
	}

	merged, diags := stringSet(append(priorMerged, matchStrings(matches)...))
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("merged"), merged)...)
}

func (r *employeeMergeRuleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Provider not configured", "The Push API client is unavailable.")
		return
	}

	var plan employeeMergeRuleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.apply(ctx, &plan, employeeMergeRuleModel{}, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Read refreshes the outstanding work. It cannot verify anything the rule did:
// a merge leaves no trace beyond the secondary's absence, which is exactly
// what "nothing outstanding" means.
func (r *employeeMergeRuleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Provider not configured", "The Push API client is unavailable.")
		return
	}

	var state employeeMergeRuleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	matches, ok := r.scan(ctx, state, &resp.Diagnostics)
	if !ok {
		return
	}
	pending, diags := stringSet(matchStrings(matches))
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	state.PendingMerges = pending
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *employeeMergeRuleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Provider not configured", "The Push API client is unavailable.")
		return
	}

	var plan, state employeeMergeRuleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Set even when the apply failed, because what is in state otherwise is
	// the plan, whose merged would claim every pair it named.
	r.apply(ctx, &plan, state, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *employeeMergeRuleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state employeeMergeRuleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if n := len(stringCollection(state.Merged)); n > 0 {
		resp.Diagnostics.AddWarning(
			"The employees this rule merged stay merged",
			fmt.Sprintf("This rule performed %d merges. %s", n, mergeIrreversibleDetail),
		)
	}
}

// apply performs the merges the plan named, and records in model what was
// done.
//
// It rescans rather than working from identifiers the plan resolved, because
// the plan was made before the refresh-to-apply window and a merge is only
// worth doing against records that exist now. What it will not do is merge
// anything the plan did not show: a pair that appeared in between is left for
// the next plan, where a reviewer sees it first. That holds for a pair merged
// once before, too. The plan shows a pair either as an addition to merged, or,
// when one that was merged before has come back, as its removal from the
// pending_merges the refresh found; a pair already in merged that comes back
// after the plan was made appears as neither.
//
// The exception is a plan made while the scope was unknown, which could name
// no pairs and left merged unknown. Then every pair found now is merged, still
// bounded by max_merges, and merged records what was done on top of prior.
//
// When the apply fails, merged records only the merges that succeeded, on top
// of prior, and pending_merges the ones it attempted that did not, so that the
// state a failed update leaves claims no more than happened.
func (r *employeeMergeRuleResource) apply(ctx context.Context, model *employeeMergeRuleModel, prior employeeMergeRuleModel, diags *diag.Diagnostics) {
	matches, ok := r.scan(ctx, *model, diags)
	if !ok {
		model.Merged, model.PendingMerges = prior.Merged, prior.PendingMerges
		return
	}

	var toMerge []aliasMatch
	if model.Merged.IsUnknown() {
		if !checkMaxMerges(model.MaxMerges, matches, diags) {
			model.Merged, model.PendingMerges = prior.Merged, prior.PendingMerges
			return
		}
		toMerge = matches
	} else {
		shown := map[string]bool{}
		for _, m := range missingPairs(stringCollection(model.Merged), stringCollection(prior.Merged)) {
			shown[m] = true
		}
		for _, m := range stringCollection(prior.PendingMerges) {
			shown[m] = true
		}
		for _, m := range matches {
			if shown[m.String()] {
				toMerge = append(toMerge, m)
			}
		}
	}

	done := performMerges(ctx, r.client, r.resolver, toMerge, diags)

	if model.Merged.IsUnknown() || diags.HasError() {
		merged, d := stringSet(append(stringCollection(prior.Merged), matchStrings(done)...))
		diags.Append(d...)
		model.Merged = merged
	}

	// Otherwise merged and pending_merges keep the values the plan showed.
	// Reporting what the apply happened to find instead would be rejected as
	// an inconsistent result, and would hide the difference rather than
	// surface it: anything that changed in between is found by the next plan.
	var outstanding []aliasMatch
	if diags.HasError() {
		outstanding = missingMatches(toMerge, done)
	}
	pending, d := stringSet(matchStrings(outstanding))
	diags.Append(d...)
	model.PendingMerges = pending
}

// missingPairs returns the pairs in a that b lacks. Both are as stringSet
// writes them, so they compare exactly.
func missingPairs(a, b []string) []string {
	have := make(map[string]bool, len(b))
	for _, v := range b {
		have[v] = true
	}
	var out []string
	for _, v := range a {
		if !have[v] {
			out = append(out, v)
		}
	}
	return out
}

// missingMatches returns the matches in all that done lacks.
func missingMatches(all, done []aliasMatch) []aliasMatch {
	merged := make(map[string]bool, len(done))
	for _, m := range done {
		merged[m.String()] = true
	}
	var out []aliasMatch
	for _, m := range all {
		if !merged[m.String()] {
			out = append(out, m)
		}
	}
	return out
}

// checkMaxMerges reports an error, naming the pairs, when matches exceeds the
// limit. An unset or unknown limit is the default.
func checkMaxMerges(maxMerges types.Int64, matches []aliasMatch, diags *diag.Diagnostics) bool {
	limit := defaultMaxMerges
	if !maxMerges.IsNull() && !maxMerges.IsUnknown() {
		limit = int(maxMerges.ValueInt64())
	}
	if len(matches) <= limit {
		return true
	}
	diags.AddAttributeError(
		path.Root("max_merges"),
		"More merges than this rule allows in one apply",
		fmt.Sprintf("The rule matches %d addresses, and max_merges is %d.\n\n"+
			"Terraform does not undo a merge, so the provider stops rather than performing them. "+
			"Check the pairs below against what you expected, and raise max_merges once "+
			"they are right:\n\n  %s",
			len(matches), limit, strings.Join(matchStrings(matches), "\n  ")),
	)
	return false
}

func (r *employeeMergeRuleResource) scan(ctx context.Context, model employeeMergeRuleModel, diags *diag.Diagnostics) ([]aliasMatch, bool) {
	patterns, d := parsePatterns(model.Patterns)
	diags.Append(d...)
	if diags.HasError() {
		return nil, false
	}

	employees, err := r.client.ListEmployees(ctx, pushapi.EmployeeFilter{})
	if err != nil {
		diags.AddError("Could not list employees", err.Error())
		return nil, false
	}

	matches, conflicts := findAliasMatches(employees, patterns, aliasScope{
		Domains:  stringCollection(model.Domains),
		Excluded: stringCollection(model.ExcludeEmails),
	})

	for _, c := range conflicts {
		diags.AddError(
			"One address matches two employees",
			fmt.Sprintf("%s could be merged into %s.\n\n"+
				"The provider will not choose. Merge that address explicitly with a "+
				"pushsecurity_employee_merge resource, or exclude it with exclude_emails.",
				c.SecondaryEmail, strings.Join(c.Primaries, " or ")),
		)
	}
	if diags.HasError() {
		return nil, false
	}
	return matches, true
}

// parsePatterns reports each failure against the attribute, so the diagnostic
// points at the offending line.
func parsePatterns(set types.Set) ([]aliasPattern, diag.Diagnostics) {
	var diags diag.Diagnostics
	raw := stringCollection(set)
	out := make([]aliasPattern, 0, len(raw))
	for _, p := range raw {
		parsed, err := parseAliasPattern(p)
		if err != nil {
			diags.AddAttributeError(path.Root("patterns"), "Invalid alias pattern", err.Error())
			continue
		}
		out = append(out, parsed)
	}
	return out, diags
}
