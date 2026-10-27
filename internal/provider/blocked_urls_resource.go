package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/provider/controlspec"
	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/pushapi"
)

// blockedURLsResource implements pushsecurity_blocked_urls.
//
// This is the one control whose API does not follow the whole-document PUT
// pattern: there is a GET for the whole list, a POST that adds one entry, and a
// DELETE that removes every entry. There is no bulk replace and no per-entry
// delete, so removing anything means deleting everything and re-adding the
// rest. Adding needs no such thing, and a change that removes nothing does not
// get it.
type blockedURLsResource struct {
	client *pushapi.Client
}

var (
	_ resource.Resource                   = &blockedURLsResource{}
	_ resource.ResourceWithConfigure      = &blockedURLsResource{}
	_ resource.ResourceWithIdentity       = &blockedURLsResource{}
	_ resource.ResourceWithImportState    = &blockedURLsResource{}
	_ resource.ResourceWithValidateConfig = &blockedURLsResource{}
)

func newBlockedURLsResource() resource.Resource { return &blockedURLsResource{} }

func (r *blockedURLsResource) Metadata(_ context.Context, _ resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = "pushsecurity_blocked_urls"
}

func (r *blockedURLsResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages the tenant's blocked URL list.\n\n" +
			"~> **A change that removes a pattern rewrites the whole list, and not " +
			"atomically.** The API offers no bulk replace and no way to remove a single " +
			"entry, so the provider deletes the entire list and re-adds it one entry at a " +
			"time. Blocking is degraded while that runs — roughly a second per entry — so " +
			"such a change to a large list leaves a window in which some or all URLs are " +
			"not blocked. Plan changes to this resource accordingly. A change that only adds " +
			"patterns adds just those, and one that only respells patterns the list already " +
			"holds sends nothing.\n\n" +
			"This resource owns the whole list: an apply removes any entry not in your " +
			"configuration, including entries added in the console.\n\n" +
			"~> **Destroying this resource empties the list.** `terraform destroy` deletes " +
			"every entry in the tenant's blocked URL list, including entries added in the " +
			"console. Removing the resource from your configuration does the same.",
		Attributes: map[string]schema.Attribute{
			"patterns": schema.SetAttribute{
				ElementType: types.StringType,
				Required:    true,
				MarkdownDescription: "The URL patterns to block, as a host optionally followed " +
					"by a port and a path: `example.com`, `*.example.com`, `example.com/path*`, " +
					"`intranet:8080/admin`. `*` is a wildcard anywhere in the host or path. " +
					"The host must be lower case, and the path may carry a query string or " +
					"fragment, as in `example.com/search?q=*`. A pattern with no path, or with " +
					"only `/`, blocks every path." +
					fmt.Sprintf(" At most %d patterns.\n\n", controlspec.MaxBlockedURLs) +
					"Do not include a scheme: the API matches every scheme, and rejects a " +
					"pattern that names one.\n\n" +
					"A set, because the API does not return entries in the order they were " +
					"added.",
				Validators: []validator.Set{
					setvalidator.SizeAtMost(controlspec.MaxBlockedURLs),
					setvalidator.ValueStringsAre(blockedURLValidator{}),
				},
			},
			"canonical_patterns": schema.SetAttribute{
				ElementType: types.StringType,
				Computed:    true,
				MarkdownDescription: "The patterns as the API stores them, with the scheme " +
					"wildcard and an explicit path: `example.com` is stored as " +
					"`*://example.com/*`. Exposed because this is the form the console and " +
					"the API's own responses show. A value in this form is also accepted in " +
					"`patterns`, and is converted to a pattern before it is sent.",
			},
		},
	}
}

func (r *blockedURLsResource) IdentitySchema(ctx context.Context, req resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	singletonIdentitySchema(ctx, req, resp)
}

func (r *blockedURLsResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	client, err := clientFromProviderData(req.ProviderData)
	if err != nil {
		resp.Diagnostics.AddError("Unexpected provider data", err.Error())
		return
	}
	r.client = client
}

// ValidateConfig rejects two patterns that mean the same thing to the API.
// Without this, the API stores only one of them and every subsequent plan
// shows a diff that cannot be resolved.
func (r *blockedURLsResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var patterns types.Set
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("patterns"), &patterns)...)
	if resp.Diagnostics.HasError() || patterns.IsNull() || patterns.IsUnknown() {
		return
	}

	seen := map[string]string{}
	for _, p := range stringCollection(patterns) {
		canonical, ok := canonicalizeBlockedURL(p)
		if !ok {
			continue // the element validator reports this
		}
		if first, dup := seen[canonical]; dup {
			resp.Diagnostics.AddAttributeError(path.Root("patterns"),
				"Duplicate URL pattern",
				fmt.Sprintf("%q and %q are the same pattern to the API — both mean %q — so "+
					"only one of them can be stored. Remove one.", first, p, canonical),
			)
			continue
		}
		seen[canonical] = p
	}
}

func (r *blockedURLsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	resp.Diagnostics.Append(setSingletonIdentity(ctx, resp.Identity)...)
	r.write(ctx, req.Plan, &resp.State, &resp.Diagnostics)
}

func (r *blockedURLsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.Append(setSingletonIdentity(ctx, resp.Identity)...)
	r.write(ctx, req.Plan, &resp.State, &resp.Diagnostics)
}

func (r *blockedURLsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Provider not configured", "The Push API client is unavailable.")
		return
	}
	resp.Diagnostics.Append(setSingletonIdentity(ctx, resp.Identity)...)

	var prior types.Set
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("patterns"), &prior)...)
	if resp.Diagnostics.HasError() {
		return
	}

	stored, err := r.client.ListBlockedURLs(ctx)
	if err != nil {
		r.addAPIError(&resp.Diagnostics, "read", err)
		return
	}

	resp.Diagnostics.Append(r.setState(ctx, &resp.State, stringCollection(prior), stored)...)
}

func (r *blockedURLsResource) Delete(ctx context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Provider not configured", "The Push API client is unavailable.")
		return
	}
	// The list cannot be removed, only emptied — the same shape of compromise
	// as destroying a control resource.
	if err := r.client.DeleteAllBlockedURLs(ctx); err != nil {
		r.addAPIError(&resp.Diagnostics, "delete", err)
	}
}

func (r *blockedURLsResource) ImportState(ctx context.Context, _ resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// One list per tenant, so there is nothing to identify; by convention the
	// identifier is "default", and it and any identity are ignored.
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("patterns"),
		types.SetValueMust(types.StringType, nil))...)
	resp.Diagnostics.Append(setSingletonIdentity(ctx, resp.Identity)...)
}

func (r *blockedURLsResource) write(ctx context.Context, plan planGetter, state stateSetter, diags *diag.Diagnostics) {
	if r.client == nil {
		diags.AddError("Provider not configured", "The Push API client is unavailable.")
		return
	}

	var patterns types.Set
	diags.Append(plan.GetAttribute(ctx, path.Root("patterns"), &patterns)...)
	if diags.HasError() {
		return
	}
	wanted := stringCollection(patterns)

	// What the tenant holds now decides how little can be sent: nothing when
	// it already holds every pattern and no other, only the missing ones when
	// it holds nothing else, and the whole list otherwise.
	held, err := r.client.ListBlockedURLs(ctx)
	if err != nil {
		r.addAPIError(diags, "read", err)
		return
	}
	toAdd, removes := blockedURLChanges(wanted, held)

	if removes {
		tflog.Warn(ctx, "rewriting the blocked URL list; blocking is degraded until this completes",
			map[string]any{"entries": len(wanted)})
		// Delete-all then add-each is the only way the API offers to remove
		// an entry.
		if err := r.client.DeleteAllBlockedURLs(ctx); err != nil {
			r.addAPIError(diags, "clear", err)
			return
		}
	}

	for _, p := range toAdd {
		// The API rejects its own canonical form, so send the pattern form.
		if _, err := r.client.AddBlockedURL(ctx, blockedURLPattern(mustCanonical(p))); err != nil {
			left := "The patterns before it were added, and every entry the list held before " +
				"is still there. Fix the configuration and apply again to add the rest."
			if removes {
				left = "The blocked URL list has been left partially written: the previous list " +
					"was deleted before this entry failed. Fix the configuration and apply " +
					"again to restore it."
			}
			diags.AddAttributeError(path.Root("patterns"),
				"Push API rejected a URL pattern",
				fmt.Sprintf("Could not add %q: %v\n\n%s", p, err, left),
			)
			return
		}
	}

	stored := held
	if removes || len(toAdd) > 0 {
		// Read back rather than assuming: the stored form is the API's, not
		// ours.
		if stored, err = r.client.ListBlockedURLs(ctx); err != nil {
			r.addAPIError(diags, "read back", err)
			return
		}
	}
	diags.Append(r.setState(ctx, state, wanted, stored)...)
}

// blockedURLChanges works out what bringing held into line with wanted takes:
// the patterns to add, and whether the list has to be emptied first because
// held has an entry wanted lacks. Once the list is emptied, every pattern is
// added.
func blockedURLChanges(wanted, held []string) (toAdd []string, removes bool) {
	want := make(map[string]bool, len(wanted))
	for _, p := range wanted {
		want[mustCanonical(p)] = true
	}
	have := make(map[string]bool, len(held))
	for _, h := range held {
		if !want[h] {
			return wanted, true
		}
		have[h] = true
	}
	for _, p := range wanted {
		if !have[mustCanonical(p)] {
			toAdd = append(toAdd, p)
		}
	}
	return toAdd, false
}

// setState reconciles the configured patterns with what the API reports.
//
// Configuration and storage use different formats, so the comparison is done
// in the canonical direction. When they agree, the practitioner's own spelling
// is kept — otherwise writing `example.com` would be rewritten to
// `*://example.com/*` in state and show as a permanent diff. When they
// disagree, something changed outside Terraform and the API is the truth, so
// state takes the API's list converted back to pattern form.
func (r *blockedURLsResource) setState(ctx context.Context, state stateSetter, configured, stored []string) diag.Diagnostics {
	var diags diag.Diagnostics

	patterns := configured
	if !sameCanonicalSet(configured, stored) {
		patterns = make([]string, 0, len(stored))
		for _, s := range stored {
			patterns = append(patterns, blockedURLPattern(s))
		}
	}

	diags.Append(state.SetAttribute(ctx, path.Root("patterns"), toStringSet(patterns))...)
	diags.Append(state.SetAttribute(ctx, path.Root("canonical_patterns"), toStringSet(stored))...)
	return diags
}

func (r *blockedURLsResource) addAPIError(diags *diag.Diagnostics, op string, err error) {
	addRequestFailure(diags, op+" the blocked URL list", err)
}

// sameCanonicalSet reports whether the configured patterns and the stored
// canonical values describe the same set.
func sameCanonicalSet(configured, stored []string) bool {
	if len(configured) != len(stored) {
		return false
	}
	want := make(map[string]struct{}, len(configured))
	for _, p := range configured {
		c, ok := canonicalizeBlockedURL(p)
		if !ok {
			return false
		}
		want[c] = struct{}{}
	}
	for _, s := range stored {
		if _, present := want[s]; !present {
			return false
		}
	}
	return true
}

// mustCanonical canonicalises a value already accepted by the validator.
func mustCanonical(pattern string) string {
	c, ok := canonicalizeBlockedURL(pattern)
	if !ok {
		// Unreachable: ValidateConfig and the element validator run first.
		return pattern
	}
	return c
}

func toStringSet(vals []string) types.Set {
	elems := make([]attr.Value, 0, len(vals))
	for _, v := range vals {
		elems = append(elems, types.StringValue(v))
	}
	return types.SetValueMust(types.StringType, elems)
}

// blockedURLValidator checks one element of the patterns set.
type blockedURLValidator struct{}

func (blockedURLValidator) Description(context.Context) string {
	return "must be a host optionally followed by a port and a path, with no scheme"
}

func (v blockedURLValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (blockedURLValidator) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if problem := validateBlockedURLPattern(req.ConfigValue.ValueString()); problem != "" {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid URL pattern",
			fmt.Sprintf("%q %s.", req.ConfigValue.ValueString(), problem))
	}
}
