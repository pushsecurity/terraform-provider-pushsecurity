package provider

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/identityschema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/pushapi"
)

// blockedURLResource implements pushsecurity_blocked_url: one pattern in the
// tenant's blocked URL list, for a list Terraform shares with something else,
// such as a workflow that adds patterns over the API.
//
// It owns its own pattern and nothing else, so the rest of the list is never
// drift. What it cannot do is remove its pattern. The API's only delete
// empties the whole list, which would take every entry added outside
// Terraform with it, so destroy, and the destroy half of a replacement, stop
// managing the pattern, leave it blocked, and say so.
type blockedURLResource struct {
	client *pushapi.Client
}

var (
	_ resource.Resource                = &blockedURLResource{}
	_ resource.ResourceWithConfigure   = &blockedURLResource{}
	_ resource.ResourceWithIdentity    = &blockedURLResource{}
	_ resource.ResourceWithImportState = &blockedURLResource{}
	_ resource.ResourceWithModifyPlan  = &blockedURLResource{}
)

func newBlockedURLResource() resource.Resource { return &blockedURLResource{} }

// blockedURLStaysDetail is the warning every destroy carries, since none of
// them removes anything.
const blockedURLStaysDetail = "Terraform has stopped managing %q, but the tenant still blocks it. " +
	"The Push API cannot remove a single entry from the blocked URL list, only empty the whole " +
	"list, which would also remove entries added outside Terraform. To unblock it, remove it " +
	"in the Push console."

func (r *blockedURLResource) Metadata(_ context.Context, _ resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = "pushsecurity_blocked_url"
}

func (r *blockedURLResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages one pattern in the tenant's blocked URL list, and leaves " +
			"every other entry alone.\n\n" +
			"Use it when Terraform shares the list: with a workflow that adds patterns through " +
			"the API, or with people adding them in the console. To have Terraform own the " +
			"whole list instead, use `pushsecurity_blocked_urls`. Never use both in one tenant: " +
			"that one removes every entry it does not list, these included.\n\n" +
			"~> **Destroying this resource does not unblock the URL.** The API cannot remove a " +
			"single entry, only empty the whole list, which would also remove entries added " +
			"outside Terraform. So destroying it, removing it from your configuration, or " +
			"changing `pattern` to a different URL stops Terraform managing the old pattern and " +
			"leaves it blocked, with a warning. Remove it in the Push console to unblock it.",
		Attributes: map[string]schema.Attribute{
			"pattern": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "The URL pattern to block, as a host optionally followed by " +
					"a port and a path: `example.com`, `*.example.com`, `example.com/path*`, " +
					"`intranet:8080/admin`. `*` is a wildcard anywhere in the host or path. The " +
					"host must be lower case, and the path may carry a query string or fragment, " +
					"as in `example.com/search?q=*`. A pattern with no path, or with only `/`, " +
					"blocks every path.\n\n" +
					"Do not include a scheme: the API matches every scheme, and rejects a pattern " +
					"that names one. The canonical form, as `canonical_pattern` shows it, is " +
					"accepted too.\n\n" +
					"Changing this to a different URL replaces the resource, and leaves the old " +
					"pattern blocked. Changing only its spelling, as from `example.com` to " +
					"`example.com/*`, changes nothing in the tenant.",
				Validators: []validator.String{blockedURLValidator{}},
			},
			"canonical_pattern": schema.StringAttribute{
				Computed: true,
				MarkdownDescription: "The pattern as the API stores it, with the scheme wildcard " +
					"and an explicit path: `example.com` is stored as `*://example.com/*`. This " +
					"is the form the console and the API's own responses show, and it is known " +
					"during plan.",
			},
		},
	}
}

// IdentitySchema identifies a pattern by its canonical form, which a
// respelling leaves unchanged: two spellings of one pattern are one entry.
func (r *blockedURLResource) IdentitySchema(_ context.Context, _ resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = identityschema.Schema{
		Attributes: map[string]identityschema.Attribute{
			"canonical_pattern": identityschema.StringAttribute{
				RequiredForImport: true,
				Description: "The pattern as the API stores it, with the scheme wildcard and " +
					"an explicit path, as canonical_pattern shows it. On import, the pattern as " +
					"written in configuration is accepted too.",
			},
		},
	}
}

func (r *blockedURLResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	client, err := clientFromProviderData(req.ProviderData)
	if err != nil {
		resp.Diagnostics.AddError("Unexpected provider data", err.Error())
		return
	}
	r.client = client
}

// ModifyPlan works out canonical_pattern during plan, which the pattern alone
// decides, and replaces the resource only when that changes. A respelling is
// an update that sends nothing.
func (r *blockedURLResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		return // destroy
	}

	var pattern types.String
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("pattern"), &pattern)...)
	if resp.Diagnostics.HasError() {
		return
	}
	creating := req.State.Raw.IsNull()

	if pattern.IsUnknown() {
		// Whether it is a different URL is not known until apply, and
		// replacing costs nothing: destroy sends nothing, and create finds a
		// pattern the list already holds.
		if !creating {
			resp.RequiresReplace = append(resp.RequiresReplace, path.Root("pattern"))
		}
		return
	}
	canonical, ok := canonicalizeBlockedURL(pattern.ValueString())
	if !ok {
		return // the validator reports this
	}
	resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("canonical_pattern"), canonical)...)
	if creating {
		return
	}

	var prior types.String
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("canonical_pattern"), &prior)...)
	if prior.ValueString() != canonical {
		resp.RequiresReplace = append(resp.RequiresReplace, path.Root("pattern"))
	}
}

func (r *blockedURLResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	r.write(ctx, req.Plan, &resp.State, resp.Identity, &resp.Diagnostics)
}

// Update is reached only by a respelling, since a different URL replaces the
// resource, so the list already holds the pattern and write sends nothing.
func (r *blockedURLResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	r.write(ctx, req.Plan, &resp.State, resp.Identity, &resp.Diagnostics)
}

func (r *blockedURLResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Provider not configured", "The Push API client is unavailable.")
		return
	}

	var canonical types.String
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("canonical_pattern"), &canonical)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(setBlockedURLIdentity(ctx, resp.Identity, canonical.ValueString())...)

	held, err := r.client.ListBlockedURLs(ctx)
	if err != nil {
		r.addAPIError(&resp.Diagnostics, "read", err)
		return
	}
	if !slices.Contains(held, canonical.ValueString()) {
		// Removed outside Terraform: drop it from state so the next plan
		// offers to add it back.
		resp.State.RemoveResource(ctx)
	}
	// Otherwise state stands as it is, keeping the configured spelling.
}

func (r *blockedURLResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	// Nothing to call: the API's only delete empties the whole list. The
	// warning is the whole of the delete, so that a destroy says it changed
	// nothing.
	var pattern types.String
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("pattern"), &pattern)...)
	resp.Diagnostics.AddWarning("The URL is still blocked",
		fmt.Sprintf(blockedURLStaysDetail, pattern.ValueString()))
}

func (r *blockedURLResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// The pattern is its own identity, so the import identifier is the
	// pattern, in either form, given as the identifier or as the identity.
	id := strings.TrimSpace(importIdentifier(ctx, req, "canonical_pattern", &resp.Diagnostics))
	if resp.Diagnostics.HasError() {
		return
	}
	if problem := validateBlockedURLPattern(id); problem != "" {
		resp.Diagnostics.AddError("Invalid import identifier",
			fmt.Sprintf("Import a blocked URL by its pattern, for example example.com or "+
				"*://example.com/*, but %q %s.", id, problem))
		return
	}
	canonical := mustCanonical(id)
	// Read then checks the list holds it, and drops it if not, which fails the
	// import.
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("pattern"), blockedURLPattern(canonical))...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("canonical_pattern"), canonical)...)
	resp.Diagnostics.Append(setBlockedURLIdentity(ctx, resp.Identity, canonical)...)
}

// write makes sure the list holds the planned pattern, adding it only when it
// is missing: a pattern already there, from the console, another API client
// or an earlier apply, is taken over as it is.
func (r *blockedURLResource) write(ctx context.Context, plan planGetter, state stateSetter, identity *tfsdk.ResourceIdentity, diags *diag.Diagnostics) {
	if r.client == nil {
		diags.AddError("Provider not configured", "The Push API client is unavailable.")
		return
	}

	var pattern types.String
	diags.Append(plan.GetAttribute(ctx, path.Root("pattern"), &pattern)...)
	if diags.HasError() {
		return
	}
	canonical := mustCanonical(pattern.ValueString())
	diags.Append(setBlockedURLIdentity(ctx, identity, canonical)...)

	held, err := r.client.ListBlockedURLs(ctx)
	if err != nil {
		r.addAPIError(diags, "read", err)
		return
	}
	if !slices.Contains(held, canonical) {
		// The API rejects its own canonical form, so send the pattern form.
		stored, err := r.client.AddBlockedURL(ctx, blockedURLPattern(canonical))
		if err != nil {
			diags.AddAttributeError(path.Root("pattern"), "Push API rejected a URL pattern",
				fmt.Sprintf("Could not add %q: %v\n\nThe rest of the blocked URL list is unchanged.",
					pattern.ValueString(), err))
			return
		}
		if stored != canonical {
			diags.AddAttributeError(path.Root("pattern"), "Push API stored a different pattern",
				fmt.Sprintf("The API stored %q as %q, where the provider expected %q, so Terraform "+
					"cannot track it. The tenant now blocks %q. This is a bug in the provider: "+
					"please report it.", pattern.ValueString(), stored, canonical, stored))
			return
		}
	}

	diags.Append(state.SetAttribute(ctx, path.Root("pattern"), pattern)...)
	diags.Append(state.SetAttribute(ctx, path.Root("canonical_pattern"), canonical)...)
}

func (r *blockedURLResource) addAPIError(diags *diag.Diagnostics, op string, err error) {
	addRequestFailure(diags, op+" the blocked URL list", err)
}

func setBlockedURLIdentity(ctx context.Context, identity *tfsdk.ResourceIdentity, canonical string) diag.Diagnostics {
	return setIdentity(ctx, identity, "canonical_pattern", canonical)
}
