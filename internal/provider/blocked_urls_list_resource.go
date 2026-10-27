package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/list"
	listschema "github.com/hashicorp/terraform-plugin-framework/list/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"

	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/provider/controlspec"
)

// blockedURLsListResource lists the tenant's blocked URL list for terraform
// query: one result when it holds a pattern, none when it is empty.
type blockedURLsListResource struct {
	res blockedURLsResource
}

var (
	_ list.ListResource              = &blockedURLsListResource{}
	_ list.ListResourceWithConfigure = &blockedURLsListResource{}
)

func newBlockedURLsListResource() list.ListResource { return &blockedURLsListResource{} }

func (l *blockedURLsListResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	l.res.Metadata(ctx, req, resp)
}

func (l *blockedURLsListResource) ListResourceConfigSchema(_ context.Context, _ list.ListResourceSchemaRequest, resp *list.ListResourceSchemaResponse) {
	resp.Schema = listschema.Schema{
		MarkdownDescription: "Finds the tenant's blocked URL list, to adopt with " +
			"`terraform query`. There is one per tenant, so this returns at most one result, " +
			"and none when the list is empty.",
		Attributes: map[string]listschema.Attribute{
			"include_empty": includeEmptyAttribute("list"),
		},
	}
}

func (l *blockedURLsListResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	client, err := clientFromProviderData(req.ProviderData)
	if err != nil {
		resp.Diagnostics.AddError("Unexpected provider data", err.Error())
		return
	}
	l.res.client = client
}

func (l *blockedURLsListResource) List(ctx context.Context, req list.ListRequest, stream *list.ListResultsStream) {
	if l.res.client == nil {
		stream.Results = notConfigured()
		return
	}

	var cfg includeEmptyModel
	if diags := req.Config.Get(ctx, &cfg); diags.HasError() {
		stream.Results = list.ListResultsStreamDiagnostics(diags)
		return
	}

	stored, err := l.res.client.ListBlockedURLs(ctx)
	if err != nil {
		result := list.ListResult{}
		l.res.addAPIError(&result.Diagnostics, "read", err)
		stream.Results = list.ListResultsStreamDiagnostics(result.Diagnostics)
		return
	}
	if len(stored) == 0 && !cfg.IncludeEmpty.ValueBool() {
		stream.Results = list.NoListResults
		return
	}

	const name = "Blocked URLs"
	result := req.NewListResult(ctx)
	result.DisplayName = fmt.Sprintf("%s (%s)", name, counted(len(stored), "pattern"))
	result.Diagnostics.Append(setSingletonIdentity(ctx, result.Identity)...)
	result.Diagnostics.Append(storedWarnings(name, controlspec.CheckStoredBlockedURLs(len(stored)))...)
	if req.IncludeResource {
		// As an import: no configured spelling to keep, so the patterns are
		// the stored ones in pattern form.
		result.Diagnostics.Append(nameWarnings(name,
			l.res.setState(ctx, result.Resource, nil, stored))...)
	}
	stream.Results = listResult(result)
}
