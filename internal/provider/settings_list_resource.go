package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/list"
	listschema "github.com/hashicorp/terraform-plugin-framework/list/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

// settingsListResource lists the tenant's settings for terraform query. A
// tenant always has them, so there is always one result.
type settingsListResource struct {
	res settingsResource
}

var (
	_ list.ListResource              = &settingsListResource{}
	_ list.ListResourceWithConfigure = &settingsListResource{}
)

func newSettingsListResource() list.ListResource { return &settingsListResource{} }

func (l *settingsListResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	l.res.Metadata(ctx, req, resp)
}

func (l *settingsListResource) ListResourceConfigSchema(_ context.Context, _ list.ListResourceSchemaRequest, resp *list.ListResourceSchemaResponse) {
	resp.Schema = listschema.Schema{
		MarkdownDescription: "Finds the tenant's settings, to adopt with `terraform query`. " +
			"Every tenant has them, so this always returns one result.",
	}
}

func (l *settingsListResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	client, err := clientFromProviderData(req.ProviderData)
	if err != nil {
		resp.Diagnostics.AddError("Unexpected provider data", err.Error())
		return
	}
	l.res.client = client
}

func (l *settingsListResource) List(ctx context.Context, req list.ListRequest, stream *list.ListResultsStream) {
	if l.res.client == nil {
		stream.Results = notConfigured()
		return
	}

	stored, err := l.res.client.GetSettings(ctx)
	if err != nil {
		result := list.ListResult{}
		l.res.addAPIError(&result.Diagnostics, "read", err)
		stream.Results = list.ListResultsStreamDiagnostics(result.Diagnostics)
		return
	}

	result := req.NewListResult(ctx)
	result.DisplayName = "Settings"
	result.Diagnostics.Append(setSingletonIdentity(ctx, result.Identity)...)
	if req.IncludeResource {
		model, diags := storedSettings(ctx, stored)
		result.Diagnostics.Append(diags...)
		if !diags.HasError() {
			result.Diagnostics.Append(result.Resource.Set(ctx, model)...)
		}
	}
	stream.Results = listResult(result)
}
