package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/pushapi"
)

// customDetectionsDataSource implements data.pushsecurity_custom_detections.
//
// It lists identity only, because that is all the API's index returns: name and
// detection event type, no logic and no rules. Reading every detection in full
// would be one request per detection, so it is deliberately not done here — the
// use for this data source is discovering what exists in a tenant, typically to
// find what still needs importing.
type customDetectionsDataSource struct {
	client *pushapi.Client
}

var (
	_ datasource.DataSource              = &customDetectionsDataSource{}
	_ datasource.DataSourceWithConfigure = &customDetectionsDataSource{}
)

func newCustomDetectionsDataSource() datasource.DataSource {
	return &customDetectionsDataSource{}
}

func (d *customDetectionsDataSource) Metadata(_ context.Context, _ datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = "pushsecurity_custom_detections"
}

func (d *customDetectionsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Lists the custom detections in the tenant.\n\n" +
			"The API's index returns identity only, so this data source does the same: it " +
			"tells you what exists, not what each detection does. Use it to find detections " +
			"that are not yet managed by Terraform.",
		Attributes: map[string]schema.Attribute{
			"detections": schema.ListNestedAttribute{
				Computed:            true,
				MarkdownDescription: "Every custom detection in the tenant, as the API returns them.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"name": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "The detection's name.",
						},
						"detection_event_type": schema.StringAttribute{
							Computed: true,
							MarkdownDescription: "The detection's permanent identifier, and the " +
								"value to use when importing it.",
						},
					},
				},
			},
			"detection_event_types": schema.SetAttribute{
				ElementType: types.StringType,
				Computed:    true,
				MarkdownDescription: "Just the identifiers, for convenience in `for_each` and " +
					"in `contains` checks.",
			},
		},
	}
}

func (d *customDetectionsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	client, err := clientFromProviderData(req.ProviderData)
	if err != nil {
		resp.Diagnostics.AddError("Unexpected provider data", err.Error())
		return
	}
	d.client = client
}

func (d *customDetectionsDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	if d.client == nil {
		resp.Diagnostics.AddError("Provider not configured", "The Push API client is unavailable.")
		return
	}

	summaries, err := d.client.ListCustomDetections(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Could not list custom detections", err.Error())
		return
	}

	objType := types.ObjectType{AttrTypes: map[string]attr.Type{
		"name":                 types.StringType,
		"detection_event_type": types.StringType,
	}}

	elems := make([]attr.Value, 0, len(summaries))
	ids := make([]attr.Value, 0, len(summaries))
	for _, s := range summaries {
		obj, diags := types.ObjectValue(objType.AttrTypes, map[string]attr.Value{
			"name":                 types.StringValue(s.DetectionEventName),
			"detection_event_type": types.StringValue(s.DetectionEventType),
		})
		resp.Diagnostics.Append(diags...)
		elems = append(elems, obj)
		ids = append(ids, types.StringValue(s.DetectionEventType))
	}
	if resp.Diagnostics.HasError() {
		return
	}

	list, diags := types.ListValue(objType, elems)
	resp.Diagnostics.Append(diags...)
	set, diags := types.SetValue(types.StringType, ids)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("detections"), list)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("detection_event_types"), set)...)
}
