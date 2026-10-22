package provider

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/pushapi"
)

var appCategoryObjectType = types.ObjectType{AttrTypes: map[string]attr.Type{
	"code":  types.StringType,
	"name":  types.StringType,
	"group": types.StringType,
}}

var appObjectType = types.ObjectType{AttrTypes: map[string]attr.Type{
	"id":                types.StringType,
	"type":              types.StringType,
	"friendly_name":     types.StringType,
	"approval_status":   types.StringType,
	"sensitivity_level": types.StringType,
	"website":           types.StringType,
	"labels":            types.SetType{ElemType: types.StringType},
	"category_codes":    types.SetType{ElemType: types.StringType},
	"category_names":    types.SetType{ElemType: types.StringType},
}}

func appAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"id":   schema.StringAttribute{Computed: true, MarkdownDescription: "The app's identifier."},
		"type": schema.StringAttribute{Computed: true, MarkdownDescription: "The app's type, as used by the `app_types` criterion."},
		"friendly_name": schema.StringAttribute{
			Computed:            true,
			MarkdownDescription: "The app's display name.",
		},
		"approval_status": schema.StringAttribute{
			Computed: true,
			MarkdownDescription: "The app's approval status, as used by the `approval_statuses` " +
				"criterion. Empty when the app has not been reviewed.",
		},
		"sensitivity_level": schema.StringAttribute{
			Computed: true,
			MarkdownDescription: "The app's sensitivity level, as used by the " +
				"`sensitivity_levels` criterion. Empty when it has not been set.",
		},
		"website": schema.StringAttribute{Computed: true, MarkdownDescription: "The app's website."},
		"labels": schema.SetAttribute{
			ElementType:         types.StringType,
			Computed:            true,
			MarkdownDescription: "The labels applied to the app, as used by the `app_labels` criterion.",
		},
		"category_codes": schema.SetAttribute{
			ElementType: types.StringType,
			Computed:    true,
			MarkdownDescription: "The app's category codes, as used by the `app_categories` " +
				"criterion. Strings, because that is what the criterion matches on.",
		},
		"category_names": schema.SetAttribute{
			ElementType:         types.StringType,
			Computed:            true,
			MarkdownDescription: "The human-readable names of the app's categories.",
		},
	}
}

func appObject(a pushapi.App) (attr.Value, error) {
	labels := make([]attr.Value, 0, len(a.Labels))
	for _, l := range a.Labels {
		labels = append(labels, types.StringValue(l))
	}
	codes := make([]attr.Value, 0, len(a.Categories))
	names := make([]attr.Value, 0, len(a.Categories))
	for _, c := range a.Categories {
		// String, because criteria.appCategories matches on strings even
		// though the inventory reports the code as a number.
		codes = append(codes, types.StringValue(strconv.Itoa(c.Code)))
		names = append(names, types.StringValue(c.Name))
	}

	labelSet, d1 := types.SetValue(types.StringType, labels)
	codeSet, d2 := types.SetValue(types.StringType, codes)
	nameSet, d3 := types.SetValue(types.StringType, names)
	if d1.HasError() || d2.HasError() || d3.HasError() {
		return nil, fmt.Errorf("building app %s: %v %v %v", a.Type, d1, d2, d3)
	}

	obj, diags := types.ObjectValue(appObjectType.AttrTypes, map[string]attr.Value{
		"id":                types.StringValue(a.ID),
		"type":              types.StringValue(a.Type),
		"friendly_name":     types.StringValue(a.FriendlyName),
		"approval_status":   types.StringValue(a.ApprovalStatus),
		"sensitivity_level": types.StringValue(a.SensitivityLevel),
		"website":           types.StringValue(a.Website),
		"labels":            labelSet,
		"category_codes":    codeSet,
		"category_names":    nameSet,
	})
	if diags.HasError() {
		return nil, fmt.Errorf("building app %s: %v", a.Type, diags)
	}
	return obj, nil
}

// appsDataSource implements data.pushsecurity_apps.
type appsDataSource struct{ client *pushapi.Client }

var (
	_ datasource.DataSource              = &appsDataSource{}
	_ datasource.DataSourceWithConfigure = &appsDataSource{}
)

func newAppsDataSource() datasource.DataSource { return &appsDataSource{} }

func (d *appsDataSource) Metadata(_ context.Context, _ datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = "pushsecurity_apps"
}

func (d *appsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Lists the apps in the tenant, so that app-scoped control criteria " +
			"can be written against what actually exists.\n\n" +
			"The API's app endpoint filters only on creation time, so filtering here happens " +
			"in the provider after fetching every app.",
		Attributes: map[string]schema.Attribute{
			"labels": schema.SetAttribute{
				ElementType:         types.StringType,
				Optional:            true,
				MarkdownDescription: "Only return apps carrying any of these labels.",
			},
			"approval_statuses": schema.SetAttribute{
				ElementType:         types.StringType,
				Optional:            true,
				MarkdownDescription: "Only return apps with any of these approval statuses.",
			},
			"apps": schema.ListNestedAttribute{
				Computed: true,
				MarkdownDescription: "The matching apps, ordered by type, and by identifier " +
					"among apps of the same type, so the result is stable.",
				NestedObject: schema.NestedAttributeObject{Attributes: appAttributes()},
			},
			"types": schema.SetAttribute{
				ElementType: types.StringType,
				Computed:    true,
				MarkdownDescription: "Just the app types, ready to pass to an `app_types` " +
					"criterion.",
			},
			"all_labels": schema.SetAttribute{
				ElementType: types.StringType,
				Computed:    true,
				MarkdownDescription: "Every label seen across the matching apps — useful for " +
					"discovering what labels a tenant uses.",
			},
		},
	}
}

func (d *appsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	client, err := clientFromProviderData(req.ProviderData)
	if err != nil {
		resp.Diagnostics.AddError("Unexpected provider data", err.Error())
		return
	}
	d.client = client
}

func (d *appsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	if d.client == nil {
		resp.Diagnostics.AddError("Provider not configured", "The Push API client is unavailable.")
		return
	}

	var wantLabels, wantStatuses types.Set
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("labels"), &wantLabels)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("approval_statuses"), &wantStatuses)...)
	if resp.Diagnostics.HasError() {
		return
	}

	apps, err := d.client.ListApps(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Could not list apps", err.Error())
		return
	}

	apps = filterApps(apps, stringCollection(wantLabels), stringCollection(wantStatuses))
	sortApps(apps)

	objs := make([]attr.Value, 0, len(apps))
	typeVals := make([]attr.Value, 0, len(apps))
	typeSeen := map[string]struct{}{}
	labelSeen := map[string]struct{}{}
	for _, a := range apps {
		obj, err := appObject(a)
		if err != nil {
			resp.Diagnostics.AddError("Could not read apps", err.Error())
			return
		}
		objs = append(objs, obj)
		// Apps can share a type, and a set refuses the same value twice.
		if _, seen := typeSeen[a.Type]; !seen {
			typeSeen[a.Type] = struct{}{}
			typeVals = append(typeVals, types.StringValue(a.Type))
		}
		for _, l := range a.Labels {
			labelSeen[l] = struct{}{}
		}
	}

	labels := make([]attr.Value, 0, len(labelSeen))
	for l := range labelSeen {
		labels = append(labels, types.StringValue(l))
	}

	list, d1 := types.ListValue(appObjectType, objs)
	typeSet, d2 := types.SetValue(types.StringType, typeVals)
	labelSet, d3 := types.SetValue(types.StringType, labels)
	resp.Diagnostics.Append(d1...)
	resp.Diagnostics.Append(d2...)
	resp.Diagnostics.Append(d3...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("apps"), list)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("types"), typeSet)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("all_labels"), labelSet)...)
}

// sortApps orders apps by type, and apps that share a type by identifier, so
// that the API's order, which nothing promises, cannot reorder the list and
// churn whatever consumes it.
func sortApps(apps []pushapi.App) {
	sort.Slice(apps, func(i, j int) bool {
		if apps[i].Type != apps[j].Type {
			return apps[i].Type < apps[j].Type
		}
		return apps[i].ID < apps[j].ID
	})
}

// filterApps applies the client-side filters. An empty filter matches
// everything; a non-empty one matches any of its values.
func filterApps(apps []pushapi.App, labels, statuses []string) []pushapi.App {
	if len(labels) == 0 && len(statuses) == 0 {
		return apps
	}
	wantLabel := toSet(labels)
	wantStatus := toSet(statuses)

	out := make([]pushapi.App, 0, len(apps))
	for _, a := range apps {
		if len(wantStatus) > 0 {
			if _, ok := wantStatus[a.ApprovalStatus]; !ok {
				continue
			}
		}
		if len(wantLabel) > 0 {
			var hit bool
			for _, l := range a.Labels {
				if _, ok := wantLabel[l]; ok {
					hit = true
					break
				}
			}
			if !hit {
				continue
			}
		}
		out = append(out, a)
	}
	return out
}

// appDataSource implements data.pushsecurity_app: exactly one app, by type.
type appDataSource struct{ client *pushapi.Client }

var (
	_ datasource.DataSource              = &appDataSource{}
	_ datasource.DataSourceWithConfigure = &appDataSource{}
)

func newAppDataSource() datasource.DataSource { return &appDataSource{} }

func (d *appDataSource) Metadata(_ context.Context, _ datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = "pushsecurity_app"
}

func (d *appDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	attrs := appAttributes()
	attrs["type"] = schema.StringAttribute{
		Required: true,
		MarkdownDescription: "The app's type, for example `GOOGLE_WORKSPACE`. Must match exactly " +
			"one app in the tenant.",
	}
	resp.Schema = schema.Schema{
		MarkdownDescription: "Looks up a single app by type.\n\n" +
			"Fails if the type matches no app, so a mistyped app type is caught during plan " +
			"rather than narrowing a control to nothing.",
		Attributes: attrs,
	}
}

func (d *appDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	client, err := clientFromProviderData(req.ProviderData)
	if err != nil {
		resp.Diagnostics.AddError("Unexpected provider data", err.Error())
		return
	}
	d.client = client
}

func (d *appDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	if d.client == nil {
		resp.Diagnostics.AddError("Provider not configured", "The Push API client is unavailable.")
		return
	}

	var appType types.String
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("type"), &appType)...)
	if resp.Diagnostics.HasError() {
		return
	}

	apps, err := d.client.ListApps(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Could not look up app", err.Error())
		return
	}

	matches := make([]pushapi.App, 0, 1)
	for _, a := range apps {
		if a.Type == appType.ValueString() {
			matches = append(matches, a)
		}
	}

	switch len(matches) {
	case 1:
	case 0:
		resp.Diagnostics.AddAttributeError(path.Root("type"), "No such app",
			fmt.Sprintf("No app of type %q exists in this tenant. Use the pushsecurity_apps data "+
				"source to list what is there.", appType.ValueString()))
		return
	default:
		resp.Diagnostics.AddAttributeError(path.Root("type"), "Ambiguous app lookup",
			fmt.Sprintf("%d apps have the type %q. Use the pushsecurity_apps data source instead.",
				len(matches), appType.ValueString()))
		return
	}

	obj, err := appObject(matches[0])
	if err != nil {
		resp.Diagnostics.AddError("Could not read app", err.Error())
		return
	}
	for name, v := range obj.(types.Object).Attributes() {
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(name), v)...)
	}
}

// appCategoriesDataSource implements data.pushsecurity_app_categories.
//
// The `app_categories` criterion matches on numeric category codes, and there
// is no endpoint that lists the catalogue. The app inventory does report each
// app's categories with both code and name, so the categories in use by a
// tenant can be derived from it. That is enough to write
// `app_categories = { matches = [data.pushsecurity_app_categories.all.codes_by_name["Generative AI"]] }`
// instead of hard-coding a number nobody can review.
type appCategoriesDataSource struct{ client *pushapi.Client }

var (
	_ datasource.DataSource              = &appCategoriesDataSource{}
	_ datasource.DataSourceWithConfigure = &appCategoriesDataSource{}
)

func newAppCategoriesDataSource() datasource.DataSource { return &appCategoriesDataSource{} }

func (d *appCategoriesDataSource) Metadata(_ context.Context, _ datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = "pushsecurity_app_categories"
}

func (d *appCategoriesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Resolves app category names to the numeric codes that the " +
			"`app_categories` criterion matches on.\n\n" +
			"~> There is no API that lists the category catalogue, so this is derived from " +
			"the categories actually attached to the tenant's apps. A category that no app " +
			"in the tenant belongs to will not appear here. Terraform fails on a missing map " +
			"key, so a lookup for such a category fails during plan.",
		Attributes: map[string]schema.Attribute{
			"categories": schema.ListNestedAttribute{
				Computed: true,
				MarkdownDescription: "The categories in use, ordered by name, and by code " +
					"among categories that share a name.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"code": schema.StringAttribute{
							Computed: true,
							MarkdownDescription: "The category code, as a string, which is what " +
								"the `app_categories` criterion matches on.",
						},
						"name":  schema.StringAttribute{Computed: true, MarkdownDescription: "The category's name."},
						"group": schema.StringAttribute{Computed: true, MarkdownDescription: "The group the category belongs to."},
					},
				},
			},
			"codes_by_name": schema.MapAttribute{
				ElementType: types.StringType,
				Computed:    true,
				MarkdownDescription: "Category name to code, for use directly in an " +
					"`app_categories` criterion.\n\n" +
					"A name that more than one code carries is left out, with a warning naming " +
					"the codes, rather than mapped to one of them: a lookup of it then fails " +
					"during plan instead of matching a category nobody chose. Pick the code " +
					"from `categories`.",
			},
		},
	}
}

func (d *appCategoriesDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	client, err := clientFromProviderData(req.ProviderData)
	if err != nil {
		resp.Diagnostics.AddError("Unexpected provider data", err.Error())
		return
	}
	d.client = client
}

func (d *appCategoriesDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	if d.client == nil {
		resp.Diagnostics.AddError("Provider not configured", "The Push API client is unavailable.")
		return
	}

	apps, err := d.client.ListApps(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Could not list apps", err.Error())
		return
	}

	categories := collectCategories(apps)

	objs := make([]attr.Value, 0, len(categories))
	codes := map[string][]string{}
	for _, c := range categories {
		code := strconv.Itoa(c.Code)
		obj, diags := types.ObjectValue(appCategoryObjectType.AttrTypes, map[string]attr.Value{
			"code":  types.StringValue(code),
			"name":  types.StringValue(c.Name),
			"group": types.StringValue(c.Group),
		})
		resp.Diagnostics.Append(diags...)
		objs = append(objs, obj)
		codes[c.Name] = append(codes[c.Name], code)
	}
	if resp.Diagnostics.HasError() {
		return
	}

	// A name carried by two codes cannot say which of them a criterion means,
	// so it is left out rather than resolved to whichever code sorts first.
	byName := make(map[string]attr.Value, len(codes))
	for name, cs := range codes {
		if len(cs) > 1 {
			resp.Diagnostics.AddAttributeWarning(path.Root("codes_by_name"),
				"App category name carried by more than one code",
				fmt.Sprintf("The category name %q is carried by the codes %s, so codes_by_name "+
					"leaves it out. Pick the code you mean from categories.",
					name, strings.Join(cs, ", ")))
			continue
		}
		byName[name] = types.StringValue(cs[0])
	}

	list, d1 := types.ListValue(appCategoryObjectType, objs)
	m, d2 := types.MapValue(types.StringType, byName)
	resp.Diagnostics.Append(d1...)
	resp.Diagnostics.Append(d2...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("categories"), list)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("codes_by_name"), m)...)
}

// collectCategories gathers the distinct categories across every app, ordered
// by name, and by code among categories that share a name, so the result is
// stable between reads.
func collectCategories(apps []pushapi.App) []pushapi.AppCategory {
	seen := map[int]pushapi.AppCategory{}
	for _, a := range apps {
		for _, c := range a.Categories {
			seen[c.Code] = c
		}
	}
	out := make([]pushapi.AppCategory, 0, len(seen))
	for _, c := range seen {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Code < out[j].Code
	})
	return out
}

func toSet(vals []string) map[string]struct{} {
	if len(vals) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(vals))
	for _, v := range vals {
		out[v] = struct{}{}
	}
	return out
}
