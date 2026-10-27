package provider

import (
	"context"
	"fmt"
	"sort"

	"github.com/hashicorp/terraform-plugin-framework/list"
	listschema "github.com/hashicorp/terraform-plugin-framework/list/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/pushapi"
)

// employeeListResource lists employees for terraform query. Most of a tenant's
// employees come from directory sync and are better left to it, so the list
// takes the same filters as the employees data source, and says so when a
// limit cuts it short.
type employeeListResource struct {
	res employeeResource
}

var (
	_ list.ListResource              = &employeeListResource{}
	_ list.ListResourceWithConfigure = &employeeListResource{}
)

func newEmployeeListResource() list.ListResource { return &employeeListResource{} }

// employeeListModel is an employee list block's configuration. groups is a
// list because list blocks have no set attribute; order does not matter.
type employeeListModel struct {
	Email          types.String `tfsdk:"email"`
	Groups         types.List   `tfsdk:"groups"`
	Licensed       types.Bool   `tfsdk:"licensed"`
	ChatopsEnabled types.Bool   `tfsdk:"chatops_enabled"`
}

func (l *employeeListResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	l.res.Metadata(ctx, req, resp)
}

func (l *employeeListResource) ListResourceConfigSchema(_ context.Context, _ list.ListResourceSchemaRequest, resp *list.ListResourceSchemaResponse) {
	resp.Schema = listschema.Schema{
		MarkdownDescription: "Finds employees, to adopt with `terraform query`, in order of " +
			"email address. Filters are applied by the API where it supports them.",
		Attributes: map[string]listschema.Attribute{
			"email": listschema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Only return the employee with this email address. The whole " +
					"address is compared, ignoring case.",
			},
			"groups": listschema.ListAttribute{
				ElementType:         types.StringType,
				Optional:            true,
				MarkdownDescription: "Only return employees who belong to all of these groups.",
			},
			"licensed": listschema.BoolAttribute{
				Optional:            true,
				MarkdownDescription: "Only return employees with, or without, a licence.",
			},
			"chatops_enabled": listschema.BoolAttribute{
				Optional:            true,
				MarkdownDescription: "Only return employees with, or without, ChatOps enabled.",
			},
		},
	}
}

func (l *employeeListResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	l.res.client, l.res.resolver = providerClients(req.ProviderData, &resp.Diagnostics)
}

func (l *employeeListResource) List(ctx context.Context, req list.ListRequest, stream *list.ListResultsStream) {
	if l.res.client == nil {
		stream.Results = notConfigured()
		return
	}

	var cfg employeeListModel
	if diags := req.Config.Get(ctx, &cfg); diags.HasError() {
		stream.Results = list.ListResultsStreamDiagnostics(diags)
		return
	}
	filter := pushapi.EmployeeFilter{
		Groups:         stringCollection(cfg.Groups),
		Licensed:       cfg.Licensed.ValueBoolPointer(),
		ChatopsEnabled: cfg.ChatopsEnabled.ValueBoolPointer(),
	}
	email := cfg.Email

	var employees []pushapi.Employee
	var err error
	if email.IsNull() {
		employees, err = l.res.client.ListEmployees(ctx, filter)
	} else {
		employees, err = employeesWithEmail(ctx, l.res.client, filter, email.ValueString())
	}
	if err != nil {
		result := list.ListResult{}
		addEmployeeAPIError(&result.Diagnostics, "the tenant's employees", err)
		stream.Results = list.ListResultsStreamDiagnostics(result.Diagnostics)
		return
	}

	// In order of address: the API's order is not documented, and the
	// resource labels terraform query generates follow the result order.
	sort.Slice(employees, func(i, j int) bool {
		return normaliseEmail(employees[i].Email) < normaliseEmail(employees[j].Email)
	})
	matched := len(employees)
	if req.Limit > 0 && int64(matched) > req.Limit {
		employees = employees[:req.Limit]
	}

	stream.Results = func(push func(list.ListResult) bool) {
		for i, e := range employees {
			result := req.NewListResult(ctx)
			result.DisplayName = e.Email
			result.Diagnostics.Append(setEmployeeIdentity(ctx, result.Identity, e.Email)...)
			if i == 0 && len(employees) < matched {
				// On the first result, because Terraform stops reading once
				// it has as many as the limit.
				result.Diagnostics.AddWarning(
					fmt.Sprintf("Employees: %d of %d returned", len(employees), matched),
					fmt.Sprintf("%d employees match, and the list block's limit is %d, so only "+
						"the first %d by email address are returned. Narrow the list with email, "+
						"groups or licensed rather than raising the limit: most of a tenant's "+
						"employees come from directory sync, and are better left to it.",
						matched, req.Limit, len(employees)),
				)
			}
			if req.IncludeResource {
				// The state an import produces.
				model := employeeModel{
					Email:          types.StringValue(e.Email),
					AllowUnlicense: types.BoolValue(false),
				}
				result.Diagnostics.Append(setEmployeeState(&model, &e)...)
				result.Diagnostics.Append(result.Resource.Set(ctx, model)...)
			}
			if !push(result) {
				return
			}
		}
	}
}
