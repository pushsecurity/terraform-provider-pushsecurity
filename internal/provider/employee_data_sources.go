package provider

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/pushapi"
)

// These data sources answer "who is in this group?" and "what groups is this
// person in?", so that a control can be scoped without naming everybody.
//
// They are not needed merely to reach the `employee_ids` criterion: that
// criterion is written with email addresses and the provider resolves them
// itself. What is worth a lookup is membership — passing `emails` from a
// group query keeps a rule correct as people join and leave it.

var employeeObjectType = types.ObjectType{AttrTypes: map[string]attr.Type{
	"id":              types.StringType,
	"email":           types.StringType,
	"first_name":      types.StringType,
	"last_name":       types.StringType,
	"department":      types.StringType,
	"location":        types.StringType,
	"licensed":        types.BoolType,
	"chatops_enabled": types.BoolType,
	"groups":          types.SetType{ElemType: types.StringType},
}}

func employeeAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"id": schema.StringAttribute{
			Computed: true,
			MarkdownDescription: "The employee identifier the API stores internally. " +
				"Control criteria are written with email addresses, which the provider " +
				"resolves, so this is informational.",
		},
		"email":           schema.StringAttribute{Computed: true, MarkdownDescription: "The employee's email address."},
		"first_name":      schema.StringAttribute{Computed: true, MarkdownDescription: "The employee's first name."},
		"last_name":       schema.StringAttribute{Computed: true, MarkdownDescription: "The employee's last name."},
		"department":      schema.StringAttribute{Computed: true, MarkdownDescription: "The employee's department."},
		"location":        schema.StringAttribute{Computed: true, MarkdownDescription: "The employee's location."},
		"licensed":        schema.BoolAttribute{Computed: true, MarkdownDescription: "Whether the employee holds a licence."},
		"chatops_enabled": schema.BoolAttribute{Computed: true, MarkdownDescription: "Whether ChatOps is enabled for the employee."},
		"groups": schema.SetAttribute{
			ElementType:         types.StringType,
			Computed:            true,
			MarkdownDescription: "The groups the employee belongs to, as used by the `employee_groups` criterion.",
		},
	}
}

func employeeObject(e pushapi.Employee) (attr.Value, error) {
	groups := make([]attr.Value, 0, len(e.Groups))
	for _, g := range e.Groups {
		groups = append(groups, types.StringValue(g))
	}
	set, diags := types.SetValue(types.StringType, groups)
	if diags.HasError() {
		return nil, fmt.Errorf("building groups for %s: %v", e.Email, diags)
	}

	obj, diags := types.ObjectValue(employeeObjectType.AttrTypes, map[string]attr.Value{
		"id":              types.StringValue(e.ID),
		"email":           types.StringValue(e.Email),
		"first_name":      types.StringValue(e.FirstName),
		"last_name":       types.StringValue(e.LastName),
		"department":      types.StringValue(e.Department),
		"location":        types.StringValue(e.Location),
		"licensed":        types.BoolValue(e.Licensed),
		"chatops_enabled": types.BoolValue(e.ChatopsEnabled),
		"groups":          set,
	})
	if diags.HasError() {
		return nil, fmt.Errorf("building employee %s: %v", e.Email, diags)
	}
	return obj, nil
}

// employeesDataSource implements data.pushsecurity_employees.
type employeesDataSource struct{ client *pushapi.Client }

var (
	_ datasource.DataSource              = &employeesDataSource{}
	_ datasource.DataSourceWithConfigure = &employeesDataSource{}
)

func newEmployeesDataSource() datasource.DataSource { return &employeesDataSource{} }

func (d *employeesDataSource) Metadata(_ context.Context, _ datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = "pushsecurity_employees"
}

func (d *employeesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Looks up employees, so that control criteria can refer to people " +
			"by group or email rather than by opaque identifier.\n\n" +
			"Filters are applied by the API where it supports them, so this is usable on a " +
			"large tenant.",
		Attributes: map[string]schema.Attribute{
			"email": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Only return the employee with this email address. The whole " +
					"address is compared, ignoring case, so `jo@example.com` does not also return " +
					"`jojo@example.com`.",
			},
			"groups": schema.SetAttribute{
				ElementType:         types.StringType,
				Optional:            true,
				MarkdownDescription: "Only return employees who belong to all of these groups.",
			},
			"licensed": schema.BoolAttribute{
				Optional:            true,
				MarkdownDescription: "Only return employees with, or without, a licence.",
			},
			"chatops_enabled": schema.BoolAttribute{
				Optional:            true,
				MarkdownDescription: "Only return employees with, or without, ChatOps enabled.",
			},
			"employees": schema.ListNestedAttribute{
				Computed:            true,
				MarkdownDescription: "The matching employees, ordered by email so the result is stable.",
				NestedObject:        schema.NestedAttributeObject{Attributes: employeeAttributes()},
			},
			"ids": schema.SetAttribute{
				ElementType: types.StringType,
				Computed:    true,
				MarkdownDescription: "Just the identifiers the API stores internally. " +
					"Informational: criteria are written with email addresses.",
			},
			"emails": schema.SetAttribute{
				ElementType: types.StringType,
				Computed:    true,
				MarkdownDescription: "Just the email addresses, ready to pass to an " +
					"`employee_ids` criterion.",
			},
		},
	}
}

func (d *employeesDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	client, err := clientFromProviderData(req.ProviderData)
	if err != nil {
		resp.Diagnostics.AddError("Unexpected provider data", err.Error())
		return
	}
	d.client = client
}

func (d *employeesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	if d.client == nil {
		resp.Diagnostics.AddError("Provider not configured", "The Push API client is unavailable.")
		return
	}

	filter, diags := employeeFilterFrom(ctx, req.Config)
	resp.Diagnostics.Append(diags...)
	var email types.String
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("email"), &email)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var employees []pushapi.Employee
	var err error
	if email.IsNull() {
		employees, err = d.client.ListEmployees(ctx, filter)
	} else {
		employees, err = employeesWithEmail(ctx, d.client, filter, email.ValueString())
	}
	if err != nil {
		resp.Diagnostics.AddError("Could not list employees", err.Error())
		return
	}

	// Ordered by email: the API's order is not documented, and an unstable
	// order would churn any resource that consumes the list.
	sort.Slice(employees, func(i, j int) bool { return employees[i].Email < employees[j].Email })

	objs := make([]attr.Value, 0, len(employees))
	ids := make([]attr.Value, 0, len(employees))
	emails := make([]attr.Value, 0, len(employees))
	for _, e := range employees {
		obj, err := employeeObject(e)
		if err != nil {
			resp.Diagnostics.AddError("Could not read employees", err.Error())
			return
		}
		objs = append(objs, obj)
		ids = append(ids, types.StringValue(e.ID))
		emails = append(emails, types.StringValue(e.Email))
	}

	list, d1 := types.ListValue(employeeObjectType, objs)
	idSet, d2 := types.SetValue(types.StringType, ids)
	emailSet, d3 := types.SetValue(types.StringType, emails)
	resp.Diagnostics.Append(d1...)
	resp.Diagnostics.Append(d2...)
	resp.Diagnostics.Append(d3...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("employees"), list)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("ids"), idSet)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("emails"), emailSet)...)
}

// employeeDataSource implements data.pushsecurity_employee: exactly one employee, or an
// error. A lookup that returned the first of several matches would produce a
// configuration that targets the wrong person without saying so.
type employeeDataSource struct{ client *pushapi.Client }

var (
	_ datasource.DataSource              = &employeeDataSource{}
	_ datasource.DataSourceWithConfigure = &employeeDataSource{}
)

func newEmployeeDataSource() datasource.DataSource { return &employeeDataSource{} }

func (d *employeeDataSource) Metadata(_ context.Context, _ datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = "pushsecurity_employee"
}

func (d *employeeDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	attrs := employeeAttributes()
	// email identifies the employee here, so it is an input rather than a
	// computed result.
	attrs["email"] = schema.StringAttribute{
		Required: true,
		MarkdownDescription: "The employee's email address, compared ignoring case. " +
			"Must match exactly one employee.",
	}
	resp.Schema = schema.Schema{
		MarkdownDescription: "Looks up a single employee by email address, for use in an " +
			"`employee_ids` criterion.\n\n" +
			"Fails if the email matches no employee, so a typo is caught during plan rather " +
			"than narrowing a control to nobody.",
		Attributes: attrs,
	}
}

func (d *employeeDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	client, err := clientFromProviderData(req.ProviderData)
	if err != nil {
		resp.Diagnostics.AddError("Unexpected provider data", err.Error())
		return
	}
	d.client = client
}

func (d *employeeDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	if d.client == nil {
		resp.Diagnostics.AddError("Provider not configured", "The Push API client is unavailable.")
		return
	}

	var email types.String
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("email"), &email)...)
	if resp.Diagnostics.HasError() {
		return
	}

	matches, err := employeesWithEmail(ctx, d.client, pushapi.EmployeeFilter{}, email.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Could not look up employee", err.Error())
		return
	}

	switch len(matches) {
	case 1:
	case 0:
		resp.Diagnostics.AddAttributeError(path.Root("email"), "No such employee",
			fmt.Sprintf("No employee has the email address %q. Check the address, or use the "+
				"pushsecurity_employees data source to list what the tenant holds.", email.ValueString()))
		return
	default:
		resp.Diagnostics.AddAttributeError(path.Root("email"), "Ambiguous employee lookup",
			fmt.Sprintf("%d employees have the email address %q, so this lookup cannot "+
				"identify one. Use the pushsecurity_employees data source instead.",
				len(matches), email.ValueString()))
		return
	}

	e := matches[0]
	obj, err := employeeObject(e)
	if err != nil {
		resp.Diagnostics.AddError("Could not read employee", err.Error())
		return
	}
	for name, v := range obj.(types.Object).Attributes() {
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(name), v)...)
	}
}

// employeesWithEmail returns the employees filter selects whose address is
// email, compared whole and ignoring case.
//
// The API's email filter does not compare whole addresses, so on its own it
// can find both too much and too little: "jo@example.com" also finds
// "jojo@example.com", and an address spelled in different case from the
// tenant's can be missed. So the filter is sent lower-cased and what comes
// back is compared whole. A filter that finds nothing falls back to one
// listing without it, as the resolver does: an address the tenant spells with
// capitals can be missed by the filter but is present in the list.
func employeesWithEmail(ctx context.Context, client *pushapi.Client, filter pushapi.EmployeeFilter, email string) ([]pushapi.Employee, error) {
	want := strings.ToLower(strings.TrimSpace(email))
	if want == "" {
		return nil, nil
	}

	filter.Email = want
	employees, err := client.ListEmployees(ctx, filter)
	if err != nil {
		return nil, err
	}
	if matches := withAddress(employees, want); len(matches) > 0 {
		return matches, nil
	}

	filter.Email = ""
	employees, err = client.ListEmployees(ctx, filter)
	if err != nil {
		return nil, err
	}
	return withAddress(employees, want), nil
}

// configGetter is the read side of a data source config, plan or state.
type configGetter interface {
	GetAttribute(context.Context, path.Path, any) diag.Diagnostics
}

// employeeFilterFrom leaves out email, which the API's filter does not match
// exactly on its own: see employeesWithEmail.
func employeeFilterFrom(ctx context.Context, cfg configGetter) (pushapi.EmployeeFilter, diag.Diagnostics) {
	var diags diag.Diagnostics
	var filter pushapi.EmployeeFilter

	var groups types.Set
	diags.Append(cfg.GetAttribute(ctx, path.Root("groups"), &groups)...)
	filter.Groups = stringCollection(groups)

	var licensed types.Bool
	diags.Append(cfg.GetAttribute(ctx, path.Root("licensed"), &licensed)...)
	if !licensed.IsNull() && !licensed.IsUnknown() {
		v := licensed.ValueBool()
		filter.Licensed = &v
	}

	var chatops types.Bool
	diags.Append(cfg.GetAttribute(ctx, path.Root("chatops_enabled"), &chatops)...)
	if !chatops.IsNull() && !chatops.IsUnknown() {
		v := chatops.ValueBool()
		filter.ChatopsEnabled = &v
	}

	return filter, diags
}
