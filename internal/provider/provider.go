// Package provider implements the Push Security Terraform provider.
package provider

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/list"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/provider/controlspec"
	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/pushapi"
)

// Environment variables the provider reads when the corresponding argument is
// not set in configuration.
const (
	envAPIKey  = "PUSH_API_KEY"
	envBaseURL = "PUSH_BASE_URL"
)

var _ provider.ProviderWithListResources = &pushProvider{}

type pushProvider struct {
	// version is set at build time and reported in the User-Agent.
	version string
}

// New returns a function that constructs the provider, as expected by
// providerserver.Serve.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &pushProvider{version: version}
	}
}

// providerModel is the provider block's configuration.
type providerModel struct {
	APIKey  types.String `tfsdk:"api_key"`
	BaseURL types.String `tfsdk:"base_url"`
}

func (p *pushProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "pushsecurity"
	resp.Version = p.version
}

func (p *pushProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages Push Security control configuration.\n\n" +
			"**Experimental:** not yet generally available or officially supported, and " +
			"may change between releases without a deprecation period. Contact " +
			"support@pushsecurity.com before you rely on it.\n\n" +
			"Each control resource owns its control's configuration in full: an apply " +
			"replaces every rule in that control, and anything absent from the " +
			"configuration is deleted. A control is therefore either managed by " +
			"Terraform or managed in the console, never both.",
		Attributes: map[string]schema.Attribute{
			"api_key": schema.StringAttribute{
				Optional:  true,
				Sensitive: true,
				MarkdownDescription: "API key for the Push Security API. May also be set with the " +
					"`" + envAPIKey + "` environment variable, which is the recommended way to " +
					"supply it: a key in configuration ends up in plan files and in version control.\n\n" +
					"A read-only key is enough for `terraform plan` and refresh; `terraform apply` " +
					"needs a full-access key. That split is what makes a plan-on-pull-request, " +
					"apply-on-merge pipeline safe.",
			},
			"base_url": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Base URL of the Push Security API. Defaults to `" +
					pushapi.DefaultBaseURL + "`. May also be set with the `" + envBaseURL +
					"` environment variable. Only set this to target a non-production environment.",
			},
		},
	}
}

// experimentalSummary heads the warning Configure adds on every run, so that
// nobody relies on the provider without knowing its status.
// -compact-warnings shortens it to this line.
const experimentalSummary = "The Push Security provider is experimental"

const experimentalDetail = "It is not yet generally available or officially supported. Resources, " +
	"attributes and behaviour may change between releases without a deprecation period. " +
	"Contact support@pushsecurity.com before you rely on it."

func (p *pushProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	// First, so that it accompanies a configuration error too.
	resp.Diagnostics.AddWarning(experimentalSummary, experimentalDetail)

	var cfg providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// An unknown value here means the practitioner interpolated something that
	// is only known after apply. Stop with a clear message rather than letting
	// every resource fail with a confusing one.
	if cfg.APIKey.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("api_key"),
			"Unknown API key",
			"The Push provider cannot be configured with an api_key that is not known until apply. "+
				"Either set it to a known value, or leave it unset and provide the "+envAPIKey+
				" environment variable.",
		)
		return
	}
	if cfg.BaseURL.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("base_url"),
			"Unknown base URL",
			"The Push provider cannot be configured with a base_url that is not known until apply.",
		)
		return
	}

	// Configuration wins over the environment, so that a module can pin a
	// specific tenant regardless of what the shell happens to export.
	apiKey := firstNonEmpty(cfg.APIKey.ValueString(), os.Getenv(envAPIKey))
	baseURL := firstNonEmpty(cfg.BaseURL.ValueString(), os.Getenv(envBaseURL), pushapi.DefaultBaseURL)

	if apiKey == "" {
		resp.Diagnostics.AddAttributeError(
			path.Root("api_key"),
			"Missing API key",
			"The Push provider requires an API key. Set the "+envAPIKey+" environment variable, "+
				"or set api_key in the provider block. Create a key under Settings in the Push "+
				"admin console.",
		)
		return
	}

	client, err := pushapi.New(baseURL, apiKey, pushapi.WithUserAgent(p.userAgent()))
	if err != nil {
		resp.Diagnostics.AddError(
			"Invalid provider configuration",
			err.Error(),
		)
		return
	}

	// The base URL is safe to log; the key is not, and nothing logs it.
	ctx = tflog.SetField(ctx, "push_base_url", baseURL)
	tflog.Debug(ctx, "configured Push API client")

	// One resolver per configured provider, so the employee lookups every
	// control needs are cached across all of them rather than per resource.
	data := &providerData{client: client, resolver: newEmployeeResolver(client)}
	resp.DataSourceData = data
	resp.ResourceData = data
	resp.ListResourceData = data
}

func (p *pushProvider) Resources(_ context.Context) []func() resource.Resource {
	// Every rule-based control resource is the same implementation driven by a
	// different spec, so registration is a loop over the specs.
	out := make([]func() resource.Resource, 0, len(controlspec.All)+6)
	for _, spec := range controlspec.All {
		out = append(out, newControlResource(spec))
	}
	// The two controls whose API does not follow the configuration PUT pattern.
	out = append(out,
		newCustomDetectionResource,
		newBlockedURLsResource,
	)
	// Employee merging: not a control at all, but the same tenant, the same
	// client, and the same email-address vocabulary as the control criteria.
	out = append(out,
		newEmployeeResource,
		newEmployeeMergeResource,
		newEmployeeMergeRuleResource,
	)
	// The tenant's own settings: a singleton like a control, but one that
	// destroy leaves alone.
	out = append(out, newSettingsResource)
	return out
}

// ListResources are what terraform query finds existing configuration with,
// which is how a tenant is adopted. Every resource that can be imported has
// one.
func (p *pushProvider) ListResources(_ context.Context) []func() list.ListResource {
	out := make([]func() list.ListResource, 0, len(controlspec.All)+4)
	for _, spec := range controlspec.All {
		out = append(out, newControlListResource(spec))
	}
	return append(out,
		newCustomDetectionListResource,
		newBlockedURLsListResource,
		newSettingsListResource,
		newEmployeeListResource,
	)
}

func (p *pushProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		newCustomDetectionsDataSource,
		newEmployeesDataSource,
		newEmployeeDataSource,
		newAppsDataSource,
		newAppDataSource,
		newAppCategoriesDataSource,
	}
}

func (p *pushProvider) userAgent() string {
	v := p.version
	if v == "" {
		v = "dev"
	}
	return "terraform-provider-pushsecurity/" + v
}

// firstNonEmpty returns the first of vals that is not blank, trimmed of
// surrounding whitespace, which a value pasted into configuration or an
// environment variable easily picks up.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}

// providerData is what the provider hands to every resource and data source:
// the API client, and the employee resolver they share so that the tenant is
// enumerated at most once per run.
type providerData struct {
	client   *pushapi.Client
	resolver *employeeResolver
}

// clientFromProviderData returns nil on the first of the two Configure passes
// the framework makes, which is not an error: it calls Configure again once
// the provider itself is configured.
func clientFromProviderData(data any) (*pushapi.Client, error) {
	d, err := unwrapProviderData(data)
	if err != nil || d == nil {
		return nil, err
	}
	return d.client, nil
}

// resolverFromProviderData recovers the shared employee resolver. Nil before
// the provider is configured, exactly as the client is.
func resolverFromProviderData(data any) (*employeeResolver, error) {
	d, err := unwrapProviderData(data)
	if err != nil || d == nil {
		return nil, err
	}
	return d.resolver, nil
}

func unwrapProviderData(data any) (*providerData, error) {
	if data == nil {
		return nil, nil
	}
	d, ok := data.(*providerData)
	if !ok {
		return nil, fmt.Errorf("expected *providerData from provider data, got %T; this is a bug in the provider", data)
	}
	return d, nil
}
