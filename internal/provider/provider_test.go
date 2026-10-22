package provider

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	fwprovider "github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/provider/controlspec"
	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/pushapi"
)

// testAccProtoV6ProviderFactories wires the in-process provider into the
// acceptance test framework. Resource tests in this package use it.
var testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"pushsecurity": providerserver.NewProtocol6WithError(New("test")()),
}

// testAccPreCheck fails a test early, with an actionable message, when the
// environment is not set up for a run against a real tenant.
//
// Acceptance tests replace whole control configurations, so they must only run
// against a dedicated test tenant. This check verifies credentials exist; it
// cannot verify the tenant is disposable.
func testAccPreCheck(t *testing.T) {
	t.Helper()
	if os.Getenv(envAPIKey) == "" {
		t.Fatalf("%s must be set for acceptance tests", envAPIKey)
	}
}

func TestProviderSchema(t *testing.T) {
	ctx := context.Background()
	resp := &fwprovider.SchemaResponse{}
	New("test")().Schema(ctx, fwprovider.SchemaRequest{}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("provider schema produced diagnostics: %v", resp.Diagnostics)
	}
	// Catches invalid attribute combinations without needing Terraform itself.
	if diags := resp.Schema.ValidateImplementation(ctx); diags.HasError() {
		t.Fatalf("provider schema is not a valid implementation: %v", diags)
	}

	apiKey, ok := resp.Schema.Attributes["api_key"]
	if !ok {
		t.Fatal("api_key attribute missing")
	}
	if !apiKey.IsSensitive() {
		t.Error("api_key must be sensitive: it would otherwise appear in plan output and state diffs")
	}
	if !apiKey.IsOptional() {
		t.Error("api_key must be optional: the supported path is the PUSH_API_KEY environment variable")
	}
	if _, ok := resp.Schema.Attributes["base_url"]; !ok {
		t.Error("base_url attribute missing")
	}
}

func TestProviderMetadata(t *testing.T) {
	resp := &fwprovider.MetadataResponse{}
	New("1.2.3")().Metadata(context.Background(), fwprovider.MetadataRequest{}, resp)
	if resp.TypeName != "pushsecurity" {
		t.Errorf("TypeName = %q, want %q", resp.TypeName, "pushsecurity")
	}
	if resp.Version != "1.2.3" {
		t.Errorf("Version = %q, want %q", resp.Version, "1.2.3")
	}
}

func TestUserAgentIncludesVersion(t *testing.T) {
	if got := (&pushProvider{version: "1.2.3"}).userAgent(); got != "terraform-provider-pushsecurity/1.2.3" {
		t.Errorf("userAgent() = %q", got)
	}
	// An unset version must still produce a well-formed User-Agent.
	if got := (&pushProvider{}).userAgent(); got != "terraform-provider-pushsecurity/dev" {
		t.Errorf("userAgent() with no version = %q", got)
	}
}

func TestFirstNonEmpty(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []string
		want string
	}{
		{"first wins", []string{"a", "b"}, "a"},
		{"skips empty", []string{"", "b"}, "b"},
		{"skips whitespace only", []string{"   ", "b"}, "b"},
		{"trims what it returns", []string{" https://api.example.com\n"}, "https://api.example.com"},
		{"all empty", []string{"", ""}, ""},
		{"none", nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := firstNonEmpty(tc.in...); got != tc.want {
				t.Errorf("firstNonEmpty(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestClientFromProviderData(t *testing.T) {
	// The framework calls Configure on resources once before the provider
	// itself is configured, with nil ProviderData. That is expected and must
	// not be reported as an error.
	c, err := clientFromProviderData(nil)
	if err != nil || c != nil {
		t.Errorf("nil provider data: got (%v, %v), want (nil, nil)", c, err)
	}

	res, err := resolverFromProviderData(nil)
	if err != nil || res != nil {
		t.Errorf("nil provider data: got (%v, %v), want (nil, nil)", res, err)
	}

	want, err := pushapi.New("https://api.example.com", "k")
	if err != nil {
		t.Fatalf("pushapi.New: %v", err)
	}
	data := &providerData{client: want, resolver: newEmployeeResolver(want)}

	got, err := clientFromProviderData(data)
	if err != nil {
		t.Fatalf("clientFromProviderData: %v", err)
	}
	if got != want {
		t.Error("client not passed through")
	}

	gotRes, err := resolverFromProviderData(data)
	if err != nil {
		t.Fatalf("resolverFromProviderData: %v", err)
	}
	if gotRes != data.resolver {
		t.Error("resolver not passed through")
	}

	if _, err := clientFromProviderData("not a client"); err == nil {
		t.Error("expected an error for the wrong provider data type")
	}
	// The bare client was the provider data before the resolver was added to
	// it; make sure the mistake is reported rather than silently ignored.
	if _, err := clientFromProviderData(want); err == nil {
		t.Error("expected an error for a bare client as provider data")
	}
}

// TestAccProvider_wrongAPIKey runs a plan's first request, a refresh, and an
// apply's, a write, with a value that is not a Push API key at all. Both must
// fail with a diagnostic that says the key was rejected, and neither may be
// retried: a 401 cannot succeed on a second attempt, and retrying one would
// keep a pipeline with a mistyped key waiting through the whole backoff before
// it says why. Nothing can be written with the key, so the test leaves the
// tenant as it found it. TestProvider_wrongAPIKey runs it against tenantStub.
func TestAccProvider_wrongAPIKey(t *testing.T) {
	if os.Getenv(resource.EnvTfAcc) == "" {
		t.Skipf("acceptance tests skipped unless env %q is set", resource.EnvTfAcc)
	}
	testAccPreCheck(t)
	log := logRequests(t)
	t.Setenv(envAPIKey, "tf-acc-not-a-real-key")
	t.Cleanup(func() { checkRefusedOnce(t, log, http.StatusUnauthorized) })
	resource.Test(t, refusedKeyTestCase(`Push API rejected the API key`))
}

// TestProvider_wrongAPIKey is TestAccProvider_wrongAPIKey against tenantStub,
// which rejects a malformed key the way the API does.
func TestProvider_wrongAPIKey(t *testing.T) {
	offlineTenant(t)
	log := logRequests(t)
	t.Setenv(envAPIKey, "tf-acc-not-a-real-key")
	t.Cleanup(func() { checkRefusedOnce(t, log, http.StatusUnauthorized) })
	resource.UnitTest(t, refusedKeyTestCase(`Push API rejected the API key`))
}

// TestAccProvider_unacceptedAPIKey is TestAccProvider_wrongAPIKey with a key
// shaped like a Push API key that no tenant holds, which is also what a key
// from a different Push environment looks like to the API. It is refused with
// a 403 rather than rejected with a 401, and the diagnostic must point at the
// key's environment, state and access rather than its spelling.
func TestAccProvider_unacceptedAPIKey(t *testing.T) {
	if os.Getenv(resource.EnvTfAcc) == "" {
		t.Skipf("acceptance tests skipped unless env %q is set", resource.EnvTfAcc)
	}
	testAccPreCheck(t)
	log := logRequests(t)
	t.Setenv(envAPIKey, unacceptedAPIKey)
	t.Cleanup(func() { checkRefusedOnce(t, log, http.StatusForbidden) })
	resource.Test(t, refusedKeyTestCase(`Push API refused the API key`))
}

// TestProvider_unacceptedAPIKey is TestAccProvider_unacceptedAPIKey against
// tenantStub.
func TestProvider_unacceptedAPIKey(t *testing.T) {
	offlineTenant(t)
	log := logRequests(t)
	t.Setenv(envAPIKey, unacceptedAPIKey)
	t.Cleanup(func() { checkRefusedOnce(t, log, http.StatusForbidden) })
	resource.UnitTest(t, refusedKeyTestCase(`Push API refused the API key`))
}

// unacceptedAPIKey is well formed, and held by no tenant.
const unacceptedAPIKey = "psak_00000000000000000000000000000000"

// TestProvider_unservedEndpoint points the provider at a base URL under which
// the API serves nothing, as a mistyped PUSH_BASE_URL does. The API refuses
// such a request before it checks the key, so the diagnostic must point at
// the base URL rather than the key.
func TestProvider_unservedEndpoint(t *testing.T) {
	offlineTenant(t)
	t.Setenv(envBaseURL, os.Getenv(envBaseURL)+"/not-the-api")
	resource.UnitTest(t, refusedKeyTestCase(`Push API does not serve this endpoint`))
}

// refusedKeyTestCase imports a control and then applies one, each of which
// must fail with the diagnostic summary given. The key itself comes from the
// environment, as it does in a pipeline.
func refusedKeyTestCase(summary string) resource.TestCase {
	const config = `resource "pushsecurity_file_download_blocking" "tf_acc" { rules = [] }`
	refused := regexp.MustCompile(summary)
	return resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:        config,
				ResourceName:  "pushsecurity_file_download_blocking.tf_acc",
				ImportState:   true,
				ImportStateId: "default",
				ExpectError:   refused,
			},
			{
				Config:      config,
				ExpectError: refused,
			},
		},
	}
}

// checkRefusedOnce asserts the provider made the import's read and the
// apply's write once each, and that both were answered with status.
func checkRefusedOnce(t *testing.T, log *requestLog, status int) {
	t.Helper()
	path := controlspec.FileDownloadBlocking.Path()
	got := log.all()
	want := []string{http.MethodGet + " " + path, http.MethodPut + " " + path}
	if len(got) != len(want) {
		t.Errorf("the provider made %d requests with the refused key, want %d, one each: %v", len(got), len(want), got)
		return
	}
	for i, r := range got {
		if r.method+" "+r.path != want[i] {
			t.Errorf("request %d was %s, want %s", i, r, want[i])
		}
		if r.status != status {
			t.Errorf("request %d was answered %d, want %d", i, r.status, status)
		}
	}
}

// The helpers below are shared by the acceptance tests in this package.

// captureAttr records an attribute value so a later step can assert it has not
// changed. Used for server-assigned identifiers, which the configuration
// cannot name.
func captureAttr(name, attr string, into *string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[name]
		if !ok {
			return fmt.Errorf("resource %s not found in state", name)
		}
		v := rs.Primary.Attributes[attr]
		if v == "" {
			return fmt.Errorf("%s.%s is empty; the server should have assigned a value", name, attr)
		}
		*into = v
		return nil
	}
}

// checkAttr asserts an attribute still holds a previously captured value.
func checkAttr(name, attr string, want *string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[name]
		if !ok {
			return fmt.Errorf("resource %s not found in state", name)
		}
		if got := rs.Primary.Attributes[attr]; got != *want {
			return fmt.Errorf("%s.%s = %q, want %q: identity did not follow the rule's key",
				name, attr, got, *want)
		}
		return nil
	}
}

// sameLength asserts two collection-count attributes agree, which is how the
// convenience sets and maps on the data sources are kept honest against the
// list they summarise.
func sameLength(name, a, b string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[name]
		if !ok {
			return fmt.Errorf("resource %s not found in state", name)
		}
		if got, want := rs.Primary.Attributes[b], rs.Primary.Attributes[a]; got != want {
			return fmt.Errorf("%s = %s but %s = %s; they must agree", b, got, a, want)
		}
		return nil
	}
}

// TestConfigureWarnsExperimental checks every run carries the experimental
// warning, including one whose configuration fails.
func TestConfigureWarnsExperimental(t *testing.T) {
	for name, key := range map[string]string{"configured": "k", "missing key": ""} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(envAPIKey, key)
			ctx := context.Background()
			p := New("test")()

			var schemaResp fwprovider.SchemaResponse
			p.Schema(ctx, fwprovider.SchemaRequest{}, &schemaResp)
			attrs := map[string]tftypes.Value{}
			for name := range schemaResp.Schema.Attributes {
				attrs[name] = tftypes.NewValue(tftypes.String, nil)
			}
			cfg := tfsdk.Config{
				Schema: schemaResp.Schema,
				Raw:    tftypes.NewValue(schemaResp.Schema.Type().TerraformType(ctx), attrs),
			}

			var resp fwprovider.ConfigureResponse
			p.Configure(ctx, fwprovider.ConfigureRequest{Config: cfg}, &resp)

			warnings := resp.Diagnostics.Warnings()
			if len(warnings) != 1 || warnings[0].Summary() != experimentalSummary {
				t.Errorf("warnings = %v, want one %q", warnings, experimentalSummary)
			}
			if got, want := resp.Diagnostics.HasError(), key == ""; got != want {
				t.Errorf("HasError = %v, want %v: %v", got, want, resp.Diagnostics)
			}
		})
	}
}

// configure runs the provider's Configure with the given api_key and base_url
// values, which may be null or unknown.
func configure(t *testing.T, apiKey, baseURL tftypes.Value) *fwprovider.ConfigureResponse {
	t.Helper()
	ctx := context.Background()
	p := New("test")()

	var schemaResp fwprovider.SchemaResponse
	p.Schema(ctx, fwprovider.SchemaRequest{}, &schemaResp)
	cfg := tfsdk.Config{
		Schema: schemaResp.Schema,
		Raw: tftypes.NewValue(schemaResp.Schema.Type().TerraformType(ctx), map[string]tftypes.Value{
			"api_key":  apiKey,
			"base_url": baseURL,
		}),
	}

	resp := &fwprovider.ConfigureResponse{}
	p.Configure(ctx, fwprovider.ConfigureRequest{Config: cfg}, resp)
	return resp
}

var (
	nullString    = tftypes.NewValue(tftypes.String, nil)
	unknownString = tftypes.NewValue(tftypes.String, tftypes.UnknownValue)
)

func knownString(s string) tftypes.Value { return tftypes.NewValue(tftypes.String, s) }

// checkConfigureError asserts Configure failed with exactly one error, with
// the given summary, against the given attribute, or against none when at is
// empty.
func checkConfigureError(t *testing.T, resp *fwprovider.ConfigureResponse, summary string, at path.Path) {
	t.Helper()
	errs := resp.Diagnostics.Errors()
	if len(errs) != 1 || errs[0].Summary() != summary {
		t.Fatalf("errors = %v, want one %q", errs, summary)
	}
	got := path.Empty()
	if withPath, ok := errs[0].(diag.DiagnosticWithPath); ok {
		got = withPath.Path()
	}
	if !got.Equal(at) {
		t.Errorf("error is against %q, want %q", got, at)
	}
	if resp.ResourceData != nil || resp.DataSourceData != nil {
		t.Error("a failed configuration must not hand out a client")
	}
}

func TestConfigureMissingAPIKey(t *testing.T) {
	t.Setenv(envAPIKey, "")
	// Blank counts as missing, wherever it comes from.
	resp := configure(t, knownString("  "), nullString)
	checkConfigureError(t, resp, "Missing API key", path.Root("api_key"))
}

func TestConfigureUnknownValues(t *testing.T) {
	// A value known only after apply cannot configure the client, and the
	// environment must not quietly stand in for it.
	t.Setenv(envAPIKey, "from-env")
	checkConfigureError(t, configure(t, unknownString, nullString), "Unknown API key", path.Root("api_key"))
	checkConfigureError(t, configure(t, knownString("k"), unknownString), "Unknown base URL", path.Root("base_url"))
}

func TestConfigureRejectsPlainHTTPBaseURL(t *testing.T) {
	t.Setenv(envAPIKey, "k")
	resp := configure(t, nullString, knownString("http://api.example.com"))
	checkConfigureError(t, resp, "Invalid provider configuration", path.Empty())
	if detail := resp.Diagnostics.Errors()[0].Detail(); !strings.Contains(detail, "must use https") {
		t.Errorf("detail = %q, want it to say https is required", detail)
	}
}

func TestConfigurePrefersConfigurationOverEnvironment(t *testing.T) {
	var gotKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("x-api-key")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"monitoredDomains":[],"monitorAllDomains":true}`))
	}))
	t.Cleanup(srv.Close)

	// Which key and which base URL the client uses shows in the request it
	// makes. The environment names a host that does not resolve, so a client
	// built from it cannot reach the server.
	client := func(t *testing.T, resp *fwprovider.ConfigureResponse) *pushapi.Client {
		t.Helper()
		if resp.Diagnostics.HasError() {
			t.Fatalf("Configure: %v", resp.Diagnostics)
		}
		data, ok := resp.ResourceData.(*providerData)
		if !ok || resp.DataSourceData != resp.ResourceData {
			t.Fatalf("provider data = %#v / %#v, want the same *providerData for both", resp.ResourceData, resp.DataSourceData)
		}
		return data.client
	}

	t.Run("configuration set", func(t *testing.T) {
		t.Setenv(envAPIKey, "env-key")
		t.Setenv(envBaseURL, "https://env.example.invalid")
		// Padded, as a value pasted into configuration can be.
		c := client(t, configure(t, knownString("config-key"), knownString(" "+srv.URL+" ")))
		if _, err := c.GetSettings(context.Background()); err != nil {
			t.Fatalf("GetSettings: %v", err)
		}
		if gotKey != "config-key" {
			t.Errorf("x-api-key = %q, want the configured key", gotKey)
		}
	})

	t.Run("configuration unset", func(t *testing.T) {
		t.Setenv(envAPIKey, "env-key")
		t.Setenv(envBaseURL, srv.URL)
		c := client(t, configure(t, nullString, nullString))
		if _, err := c.GetSettings(context.Background()); err != nil {
			t.Fatalf("GetSettings: %v", err)
		}
		if gotKey != "env-key" {
			t.Errorf("x-api-key = %q, want the key from the environment", gotKey)
		}
	})
}
