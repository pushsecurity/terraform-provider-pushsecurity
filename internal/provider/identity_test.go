package provider

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"

	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/provider/controlspec"
	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/pushapi"
)

// Terraform records resource identity, and imports by it, from 1.12. Older
// versions never ask for it, which the rest of the suite covers.
var identityVersions = []tfversion.TerraformVersionCheck{
	tfversion.SkipBelow(tfversion.Version1_12_0),
}

// identityRoundTrip creates the resource config describes, checks the
// identity Terraform stored for it, and imports it again by that identity:
// the import must plan as a no-op and arrive at the same identity. Against
// the stub unless live, when it is an acceptance test against PUSH_API_KEY's
// tenant and checkDestroy, if given, checks what destroy left there.
func identityRoundTrip(t *testing.T, live bool, addr, config string, identity map[string]knownvalue.Check, checkDestroy resource.TestCheckFunc) {
	t.Helper()
	run := resource.UnitTest
	var preCheck func()
	if live {
		run = resource.Test
		preCheck = func() { testAccPreCheck(t) }
	}
	run(t, resource.TestCase{
		PreCheck:                 preCheck,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   identityVersions,
		CheckDestroy:             checkDestroy,
		Steps: []resource.TestStep{
			{
				Config:            config,
				ConfigStateChecks: []statecheck.StateCheck{statecheck.ExpectIdentity(addr, identity)},
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
			{
				ResourceName:    addr,
				ImportState:     true,
				ImportStateKind: resource.ImportBlockWithResourceIdentity,
			},
		},
	})
}

// TestIdentity_control: every control configuration is the same singleton, so
// one control stands for all sixteen.
func TestIdentity_control(t *testing.T) {
	offlineTenant(t)
	identityRoundTrip(t, false, testResource, `
resource "pushsecurity_file_download_blocking" "test" {
  rules = [{ name = "Monitor", enabled = true, mode = "MONITOR" }]
}
`, map[string]knownvalue.Check{"id": knownvalue.StringExact("default")}, nil)
}

func TestIdentity_blockedURLs(t *testing.T) {
	offlineTenant(t)
	// Written in the short form an import reads it back in, so that the
	// import plans nothing.
	identityRoundTrip(t, false, testBlockedURLs,
		`resource "pushsecurity_blocked_urls" "test" { patterns = ["tf-acc-one.example.com"] }`,
		map[string]knownvalue.Check{"id": knownvalue.StringExact("default")}, nil)
}

func TestIdentity_settings(t *testing.T) {
	stub := offlineTenant(t)
	stub.seedSettings([]string{"example.com"}, true)
	identityRoundTrip(t, false, settingsAddr, `
resource "pushsecurity_settings" "this" {
  monitored_domains = ["example.com"]
}
`, map[string]knownvalue.Check{"id": knownvalue.StringExact("default")}, nil)
}

func TestIdentity_customDetection(t *testing.T) {
	offlineTenant(t)
	identityRoundTrip(t, false, "pushsecurity_custom_detection.test", `
resource "pushsecurity_custom_detection" "test" {
  name            = "Torrent website visit"
  detection_logic = "input: web_request\n"
  rules           = [{ name = "Monitor", enabled = true, mode = "MONITOR", severity = "LOW" }]
}
`, map[string]knownvalue.Check{
		"detection_event_type": knownvalue.StringExact("CUSTOM_TORRENT_WEBSITE_VISIT"),
	}, nil)
}

// TestIdentity_employee: the identity is the address lower-cased, so
// respelling it in configuration stays an update in place rather than an
// identity Terraform would refuse to see change.
func TestIdentity_employee(t *testing.T) {
	stub := offlineTenant(t)
	stub.addEmployee("ada@example.com", "Ada", "Lovelace", true)
	identity := map[string]knownvalue.Check{"email": knownvalue.StringExact("ada@example.com")}

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   identityVersions,
		Steps: []resource.TestStep{
			{
				Config:            `resource "pushsecurity_employee" "test" { email = "Ada@Example.com" }`,
				ConfigStateChecks: []statecheck.StateCheck{statecheck.ExpectIdentity(employeeAddr, identity)},
			},
			{
				Config: `resource "pushsecurity_employee" "test" { email = "ada@example.com" }`,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(employeeAddr, plancheck.ResourceActionUpdate),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
				ConfigStateChecks: []statecheck.StateCheck{statecheck.ExpectIdentity(employeeAddr, identity)},
			},
			{
				ResourceName:    employeeAddr,
				ImportState:     true,
				ImportStateKind: resource.ImportBlockWithResourceIdentity,
			},
			{
				// An identity written by hand may spell the address any way.
				// The import takes the address as written, as an import by
				// identifier does, so the configuration's spelling is an
				// update in place, not a replacement.
				ResourceName:           employeeAddr,
				ImportState:            true,
				ImportStateKind:        resource.ImportBlockWithResourceIdentity,
				ImportStateConfigExact: true,
				ExpectNonEmptyPlan:     true,
				ImportPlanChecks: resource.ImportPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(employeeAddr, plancheck.ResourceActionUpdate),
					},
				},
				Config: `
resource "pushsecurity_employee" "test" { email = "ada@example.com" }

import {
  to       = pushsecurity_employee.test
  identity = { email = "ADA@example.com" }
}
`,
			},
		},
	})
}

// TestIdentity_singletonIgnoresTheImportedValue: there is nothing to tell
// singletons apart by, so an import accepts any id, as the import identifier
// always has, and stores "default".
func TestIdentity_singletonIgnoresTheImportedValue(t *testing.T) {
	offlineTenant(t)
	const config = `
resource "pushsecurity_file_download_blocking" "test" {
  rules = [{ name = "Monitor", enabled = true, mode = "MONITOR" }]
}
`
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		TerraformVersionChecks:   identityVersions,
		Steps: []resource.TestStep{
			{Config: config},
			{
				ResourceName:           testResource,
				ImportState:            true,
				ImportStateKind:        resource.ImportBlockWithResourceIdentity,
				ImportStateConfigExact: true,
				Config: config + `
import {
  to       = pushsecurity_file_download_blocking.test
  identity = { id = "anything" }
}
`,
			},
		},
	})
}

// The same round trips against a real tenant, which is where the identity
// has to survive the API's own answers rather than the stub's.

func TestAccIdentity_control(t *testing.T) {
	identityRoundTrip(t, true, "pushsecurity_file_upload_blocking.test", `
resource "pushsecurity_file_upload_blocking" "test" {
  rules = [{ name = "Tf acceptance identity", enabled = true, mode = "MONITOR" }]
}
`, map[string]knownvalue.Check{"id": knownvalue.StringExact("default")},
		checkStoredRules(controlspec.FileUploadBlocking))
}

func TestAccIdentity_blockedURLs(t *testing.T) {
	identityRoundTrip(t, true, testBlockedURLs,
		`resource "pushsecurity_blocked_urls" "test" { patterns = ["tf-acc-identity.example.com"] }`,
		map[string]knownvalue.Check{"id": knownvalue.StringExact("default")},
		checkStoredBlockedURLs())
}

// TestAccIdentity_settings writes the tenant's settings back as they are, so
// it changes nothing, and destroy leaves them alone.
func TestAccIdentity_settings(t *testing.T) {
	if os.Getenv(resource.EnvTfAcc) == "" {
		t.Skipf("acceptance test; set %s to run it", resource.EnvTfAcc)
	}
	before, err := testAccClient(t).GetSettings(context.Background())
	if err != nil {
		t.Fatalf("reading the tenant's settings: %v", err)
	}
	quoted := make([]string, len(before.MonitoredDomains))
	for i, d := range before.MonitoredDomains {
		quoted[i] = fmt.Sprintf("%q", d)
	}
	identityRoundTrip(t, true, settingsAddr, fmt.Sprintf(`
resource "pushsecurity_settings" "this" {
  monitored_domains   = [%s]
  monitor_all_domains = %t
}
`, strings.Join(quoted, ", "), before.MonitorAllDomains),
		map[string]knownvalue.Check{"id": knownvalue.StringExact("default")}, nil)
}

func TestAccIdentity_customDetection(t *testing.T) {
	// Unkeyed, as an import leaves it, so that the import plans nothing.
	identityRoundTrip(t, true, "pushsecurity_custom_detection.test",
		detectionConfig("Tf acceptance identity", testDetectionLogic,
			`[{ name = "Monitor", enabled = true, mode = "MONITOR", severity = "LOW" }]`),
		map[string]knownvalue.Check{
			"detection_event_type": knownvalue.StringExact("CUSTOM_TF_ACCEPTANCE_IDENTITY"),
		}, nil)
}

// TestAccIdentity_employee adopts an employee the tenant already holds and
// changes nothing about them; destroy leaves them as they are.
func TestAccIdentity_employee(t *testing.T) {
	if os.Getenv(resource.EnvTfAcc) == "" {
		t.Skipf("acceptance test; set %s to run it", resource.EnvTfAcc)
	}
	licensed := true
	employees, err := testAccClient(t).ListEmployees(context.Background(),
		pushapi.EmployeeFilter{Licensed: &licensed})
	if err != nil {
		t.Fatalf("listing the tenant's employees: %v", err)
	}
	if len(employees) == 0 {
		t.Skip("the tenant holds no licensed employee to adopt")
	}
	// Lower-cased, as the identity is: an import takes the address as the
	// identity spells it, and any other spelling would plan an update.
	email := normaliseEmail(employees[0].Email)
	identityRoundTrip(t, true, employeeAddr,
		fmt.Sprintf(`resource "pushsecurity_employee" "test" { email = %q }`, email),
		map[string]knownvalue.Check{"email": knownvalue.StringExact(email)}, nil)
}

func testAccClient(t *testing.T) *pushapi.Client {
	t.Helper()
	testAccPreCheck(t)
	client, err := pushapi.New(os.Getenv(envBaseURL), os.Getenv(envAPIKey))
	if err != nil {
		t.Fatalf("building a client: %v", err)
	}
	return client
}
