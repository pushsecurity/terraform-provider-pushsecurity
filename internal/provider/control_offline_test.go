package provider

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"

	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/provider/controlspec"
	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/pushapi"
)

// The tests in this file drive the control resource through real terraform
// plan and apply runs against tenantStub, so they run on every pull request
// rather than only on the release pull request into main. They mirror the
// TestAcc lifecycle tests step for step, down to the checks of what the tenant
// stores; those remain the check that the stub's behaviours are the API's.

// TestControlResource_lifecycle is TestAccControlResource_lifecycle without
// the tenant: create, edit, reorder, insert, remove, import, destroy.
func TestControlResource_lifecycle(t *testing.T) {
	offlineTenant(t)
	spec := controlspec.FileDownloadBlocking
	var blockID, monitorID string

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		// There is no delete verb: destroy writes an empty document.
		CheckDestroy: checkStoredRules(spec),
		Steps: []resource.TestStep{
			{
				Config: testAccTwoRules,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(testResource, "rules.#", "2"),
					resource.TestCheckResourceAttr(testResource, "rules.0.key", "block"),
					resource.TestCheckResourceAttr(testResource, "rules.0.mode", "BLOCK"),
					resource.TestCheckResourceAttr(testResource, "rules.1.key", "monitor"),
					resource.TestCheckResourceAttr(testResource, "rules.0.criteria.file_extensions.action", "INCLUDE"),
					resource.TestCheckResourceAttr(testResource, "rules.0.criteria.employee_groups.action", "EXCLUDE"),
					resource.TestCheckResourceAttr(testResource, "rules.0.criteria.profile_scope", "ALL"),
					resource.TestCheckResourceAttr(testResource, "rules.1.criteria.profile_scope", "ALL"),
					resource.TestCheckNoResourceAttr(testResource, "rules.1.title"),
					captureRuleID(testResource, 0, &blockID),
					captureRuleID(testResource, 1, &monitorID),
					// What the tenant was sent, which state cannot show. Among
					// other things, a text field left out of configuration is
					// left out of the request, not sent as null: the stub keeps
					// a null, and the API rejects one where it accepts absence.
					checkStoredRules(spec, storedBlockRule("Download blocked"), storedMonitorRule),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
			{
				Config: testAccTwoRulesEdited,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(testResource, "rules.0.title", "Blocked by policy"),
					checkRuleID(testResource, 0, &blockID),
					checkRuleID(testResource, 1, &monitorID),
					checkStoredRules(spec, storedBlockRule("Blocked by policy"), storedMonitorRule),
				),
			},
			{
				// Identifiers must move with the keys, not stay with the
				// positions. The stub assigns a fresh identifier to any rule
				// sent without one, so a provider that dropped them here
				// would fail the checks rather than pass by accident.
				Config: testAccTwoRulesReordered,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(testResource, "rules.0.key", "monitor"),
					resource.TestCheckResourceAttr(testResource, "rules.1.key", "block"),
					checkRuleID(testResource, 0, &monitorID),
					checkRuleID(testResource, 1, &blockID),
					checkStoredRules(spec, storedMonitorRule, storedBlockRule("Blocked by policy")),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
			{
				Config: testAccThreeRules,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(testResource, "rules.#", "3"),
					resource.TestCheckResourceAttr(testResource, "rules.0.key", "inserted"),
					resource.TestCheckResourceAttrSet(testResource, "rules.0.id"),
					checkRuleID(testResource, 1, &monitorID),
					checkRuleID(testResource, 2, &blockID),
					checkStoredRules(spec, storedInsertedRule, storedMonitorRule, storedBlockRule("Blocked by policy")),
				),
			},
			{
				// Removing a rule must delete it on the tenant.
				Config: testAccOneRule,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(testResource, "rules.#", "1"),
					checkRuleID(testResource, 0, &blockID),
					checkStoredRules(spec, storedBlockRule("Blocked by policy")),
				),
			},
			{
				ResourceName:                         testResource,
				ImportState:                          true,
				ImportStateId:                        "default",
				ImportStateVerify:                    true,
				ImportStateVerifyIgnore:              []string{"rules.0.key"},
				ImportStateVerifyIdentifierAttribute: "rules.#",
			},
		},
	})
}

// TestAllControls_smokeOffline runs the configuration TestAccAllControls_smoke
// generates for every control against the stub, so that a control whose
// minimal rule does not even pass plan is caught here rather than in the run
// against a real tenant.
func TestAllControls_smokeOffline(t *testing.T) {
	for _, spec := range controlspec.All {
		t.Run(spec.TypeName, func(t *testing.T) {
			offlineTenant(t)
			rule := minimalConfig(spec)
			addr := spec.ResourceName() + ".smoke"

			resource.UnitTest(t, resource.TestCase{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				CheckDestroy:             checkStoredRules(spec),
				Steps: []resource.TestStep{{
					Config: rule.config,
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttr(addr, "rules.0.mode", rule.mode),
						checkStoredRules(spec, rule.stored),
					),
					ConfigPlanChecks: resource.ConfigPlanChecks{
						PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
					},
				}},
			})
		})
	}
}

// TestAllControls_maximalOffline runs the configuration
// TestAccAllControls_maximal generates for every control against the stub,
// two seeded employees standing in for the tenant's.
//
// It also pins what the generated rules leave out. Every field and criterion
// is in the rule unless the spec makes it inapplicable there, and the only
// such case is clipboard blocking's acknowledge button, which the API rejects
// on a rule that matches regex patterns. Anything else dropped is a gap in
// the live coverage, so it fails here rather than going unnoticed.
func TestAllControls_maximalOffline(t *testing.T) {
	wantOmitted := map[string][]string{
		"clipboard_blocking": {"acknowledge_button_text"},
	}

	for _, spec := range controlspec.All {
		t.Run(spec.TypeName, func(t *testing.T) {
			stub := offlineTenant(t)
			var employees []pushapi.Employee
			for _, email := range []string{"tfacc-b@example.com", "tfacc-a@example.com"} {
				id := stub.addEmployee(email, "Terraform", "Acceptance", true)
				employees = append(employees, pushapi.Employee{ID: id, Email: email})
			}
			rule := mustMaximalConfig(t, spec, employees)

			var omitted []string
			for _, o := range rule.omitted {
				name, _, _ := strings.Cut(o, " ")
				omitted = append(omitted, name)
			}
			if want := wantOmitted[spec.TypeName]; !slices.Equal(omitted, want) {
				t.Fatalf("the maximal rule leaves out %q, want %q", omitted, want)
			}

			resource.UnitTest(t, maximalTestCase(spec, rule))
		})
	}
}

// TestAllControls_parallelOffline is TestAccAllControls_parallel against the
// stub: every control's minimal rule in one configuration, applied and
// destroyed at Terraform's default parallelism.
func TestAllControls_parallelOffline(t *testing.T) {
	offlineTenant(t)
	log := logRequests(t)
	t.Cleanup(func() { checkNotRateLimited(t, log) })
	resource.UnitTest(t, parallelTestCase())
}

// TestControlResource_changedOutsideTerraform is
// TestAccControlResource_changedOutsideTerraform against the stub: a rule
// changed, one added and one deleted over the API show up as drift, and the
// apply restores the configuration without the survivor losing its
// identifier.
func TestControlResource_changedOutsideTerraform(t *testing.T) {
	offlineTenant(t)
	resource.UnitTest(t, driftTestCase(t))
}

// TestControlResource_emptyRules is the destroy semantics, stated directly.
func TestControlResource_emptyRules(t *testing.T) {
	offlineTenant(t)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `resource "pushsecurity_file_download_blocking" "test" { rules = [] }`,
				Check:  resource.TestCheckResourceAttr(testResource, "rules.#", "0"),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
		},
	})
}

// TestControlResource_unkeyedRules pins the documented degradation: rules
// without a key work, the practitioner is warned, and a reorder moves the
// identifiers by position rather than with the rules.
func TestControlResource_unkeyedRules(t *testing.T) {
	offlineTenant(t)
	log := &diagnosticLog{}
	var firstID, secondID string

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: log.factories(),
		Steps: []resource.TestStep{
			{
				Config: `
resource "pushsecurity_file_download_blocking" "test" {
  rules = [
    { name = "one", enabled = true, mode = "MONITOR" },
    { name = "two", enabled = true, mode = "OFF" },
  ]
}`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(testResource, "rules.#", "2"),
					resource.TestCheckNoResourceAttr(testResource, "rules.0.key"),
					captureRuleID(testResource, 0, &firstID),
					captureRuleID(testResource, 1, &secondID),
					checkWarned(log, "Rules without a key are matched by position"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
			{
				// Swapped. Without keys there is nothing to follow, so the
				// first identifier stays on the first position.
				Config: `
resource "pushsecurity_file_download_blocking" "test" {
  rules = [
    { name = "two", enabled = true, mode = "OFF" },
    { name = "one", enabled = true, mode = "MONITOR" },
  ]
}`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(testResource, "rules.0.name", "two"),
					checkRuleID(testResource, 0, &firstID),
					checkRuleID(testResource, 1, &secondID),
				),
			},
		},
	})
}

// TestControlResource_adoption is TestAccControlResource_adoption without the
// tenant: rules that exist without Terraform having made them are imported,
// and the apply that adds keys to them keeps their identifiers.
func TestControlResource_adoption(t *testing.T) {
	stub := offlineTenant(t)
	var blockID, monitorID string

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// The seed mirrors testAccTwoRules minus the keys, which the
				// API never sees. checkImportedUnkeyedRules keeps the two in
				// step.
				PreConfig: func() {
					ids := stub.seedControl(controlspec.FileDownloadBlocking,
						map[string]any{
							"name": "Block executables", "enabled": true, "mode": "BLOCK",
							"title": "Download blocked", "subtext": "Not permitted on company devices.",
							"criteria": map[string]any{
								"fileExtensions": map[string]any{"matches": []any{".exe", ".msi"}},
								"employeeGroups": map[string]any{"matches": []any{"Contractors"}, "action": "EXCLUDE"},
							},
						},
						map[string]any{"name": "Monitor the rest", "enabled": true, "mode": "MONITOR"},
					)
					blockID, monitorID = ids[0], ids[1]
				},
				Config: testAccTwoRules,

				ResourceName:       testResource,
				ImportState:        true,
				ImportStateId:      "default",
				ImportStatePersist: true,
				ImportStateCheck:   checkImportedUnkeyedRules,
			},
			{
				// The same rules with keys added: a no-op on the tenant, and
				// it has to be a no-op on identity too. Without the positional
				// fallback every rule would be sent without an identifier and
				// the stub, like the API, would hand out new ones.
				Config: testAccTwoRules,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(testResource, "rules.#", "2"),
					resource.TestCheckResourceAttr(testResource, "rules.0.key", "block"),
					resource.TestCheckResourceAttr(testResource, "rules.1.key", "monitor"),
					checkRuleID(testResource, 0, &blockID),
					checkRuleID(testResource, 1, &monitorID),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
			{
				// State now carries keys, so a reorder follows them.
				Config: testAccTwoRulesReordered,
				Check: resource.ComposeAggregateTestCheckFunc(
					checkRuleID(testResource, 0, &monitorID),
					checkRuleID(testResource, 1, &blockID),
				),
			},
		},
	})
}

// departedEmployeeWarning is what a read raises for a rule naming an employee
// the tenant no longer holds; its detail is pinned in employee_criteria_test.go.
const departedEmployeeWarning = "Rule names an employee the tenant no longer holds"

// seedDepartedRule seeds one rule whose employee criterion names only an
// employee the tenant no longer holds: the stub holds no employees at all.
func seedDepartedRule(action string, extra map[string]any) map[string]any {
	rule := map[string]any{
		"name": "Departed", "enabled": true, "mode": "MONITOR",
		"criteria": map[string]any{
			"employeeIds": map[string]any{"matches": []any{"departed-employee-id"}, "action": action},
		},
	}
	for k, v := range extra {
		rule[k] = v
	}
	return rule
}

// generatedImport is an import step whose resource block Terraform generates
// from the imported state, which is what `terraform plan -generate-config-out`
// does and what `terraform query -generate-config-out` writes.
func generatedImport(addr, id string) resource.TestStep {
	return resource.TestStep{
		// Only the import block is written.
		Config:          `# generated`,
		ResourceName:    addr,
		ImportState:     true,
		ImportStateKind: resource.ImportBlockWithID,
		ImportStateId:   id,
		GenerateConfig:  true,
	}
}

// TestControlResource_generatedConfigExcludingOnlyDepartedEmployees: a rule
// that excludes only employees the tenant no longer holds excludes nobody,
// which is a rule with no employee criterion, so that is how it is read and
// the configuration generated from it imports with an empty plan.
func TestControlResource_generatedConfigExcludingOnlyDepartedEmployees(t *testing.T) {
	stub := offlineTenant(t)
	stub.seedControl(controlspec.FileDownloadBlocking, seedDepartedRule("EXCLUDE", nil))
	log := &diagnosticLog{}

	step := generatedImport(testResource, "default")
	step.ImportPlanChecks.PreApply = []plancheck.PlanCheck{
		plancheck.ExpectKnownValue(testResource,
			tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("criteria").AtMapKey("employee_ids"),
			knownvalue.Null()),
	}
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: log.factories(),
		Steps:                    []resource.TestStep{step},
	})
	if !log.warned(departedEmployeeWarning) {
		t.Errorf("no warning %q was raised", departedEmployeeWarning)
	}
}

// TestControlResource_generatedConfigIncludingOnlyDepartedEmployees: a rule
// that applies only to employees the tenant no longer holds applies to nobody,
// which configuration cannot say. The generated configuration fails plan with
// what to write instead, and writing it — the rule disabled, its employee
// criterion gone — adopts the rule.
func TestControlResource_generatedConfigIncludingOnlyDepartedEmployees(t *testing.T) {
	stub := offlineTenant(t)
	spec := controlspec.FileDownloadBlocking
	stub.seedControl(spec, seedDepartedRule("INCLUDE", nil))
	log := &diagnosticLog{}

	generated := generatedImport(testResource, "default")
	generated.ExpectError = regexp.MustCompile(`(?s)Employee criterion names nobody.*enabled = false`)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: log.factories(),
		Steps: []resource.TestStep{
			generated,
			{
				Config: `
import {
  to = pushsecurity_file_download_blocking.test
  id = "default"
}

resource "pushsecurity_file_download_blocking" "test" {
  rules = [{ name = "Departed", enabled = false, mode = "MONITOR" }]
}
`,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(testResource, plancheck.ResourceActionUpdate),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
				Check: func(*terraform.State) error {
					rules := stub.rules(spec)
					if len(rules) != 1 {
						return fmt.Errorf("the tenant holds %d rules, want 1", len(rules))
					}
					if rules[0]["enabled"] != false {
						return fmt.Errorf("the rule is stored enabled = %v, want false", rules[0]["enabled"])
					}
					if crit, _ := rules[0]["criteria"].(map[string]any); crit["employeeIds"] != nil {
						return fmt.Errorf("the rule still holds an employee criterion: %v", crit["employeeIds"])
					}
					return nil
				},
			},
		},
	})
	if !log.warned(departedEmployeeWarning) {
		t.Errorf("no warning %q was raised", departedEmployeeWarning)
	}
}

// TestControlResource_enumSetField covers the one field type the file
// download control does not have: a set of enum values, which the server
// returns in an order of its own.
func TestControlResource_enumSetField(t *testing.T) {
	offlineTenant(t)
	const addr = "pushsecurity_strong_password_enforcement.test"
	var id string

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "pushsecurity_strong_password_enforcement" "test" {
  rules = [{
    key                 = "ack"
    name                = "Acknowledge weak passwords"
    enabled             = true
    mode                = "ACKNOWLEDGE"
    title               = "Weak password"
    subtext             = "Change it before you carry on."
    button_text         = "Understood"
    applicable_findings = ["WEAK_PASSWORD", "REUSED_PASSWORD"]
    criteria = {
      app_labels = { matches = ["Finance"] }
    }
  }]
}`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(addr, "rules.0.applicable_findings.#", "2"),
					resource.TestCheckTypeSetElemAttr(addr, "rules.0.applicable_findings.*", "WEAK_PASSWORD"),
					resource.TestCheckTypeSetElemAttr(addr, "rules.0.applicable_findings.*", "REUSED_PASSWORD"),
					resource.TestCheckResourceAttr(addr, "rules.0.criteria.app_labels.action", "INCLUDE"),
					// This control has no profile scope, so none is injected.
					resource.TestCheckNoResourceAttr(addr, "rules.0.criteria.profile_scope"),
					captureRuleID(addr, 0, &id),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
			{
				Config: `
resource "pushsecurity_strong_password_enforcement" "test" {
  rules = [{
    key                 = "ack"
    name                = "Acknowledge weak passwords"
    enabled             = true
    mode                = "ACKNOWLEDGE"
    title               = "Weak password"
    subtext             = "Change it before you carry on."
    button_text         = "Understood"
    applicable_findings = ["LEAKED_PASSWORD", "WEAK_PASSWORD", "STOLEN_CREDENTIALS"]
    criteria = {
      app_labels = { matches = ["Finance"] }
    }
  }]
}`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(addr, "rules.0.applicable_findings.#", "3"),
					checkRuleID(addr, 0, &id),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
		},
	})
}

// TestControlResource_serverDefaultFields covers fields the server fills in
// when they are omitted, which the schema has to plan to the same value or
// every apply would be followed by a diff. The malicious copy/paste control
// has one of each kind, a bool and an enum, plus the sorted ignored_hosts
// global.
func TestControlResource_serverDefaultFields(t *testing.T) {
	offlineTenant(t)
	const addr = "pushsecurity_malicious_copy_paste_detection.test"
	var id string

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "pushsecurity_malicious_copy_paste_detection" "test" {
  globals = {
    ignored_hosts = ["b.example.com", "a.example.com"]
  }
  rules = [{
    key     = "monitor"
    name    = "Monitor pastes"
    enabled = true
    mode    = "MONITOR"
  }]
}`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(addr, "rules.0.payload_collection", "false"),
					resource.TestCheckResourceAttr(addr, "rules.0.os_target", "WINDOWS"),
					resource.TestCheckResourceAttr(addr, "globals.ignored_hosts.#", "2"),
					captureRuleID(addr, 0, &id),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
			{
				// Set explicitly, and away from the defaults.
				Config: `
resource "pushsecurity_malicious_copy_paste_detection" "test" {
  rules = [{
    key                = "monitor"
    name               = "Monitor pastes"
    enabled            = true
    mode               = "MONITOR"
    payload_collection = true
    os_target          = "UNIX"
  }]
}`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(addr, "rules.0.payload_collection", "true"),
					resource.TestCheckResourceAttr(addr, "rules.0.os_target", "UNIX"),
					// Dropping the globals block plans to the empty default,
					// which is what the server holds once they are gone.
					resource.TestCheckResourceAttr(addr, "globals.ignored_hosts.#", "0"),
					checkRuleID(addr, 0, &id),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
		},
	})
}

// TestControlResource_computedGlobals covers a global the server adds to: a
// clipboard custom content pattern's enum is derived from its name on write,
// so the attribute is computed, and a rule may reference it.
func TestControlResource_computedGlobals(t *testing.T) {
	offlineTenant(t)
	const addr = "pushsecurity_clipboard_blocking.test"

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "pushsecurity_clipboard_blocking" "test" {
  globals = {
    custom_content_patterns = [
      { name = "Incident ticket", regex = "INC-\\d{6}" },
    ]
  }
  rules = [{
    key             = "monitor"
    name            = "Monitor incident references"
    enabled         = true
    mode            = "MONITOR"
    operation       = "PASTE"
    content_capture = false
    criteria = {
      regex_patterns = { matches = ["CUSTOM_INCIDENT_TICKET"] }
    }
  }]
}`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(addr, "globals.custom_content_patterns.#", "1"),
					resource.TestCheckResourceAttr(addr, "globals.custom_content_patterns.0.enum", "CUSTOM_INCIDENT_TICKET"),
					resource.TestCheckResourceAttr(addr, "rules.0.criteria.profile_scope", "ALL"),
					resource.TestCheckResourceAttr(addr, "rules.0.content_capture", "false"),
					resource.TestCheckNoResourceAttr(addr, "rules.0.mask_pii"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
			{
				// A second pattern, and the first renamed: both enums are
				// recomputed and the plan after settles.
				Config: `
resource "pushsecurity_clipboard_blocking" "test" {
  globals = {
    custom_content_patterns = [
      { name = "Incident reference", regex = "INC-\\d{6}" },
      { name = "Change request", regex = "CHG-\\d{6}" },
    ]
  }
  rules = [{
    key             = "monitor"
    name            = "Monitor incident references"
    enabled         = true
    mode            = "MONITOR"
    operation       = "PASTE"
    content_capture = false
    criteria = {
      regex_patterns = { matches = ["CUSTOM_INCIDENT_REFERENCE", "CUSTOM_CHANGE_REQUEST"] }
    }
  }]
}`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(addr, "globals.custom_content_patterns.#", "2"),
					resource.TestCheckResourceAttr(addr, "globals.custom_content_patterns.0.enum", "CUSTOM_INCIDENT_REFERENCE"),
					resource.TestCheckResourceAttr(addr, "globals.custom_content_patterns.1.enum", "CUSTOM_CHANGE_REQUEST"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
			{
				ResourceName:                         addr,
				ImportState:                          true,
				ImportStateId:                        "default",
				ImportStateVerify:                    true,
				ImportStateVerifyIgnore:              []string{"rules.0.key"},
				ImportStateVerifyIdentifierAttribute: "rules.#",
			},
		},
	})
}

// TestControlResource_accountConditionEnforcement covers the shapes only
// account condition enforcement has: two required criteria, one of them
// single-valued with no default, and login domains that the domain scope
// requires or forbids. It adopts rules as a client writes them, keys them,
// changes one's mode and scope, and imports the result.
// TestAccControlResource_accountConditionEnforcement runs the same steps
// against a real tenant.
func TestControlResource_accountConditionEnforcement(t *testing.T) {
	stub := offlineTenant(t)
	spec := controlspec.AccountConditionEnforcement
	const addr = "pushsecurity_account_condition_enforcement.test"
	var warnID, monitorID string

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             checkStoredRules(spec),
		Steps: []resource.TestStep{
			{
				PreConfig: func() {
					ids := stub.seedControl(spec, aceSeedRules()...)
					warnID, monitorID = ids[0], ids[1]
				},
				Config:             testACEWarn,
				ResourceName:       addr,
				ImportState:        true,
				ImportStateId:      "default",
				ImportStatePersist: true,
				ImportStateCheck:   checkImportedACESeed(spec),
			},
			{
				// Keys added to what was imported: nothing changes on the
				// tenant, and the identifiers stay where they were.
				Config: testACEWarn,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(addr, "rules.#", "2"),
					resource.TestCheckResourceAttr(addr, "rules.0.criteria.login_domains.action", "INCLUDE"),
					resource.TestCheckResourceAttr(addr, "rules.0.criteria.login_types.action", "INCLUDE"),
					checkRuleID(addr, 0, &warnID),
					checkRuleID(addr, 1, &monitorID),
					checkStoredRules(spec, storedACEWarnRule, storedACEMonitorRule),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
			{
				// WARN to BLOCK drops the continue button, and a company
				// domain scope drops the login domains. Both have to leave
				// the request, since the API rejects either one here.
				Config: testACEBlock,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(addr, "rules.0.mode", "BLOCK"),
					resource.TestCheckNoResourceAttr(addr, "rules.0.continue_button_text"),
					resource.TestCheckResourceAttr(addr, "rules.0.criteria.domain_scope", "COMPANY_DOMAINS"),
					resource.TestCheckNoResourceAttr(addr, "rules.0.criteria.login_domains.matches.#"),
					checkRuleID(addr, 0, &warnID),
					checkStoredRules(spec, storedACEBlockRule, storedACEMonitorRule),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
			{
				ResourceName:                         addr,
				ImportState:                          true,
				ImportStateId:                        "default",
				ImportStateVerify:                    true,
				ImportStateVerifyIgnore:              []string{"rules.0.key", "rules.1.key"},
				ImportStateVerifyIdentifierAttribute: "rules.#",
			},
		},
	})
}

// aceSeedRules are testACEWarn's rules without keys, as a client writes them:
// no action where the API defaults one, and no profile scope. They are built
// afresh on each call because the stub keeps and fills in what it is given.
func aceSeedRules() []map[string]any {
	return []map[string]any{
		{
			"name": "Warn on personal accounts", "enabled": true, "mode": "WARN",
			"title": "Personal account", "subtext": "Use your **work** account.",
			"terminateButtonText": "Sign out", "continueButtonText": "Continue anyway",
			"criteria": map[string]any{
				"appTypes":     map[string]any{"matches": []any{"OPENAI_CHATGPT", "ANTHROPIC_CLAUDE"}},
				"domainScope":  map[string]any{"matches": []any{"SPECIFIC_DOMAINS"}},
				"loginDomains": map[string]any{"matches": []any{"personal-mail.example"}},
				"loginTypes":   map[string]any{"matches": []any{"PASSWORD_LOGIN"}},
				"browserTypes": map[string]any{"matches": []any{"SAFARI"}, "action": "EXCLUDE"},
			},
		},
		{
			"name": "Monitor non-company logins", "enabled": true, "mode": "MONITOR",
			"criteria": map[string]any{
				"appTypes":    map[string]any{"matches": []any{"GITHUB"}},
				"domainScope": map[string]any{"matches": []any{"NON_COMPANY_DOMAINS"}},
			},
		},
	}
}

// checkImportedACESeed asserts what the import of aceSeedRules read, and what
// the tenant holds: the seed with INCLUDE on the excludable conditions sent
// without an action, and profileScope ALL on rules sent without one. State
// alone cannot show either, since the provider reads both of them that way
// whether the API returned them or not.
func checkImportedACESeed(spec controlspec.Spec) resource.ImportStateCheckFunc {
	return func(states []*terraform.InstanceState) error {
		if len(states) != 1 {
			return fmt.Errorf("imported %d instances, want 1", len(states))
		}
		for attr, want := range map[string]string{
			"rules.0.criteria.domain_scope":         "SPECIFIC_DOMAINS",
			"rules.0.criteria.app_types.matches.#":  "2",
			"rules.0.criteria.browser_types.action": "EXCLUDE",
			"rules.0.criteria.profile_scope":        "ALL",
			"rules.1.criteria.domain_scope":         "NON_COMPANY_DOMAINS",
			"rules.1.criteria.profile_scope":        "ALL",
		} {
			if got := states[0].Attributes[attr]; got != want {
				return fmt.Errorf("imported %s = %q, want %q", attr, got, want)
			}
		}
		return checkStoredRules(spec, storedACEWarnRule, storedACEMonitorRule)(nil)
	}
}

// storedACEWarnRule, storedACEBlockRule and storedACEMonitorRule are the rules
// of testACEWarn and testACEBlock as the API should hold them.
//
// domainScope and appTypes are include-only: the API rejects an action on
// either, and must not hold one. The excludable conditions hold the action
// they were sent, or INCLUDE. profileScope holds ALL where it was omitted, and
// no action.
var storedACEWarnRule = map[string]any{
	"name": "Warn on personal accounts", "enabled": true, "mode": "WARN",
	"title": "Personal account", "subtext": "Use your **work** account.",
	"terminateButtonText": "Sign out", "continueButtonText": "Continue anyway",
	"criteria": map[string]any{
		"appTypes":     map[string]any{"matches": []any{"OPENAI_CHATGPT", "ANTHROPIC_CLAUDE"}},
		"domainScope":  map[string]any{"matches": []any{"SPECIFIC_DOMAINS"}},
		"loginDomains": map[string]any{"matches": []any{"personal-mail.example"}, "action": "INCLUDE"},
		"loginTypes":   map[string]any{"matches": []any{"PASSWORD_LOGIN"}, "action": "INCLUDE"},
		"browserTypes": map[string]any{"matches": []any{"SAFARI"}, "action": "EXCLUDE"},
		"profileScope": map[string]any{"matches": []any{"ALL"}},
	},
}

// storedACEBlockRule is the same rule switched to BLOCK with a company domain
// scope: no continueButtonText, which BLOCK forbids, and no loginDomains,
// which only SPECIFIC_DOMAINS takes.
var storedACEBlockRule = map[string]any{
	"name": "Block personal accounts", "enabled": true, "mode": "BLOCK",
	"title": "Personal account", "subtext": "Use your **work** account.",
	"terminateButtonText": "Sign out",
	"criteria": map[string]any{
		"appTypes":     map[string]any{"matches": []any{"OPENAI_CHATGPT", "ANTHROPIC_CLAUDE"}},
		"domainScope":  map[string]any{"matches": []any{"COMPANY_DOMAINS"}},
		"loginTypes":   map[string]any{"matches": []any{"PASSWORD_LOGIN"}, "action": "INCLUDE"},
		"browserTypes": map[string]any{"matches": []any{"SAFARI"}, "action": "EXCLUDE"},
		"profileScope": map[string]any{"matches": []any{"NON_COMPANY_DOMAIN"}},
	},
}

var storedACEMonitorRule = map[string]any{
	"name": "Monitor non-company logins", "enabled": true, "mode": "MONITOR",
	"criteria": map[string]any{
		"appTypes":     map[string]any{"matches": []any{"GITHUB"}},
		"domainScope":  map[string]any{"matches": []any{"NON_COMPANY_DOMAINS"}},
		"profileScope": map[string]any{"matches": []any{"ALL"}},
	},
}

const testACEWarn = `
resource "pushsecurity_account_condition_enforcement" "test" {
  rules = [
    {
      key                   = "warn-personal"
      name                  = "Warn on personal accounts"
      enabled               = true
      mode                  = "WARN"
      title                 = "Personal account"
      subtext               = "Use your **work** account."
      terminate_button_text = "Sign out"
      continue_button_text  = "Continue anyway"
      criteria = {
        app_types     = { matches = ["OPENAI_CHATGPT", "ANTHROPIC_CLAUDE"] }
        domain_scope  = "SPECIFIC_DOMAINS"
        login_domains = { matches = ["personal-mail.example"] }
        login_types   = { matches = ["PASSWORD_LOGIN"] }
        browser_types = { matches = ["SAFARI"], action = "EXCLUDE" }
      }
    },
    {
      key     = "monitor-rest"
      name    = "Monitor non-company logins"
      enabled = true
      mode    = "MONITOR"
      criteria = {
        app_types    = { matches = ["GITHUB"] }
        domain_scope = "NON_COMPANY_DOMAINS"
      }
    },
  ]
}`

const testACEBlock = `
resource "pushsecurity_account_condition_enforcement" "test" {
  rules = [
    {
      key                   = "warn-personal"
      name                  = "Block personal accounts"
      enabled               = true
      mode                  = "BLOCK"
      title                 = "Personal account"
      subtext               = "Use your **work** account."
      terminate_button_text = "Sign out"
      criteria = {
        app_types     = { matches = ["OPENAI_CHATGPT", "ANTHROPIC_CLAUDE"] }
        domain_scope  = "COMPANY_DOMAINS"
        login_types   = { matches = ["PASSWORD_LOGIN"] }
        browser_types = { matches = ["SAFARI"], action = "EXCLUDE" }
        profile_scope = "NON_COMPANY_DOMAIN"
      }
    },
    {
      key     = "monitor-rest"
      name    = "Monitor non-company logins"
      enabled = true
      mode    = "MONITOR"
      criteria = {
        app_types    = { matches = ["GITHUB"] }
        domain_scope = "NON_COMPANY_DOMAINS"
      }
    },
  ]
}`

// TestControlResource_globalsErrorStopsTheWrite: a global that cannot be
// converted for the API fails the apply before anything is sent, rather than
// writing the control without it.
func TestControlResource_globalsErrorStopsTheWrite(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	client, err := pushapi.New(srv.URL, "offline-test-key", pushapi.WithMaxRetries(0))
	if err != nil {
		t.Fatal(err)
	}

	spec := controlspec.Spec{
		APIName: "testControl",
		Globals: []controlspec.Global{{
			Name: "items", APIName: "items", Type: controlspec.GlobalObjectList,
			Attributes: []controlspec.Field{{Name: "modes", APIName: "modes", Type: controlspec.TypeEnumSet}},
		}},
	}
	// A set of numbers where the spec expects strings: the conversion fails.
	modes := types.SetValueMust(types.Int64Type, []attr.Value{types.Int64Value(1)})
	itemType := types.ObjectType{AttrTypes: map[string]attr.Type{"modes": modes.Type(context.Background())}}
	item := types.ObjectValueMust(itemType.AttrTypes, map[string]attr.Value{"modes": modes})
	globals := types.ObjectValueMust(
		map[string]attr.Type{"items": types.ListType{ElemType: itemType}},
		map[string]attr.Value{"items": types.ListValueMust(itemType, []attr.Value{item})},
	)

	r := &controlResource{spec: spec, client: client}
	plan := fakePlan{
		"rules":   types.ListValueMust(types.ObjectType{AttrTypes: map[string]attr.Type{}}, nil),
		"globals": globals,
	}
	var diags diag.Diagnostics
	r.write(context.Background(), plan, nil, fakeState{}, &diags)

	if !diags.HasError() {
		t.Fatal("write succeeded with a global that could not be converted")
	}
	if n := requests.Load(); n != 0 {
		t.Errorf("sent %d requests, want none", n)
	}
}

// fakePlan serves top-level attributes to write.
type fakePlan map[string]attr.Value

func (p fakePlan) GetAttribute(_ context.Context, at path.Path, target any) diag.Diagnostics {
	var diags diag.Diagnostics
	v := p[at.String()]
	switch t := target.(type) {
	case *types.List:
		*t = v.(types.List)
	case *types.Object:
		*t = v.(types.Object)
	default:
		diags.AddError("unexpected target", fmt.Sprintf("%T", target))
	}
	return diags
}

type fakeState struct{}

func (fakeState) SetAttribute(context.Context, path.Path, any) diag.Diagnostics { return nil }

// TestControlResource_rejectedWritePointsAtTheAttribute checks a write the API
// refuses is reported against the part of the configuration at fault — a rule
// field by its index and attribute name, a control-wide setting under globals
// — and that a failure with no field errors is still reported, without one.
//
// Every write that reaches the tenant here is refused, in the shape tenantStub
// gives the API's validation failures.
func TestControlResource_rejectedWritePointsAtTheAttribute(t *testing.T) {
	spec := controlspec.ClonedLoginPageDetection

	write := func(t *testing.T, answer http.HandlerFunc) diag.Diagnostics {
		t.Helper()
		srv := httptest.NewServer(answer)
		t.Cleanup(srv.Close)
		client, err := pushapi.New(srv.URL, "offline-test-key", pushapi.WithMaxRetries(0))
		if err != nil {
			t.Fatal(err)
		}
		r := &controlResource{spec: spec, client: client}
		plan := fakePlan{
			"rules":   types.ListValueMust(ruleObjectType(spec), nil),
			"globals": defaultGlobals(spec),
		}
		var diags diag.Diagnostics
		r.write(context.Background(), plan, nil, fakeState{}, &diags)
		return diags
	}

	t.Run("field errors", func(t *testing.T) {
		errs := map[string]any{}
		fieldError(errs, "Title is required for mode BLOCK.", "rules", "1", "title")
		fieldError(errs, "Not a valid hostname.", "globals", "ignoredHosts")
		diags := write(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			invalidInput(w, errs)
		})

		want := map[string]string{
			path.Root("rules").AtListIndex(1).AtName("title").String(): "Title is required",
			path.Root("globals").AtName("ignored_hosts").String():      "Not a valid hostname",
		}
		for _, d := range diags.Errors() {
			wp, ok := d.(diag.DiagnosticWithPath)
			if !ok {
				t.Errorf("error without an attribute: %s: %s", d.Summary(), d.Detail())
				continue
			}
			at := wp.Path().String()
			text, expected := want[at]
			if !expected {
				t.Errorf("error at %s, which is not where the API put it: %s", at, d.Detail())
				continue
			}
			if d.Summary() != "Push API rejected the configuration" || !strings.Contains(d.Detail(), text) {
				t.Errorf("error at %s is %q: %q, want the API's message %q", at, d.Summary(), d.Detail(), text)
			}
			delete(want, at)
		}
		for at := range want {
			t.Errorf("no error reported at %s", at)
		}
		if diags.WarningsCount() != 1 || diags.Warnings()[0].Summary() != "Validation happened at apply time" {
			t.Errorf("warnings = %v, want one saying the validation happened at apply time", diags.Warnings())
		}
	})

	t.Run("failure without field errors", func(t *testing.T) {
		diags := write(t, func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusInternalServerError, map[string]string{
				"status": "INTERNAL_ERROR", "message": "Something went wrong.",
			})
		})
		errs := diags.Errors()
		if len(errs) != 1 {
			t.Fatalf("errors = %v, want one", errs)
		}
		if _, ok := errs[0].(diag.DiagnosticWithPath); ok {
			t.Errorf("error is on an attribute, but nothing in the response names one: %v", errs[0])
		}
		if got := errs[0].Summary(); got != "Push API returned HTTP 500" {
			t.Errorf("summary = %q, want Push API returned HTTP 500", got)
		}
		for _, want := range []string{"write", spec.APIName, "Something went wrong."} {
			if !strings.Contains(errs[0].Detail(), want) {
				t.Errorf("detail %q does not mention %q", errs[0].Detail(), want)
			}
		}
	})
}

// TestControlResource_clipboardAcknowledgeButton writes the one rule text field
// no other test does: the button that dismisses a clipboard banner, which the
// API takes only on a BLOCK rule that does not match regex patterns.
func TestControlResource_clipboardAcknowledgeButton(t *testing.T) {
	offlineTenant(t)
	spec := controlspec.ClipboardBlocking
	const addr = "pushsecurity_clipboard_blocking.test"

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             checkStoredRules(spec),
		Steps: []resource.TestStep{
			{
				Config: `
resource "pushsecurity_clipboard_blocking" "test" {
  rules = [{
    key                     = "block-paste"
    name                    = "Block pasting into example.com"
    enabled                 = true
    mode                    = "BLOCK"
    operation               = "PASTE"
    content_capture         = false
    title                   = "Paste blocked"
    subtext                 = "Pasting into this site is not permitted."
    acknowledge_button_text = "Understood"
    criteria = {
      url_patterns = { matches = ["*://example.com/*"] }
    }
  }]
}`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(addr, "rules.0.acknowledge_button_text", "Understood"),
					resource.TestCheckNoResourceAttr(addr, "rules.0.copy_redacted_button_text"),
					checkStoredRules(spec, map[string]any{
						"name": "Block pasting into example.com", "enabled": true, "mode": "BLOCK",
						"operation": "PASTE", "contentCapture": false,
						"title": "Paste blocked", "subtext": "Pasting into this site is not permitted.",
						"acknowledgeButtonText": "Understood",
						"criteria": map[string]any{
							"urlPatterns":  map[string]any{"matches": []any{"*://example.com/*"}},
							"profileScope": map[string]any{"matches": []any{"ALL"}},
						},
					}),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
		},
	})
}

// TestControlResource_keyFollowsAReturnedIdentifier checks a rule keeps its key
// when a write is answered with an identifier other than the one the rule was
// sent with. The stub never does that, so this test replaces the first rule's
// identifier, in the tenant and in the response, on one write.
func TestControlResource_keyFollowsAReturnedIdentifier(t *testing.T) {
	stub := newTenantStub()
	stub.apiKey = "offline-test-key"
	spec := controlspec.FileDownloadBlocking
	const replacement = "replaced-rule-id"

	var replaceNext atomic.Bool
	tenant := stub.handler()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != spec.Path() || !replaceNext.CompareAndSwap(true, false) {
			tenant.ServeHTTP(w, r)
			return
		}
		rec := httptest.NewRecorder()
		tenant.ServeHTTP(rec, r)
		if rec.Code != http.StatusOK {
			w.WriteHeader(rec.Code)
			_, _ = w.Write(rec.Body.Bytes())
			return
		}
		stub.mu.Lock()
		doc := stub.document(spec)
		doc.Rules[0]["id"] = replacement
		stub.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		writeJSON(w, http.StatusOK, doc)
	}))
	t.Cleanup(srv.Close)
	t.Setenv(envBaseURL, srv.URL)
	t.Setenv(envAPIKey, stub.apiKey)

	var monitorID string
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccTwoRules,
				Check:  captureRuleID(testResource, 1, &monitorID),
			},
			{
				// An edit, so that there is a write to answer.
				PreConfig: func() { replaceNext.Store(true) },
				Config:    testAccTwoRulesEdited,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(testResource, "rules.0.id", replacement),
					resource.TestCheckResourceAttr(testResource, "rules.0.key", "block"),
					resource.TestCheckResourceAttr(testResource, "rules.1.key", "monitor"),
					checkRuleID(testResource, 1, &monitorID),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
		},
	})
}
