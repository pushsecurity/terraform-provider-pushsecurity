package provider

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/pushapi"
)

const testDetection = "pushsecurity_custom_detection.test"

// testDetectionLogic is a minimal but real detection document. It is stored and
// returned byte for byte, which the test asserts.
const testDetectionLogic = `input: web_request
metadata:
  indicator: TF_ACCEPTANCE_INDICATOR
conditions:
  request_url:
    scheme: magnet
`

// testDetectionLogicEdited differs from testDetectionLogic only in the
// indicator, so an edit to the logic can be applied and asserted.
const testDetectionLogicEdited = `input: web_request
metadata:
  indicator: TF_ACCEPTANCE_INDICATOR_V2
conditions:
  request_url:
    scheme: magnet
`

func TestAccCustomDetection_lifecycle(t *testing.T) {
	var warnID string

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccDetectionOneRule,
				Check: resource.ComposeAggregateTestCheckFunc(
					// The identifier is derived from the name: upper-cased,
					// spaces to underscores, CUSTOM_ prefix.
					resource.TestCheckResourceAttr(testDetection, "detection_event_type",
						"CUSTOM_TF_ACCEPTANCE_DETECTION"),
					// Byte-for-byte round trip is what makes file() usable for
					// detection logic.
					resource.TestCheckResourceAttr(testDetection, "detection_logic", testDetectionLogic),
					resource.TestCheckResourceAttr(testDetection, "rules.#", "1"),
					resource.TestCheckResourceAttr(testDetection, "rules.0.severity", "MEDIUM"),
					// Injected by the server when absent.
					resource.TestCheckResourceAttr(testDetection, "rules.0.detect_on_internal_hosts", "false"),
					captureAttr(testDetection, "rules.0.id", &warnID),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
			{
				// Editing the logic and adding a rule must not disturb the
				// existing rule's identity.
				Config: testAccDetectionTwoRules,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(testDetection, "rules.#", "2"),
					resource.TestCheckResourceAttr(testDetection, "rules.0.key", "block"),
					resource.TestCheckResourceAttr(testDetection, "rules.1.key", "warn"),
					checkAttr(testDetection, "rules.1.id", &warnID),
					resource.TestCheckResourceAttr(testDetection, "rules.0.detect_on_internal_hosts", "true"),
					// Detection logic is stored verbatim, so an edit round
					// trips exactly.
					resource.TestCheckResourceAttr(testDetection, "detection_logic", testDetectionLogicEdited),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
			{
				ResourceName:                         testDetection,
				ImportState:                          true,
				ImportStateId:                        "CUSTOM_TF_ACCEPTANCE_DETECTION",
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "detection_event_type",
				// Keys are provider-side only; the API cannot return them.
				ImportStateVerifyIgnore: []string{"rules.0.key", "rules.1.key"},
			},
			{
				// The API cannot rename a detection, so the provider replaces
				// it rather than reporting a rename that did not happen.
				Config: testAccDetectionRenamed,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(testDetection, "detection_event_type",
						"CUSTOM_TF_ACCEPTANCE_RENAMED"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(testDetection, plancheck.ResourceActionReplace),
					},
				},
			},
		},
	})
}

// TestAccCustomDetection_deletedOutsideTerraform is the offline test of the
// same name against a real tenant: the detection is deleted through the API
// between applies, as it would be in the console, and must drop out of state
// on refresh and be created again rather than fail to update.
func TestAccCustomDetection_deletedOutsideTerraform(t *testing.T) {
	const name, eventType = "Tf acceptance deleted", "CUSTOM_TF_ACCEPTANCE_DELETED"
	config := detectionConfig(name, testDetectionLogic, testAccOneRuleBlock)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t); cleanUpDetection(t, eventType) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             checkDetectionsGone(eventType),
		Steps: []resource.TestStep{
			{
				Config: config,
			},
			{
				PreConfig: func() {
					if err := detectionClient(t).DeleteCustomDetection(context.Background(), eventType); err != nil {
						t.Fatalf("deleting %s outside Terraform: %v", eventType, err)
					}
				},
				Config: config,
				Check:  checkStoredDetection(eventType, name, testDetectionLogic, storedDetectionWarnRule),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(testDetection, plancheck.ResourceActionCreate),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
		},
	})
}

// TestAccCustomDetection_nameInUse is the offline test of the same name
// against a real tenant. The diagnostic naming the import to run rests on the
// API answering a create whose name derives an identifier already in use with
// a conflict, which only a real tenant can confirm. The import must then adopt
// the detection with the identifier its rule was given when it was seeded.
func TestAccCustomDetection_nameInUse(t *testing.T) {
	const name, eventType = "Tf acceptance name in use", "CUSTOM_TF_ACCEPTANCE_NAME_IN_USE"
	config := detectionConfig(name, testDetectionLogic, testAccOneRuleBlock)
	var warnID string

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t); cleanUpDetection(t, eventType) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             checkDetectionsGone(eventType),
		Steps: []resource.TestStep{
			{
				// The seed is testAccOneRuleBlock's rule without its key,
				// which the API never sees.
				PreConfig: func() {
					warnID = seedDetection(t, name, eventType, testDetectionLogic, pushapi.Rule{
						Name: "Warn everyone", Enabled: true, Mode: "WARN",
						Fields: map[string]any{
							"severity": "MEDIUM", "title": "Careful",
							"subtext": "This looks like a magnet link.", "buttonText": "Continue anyway",
						},
					})
				},
				Config: config,
				ExpectError: regexp.MustCompile(`(?s)A custom detection with this name already exists` +
					`.*id\s+=\s+"` + eventType + `"`),
			},
			{
				Config:             config,
				ResourceName:       testDetection,
				ImportState:        true,
				ImportStateId:      eventType,
				ImportStatePersist: true,
				ImportStateCheck: func(states []*terraform.InstanceState) error {
					if len(states) != 1 {
						return fmt.Errorf("imported %d instances, want 1", len(states))
					}
					if got := states[0].Attributes["rules.0.id"]; got != warnID {
						return fmt.Errorf("the imported rule's id is %q, the seeded rule's %q", got, warnID)
					}
					return nil
				},
			},
			{
				// The key is added; nothing else changes, on the tenant or in
				// the rule's identity.
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(testDetection, "rules.0.key", "warn"),
					checkAttr(testDetection, "rules.0.id", &warnID),
					checkStoredDetection(eventType, name, testDetectionLogic, storedDetectionWarnRule),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
		},
	})
}

// TestAccCustomDetection_logicRefused is the offline test of the same name
// against a real tenant: YAML that does not parse fails the apply with the
// API's reason, attached to detection_logic, and leaves nothing behind.
func TestAccCustomDetection_logicRefused(t *testing.T) {
	const eventType = "CUSTOM_TF_ACCEPTANCE_REFUSED"

	resource.Test(t, resource.TestCase{
		// Cleaned up in case the API takes the logic after all.
		PreCheck:                 func() { testAccPreCheck(t); cleanUpDetection(t, eventType) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             checkDetectionsGone(eventType),
		Steps: []resource.TestStep{{
			Config: `
resource "pushsecurity_custom_detection" "test" {
  name            = "Tf acceptance refused"
  detection_logic = "\tinput: web_request\n"
  rules           = [{ name = "Monitor", enabled = true, mode = "MONITOR", severity = "LOW" }]
}`,
			ExpectError: regexp.MustCompile(`(?s)Push API rejected the custom detection` +
				`.*detection_logic = .*not\s+valid\s+YAML`),
		}},
	})
}

// TestAccCustomDetection_logicAtLimits applies detection logic exactly at both
// limits the plan enforces, and the API must take it and serve it back byte
// for byte. The plan refuses a byte or a document more, so this is what keeps
// it from passing logic the apply would fail.
func TestAccCustomDetection_logicAtLimits(t *testing.T) {
	const name, eventType = "Tf acceptance limits", "CUSTOM_TF_ACCEPTANCE_LIMITS"
	logic := detectionLogicAtLimits(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t); cleanUpDetection(t, eventType) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             checkDetectionsGone(eventType),
		Steps: []resource.TestStep{{
			Config: detectionConfig(name, logic, testAccOneRuleBlock),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr(testDetection, "detection_logic", logic),
				checkStoredDetection(eventType, name, logic, storedDetectionWarnRule),
			),
			ConfigPlanChecks: resource.ConfigPlanChecks{
				PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
			},
		}},
	})
}

// detectionLogicAtLimits returns detection logic of exactly
// detectionLogicByteLimit bytes holding exactly detectionLogicDocumentLimit
// YAML documents: copies of a minimal detection, then a comment padding it
// out. The comment is mostly two-byte characters, so that the logic is fewer
// characters than bytes and only a limit counted in bytes puts it at the edge.
func detectionLogicAtLimits(t *testing.T) string {
	t.Helper()
	const document = `---
input: web_request
metadata:
  indicator: TF_ACC
conditions:
  request_url:
    scheme: magnet
`
	logic := strings.Repeat(document, detectionLogicDocumentLimit)
	pad := detectionLogicByteLimit - len(logic) - len("#\n")
	logic += "#" + strings.Repeat("é", pad/2) + strings.Repeat("x", pad%2) + "\n"

	if size, n := len(logic), yamlDocumentCount(logic); size != detectionLogicByteLimit ||
		n != detectionLogicDocumentLimit {
		t.Fatalf("the logic is %d bytes in %d documents, want %d in %d",
			size, n, detectionLogicByteLimit, detectionLogicDocumentLimit)
	}
	return logic
}

// detectionClient is an API client for acting on the tenant outside Terraform.
func detectionClient(t *testing.T) *pushapi.Client {
	t.Helper()
	client, err := pushapi.New(os.Getenv(envBaseURL), os.Getenv(envAPIKey))
	if err != nil {
		t.Fatalf("pushapi.New: %v", err)
	}
	return client
}

// seedDetection creates a custom detection through the API, as the console
// would, and returns the identifier its one rule was given. It fails the test
// unless the API derived eventType from the name.
func seedDetection(t *testing.T, name, eventType, logic string, rule pushapi.Rule) string {
	t.Helper()
	stored, err := detectionClient(t).CreateCustomDetection(context.Background(), name, logic,
		[]pushapi.Rule{rule})
	if err != nil {
		t.Fatalf("seeding %q: %v", name, err)
	}
	if stored.DetectionEventType != eventType {
		t.Fatalf("seeding %q created %s, want %s", name, stored.DetectionEventType, eventType)
	}
	if len(stored.Rules) != 1 || stored.Rules[0].ID == "" {
		t.Fatalf("seeding %q stored %d rules, want 1 with an id", name, len(stored.Rules))
	}
	return stored.Rules[0].ID
}

// cleanUpDetection deletes a custom detection once the test is over. Destroy
// removes only what is in state, so a detection created outside Terraform, or
// one a failed step left out of state, would otherwise outlive the test and
// make the next run's create conflict.
//
// A create answered with a 504 can still complete afterwards, so once a test
// has failed the delete is repeated for detectionCreateOutlast, catching a
// detection that appears late.
func cleanUpDetection(t *testing.T, eventType string) {
	t.Helper()
	client := detectionClient(t)
	t.Cleanup(func() {
		deadline := time.Now().Add(detectionCreateOutlast)
		for {
			err := client.DeleteCustomDetection(context.Background(), eventType)
			if err != nil && !pushapi.NotFound(err) {
				t.Errorf("deleting %s: %v", eventType, err)
				return
			}
			if !t.Failed() || time.Now().After(deadline) {
				return
			}
			time.Sleep(10 * time.Second)
		}
	})
}

// detectionCreateOutlast is how long a failed test keeps deleting its
// detection. The API answers a request still running after 29 seconds with a
// 504, but how long the create goes on after that cannot be seen from
// outside, so this allows a wide margin.
const detectionCreateOutlast = 2 * time.Minute

// checkDetectionsGone asserts the tenant holds none of these custom
// detections. Unlike checkStoredDetections it ignores the tenant's others,
// which a real tenant may hold.
func checkDetectionsGone(eventTypes ...string) resource.TestCheckFunc {
	return func(*terraform.State) error {
		client, err := pushapi.New(os.Getenv(envBaseURL), os.Getenv(envAPIKey))
		if err != nil {
			return err
		}
		index, err := client.ListCustomDetections(context.Background())
		if err != nil {
			return err
		}
		var left []error
		for _, d := range index {
			if slices.Contains(eventTypes, d.DetectionEventType) {
				left = append(left, fmt.Errorf("%s is still on the tenant", d.DetectionEventType))
			}
		}
		return errors.Join(left...)
	}
}

func TestAccCustomDetection_validation(t *testing.T) {
	for _, tc := range []struct {
		name, config string
		wantErr      *regexp.Regexp
	}{
		{
			name: "severity required outside OFF",
			config: `
resource "pushsecurity_custom_detection" "test" {
  name            = "Tf acceptance validation"
  detection_logic = "input: web_request\n"
  rules           = [{ name = "n", enabled = true, mode = "MONITOR" }]
}`,
			wantErr: regexp.MustCompile("`severity` is required for mode MONITOR"),
		},
		{
			name: "detect_on_internal_hosts cannot be true for OFF",
			config: `
resource "pushsecurity_custom_detection" "test" {
  name            = "Tf acceptance validation"
  detection_logic = "input: web_request\n"
  rules = [{
    name                     = "n"
    enabled                  = false
    mode                     = "OFF"
    detect_on_internal_hosts = true
  }]
}`,
			wantErr: regexp.MustCompile("`detect_on_internal_hosts` cannot be true for mode OFF"),
		},
		{
			name: "at least one rule",
			config: `
resource "pushsecurity_custom_detection" "test" {
  name            = "Tf acceptance validation"
  detection_logic = "input: web_request\n"
  rules           = []
}`,
			wantErr: regexp.MustCompile(`(?s)rules.*at least 1`),
		},
		{
			name: "name character set",
			config: `
resource "pushsecurity_custom_detection" "test" {
  name            = "Not-allowed: punctuation!"
  detection_logic = "input: web_request\n"
  rules           = [{ name = "n", enabled = false, mode = "OFF" }]
}`,
			wantErr: regexp.MustCompile("letters, numbers, spaces and underscores"),
		},
		{
			// 513 lines of 20 bytes, 20 bytes over the API's limit.
			name: "detection logic size",
			config: `
resource "pushsecurity_custom_detection" "test" {
  name            = "Tf acceptance validation"
  detection_logic = join("", [for i in range(513) : "# twenty bytes long\n"])
  rules           = [{ name = "n", enabled = false, mode = "OFF" }]
}`,
			wantErr: regexp.MustCompile(`(?s)Detection logic is too\s+large.*10260\s+bytes`),
		},
		{
			name: "detection logic documents",
			config: `
resource "pushsecurity_custom_detection" "test" {
  name            = "Tf acceptance validation"
  detection_logic = join("", [for i in range(101) : "---\ninput: web_request\n"])
  rules           = [{ name = "n", enabled = false, mode = "OFF" }]
}`,
			wantErr: regexp.MustCompile(`(?s)too\s+many\s+documents.*holds\s+101\s+YAML`),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resource.UnitTest(t, resource.TestCase{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				Steps: []resource.TestStep{{
					Config:      tc.config,
					PlanOnly:    true,
					ExpectError: tc.wantErr,
				}},
			})
		})
	}
}

// detectionConfig renders a configuration with the logic quoted from the Go
// constant rather than written as a heredoc, so that the bytes sent are exactly
// the bytes the round-trip assertion compares against.
func detectionConfig(name, logic, rules string) string {
	return fmt.Sprintf(`
resource "pushsecurity_custom_detection" "test" {
  name            = %q
  detection_logic = %q
  rules           = %s
}
`, name, logic, rules)
}

const testAccOneRuleBlock = `[{
    key         = "warn"
    name        = "Warn everyone"
    enabled     = true
    mode        = "WARN"
    severity    = "MEDIUM"
    title       = "Careful"
    subtext     = "This looks like a magnet link."
    button_text = "Continue anyway"
  }]`

var testAccDetectionOneRule = detectionConfig(
	"Tf acceptance detection", testDetectionLogic, testAccOneRuleBlock)

var testAccDetectionTwoRules = detectionConfig(
	"Tf acceptance detection", testDetectionLogicEdited, `[
    {
      key                      = "block"
      name                     = "Block contractors"
      enabled                  = true
      mode                     = "BLOCK"
      severity                 = "HIGH"
      title                    = "Blocked"
      subtext                  = "Not permitted."
      detect_on_internal_hosts = true
      criteria = {
        employee_groups = { matches = ["Contractors"] }
      }
    },
    {
      key         = "warn"
      name        = "Warn everyone"
      enabled     = true
      mode        = "WARN"
      severity    = "MEDIUM"
      title       = "Careful"
      subtext     = "This looks like a magnet link."
      button_text = "Continue anyway"
    },
  ]`)

var testAccDetectionRenamed = detectionConfig(
	"Tf acceptance renamed", testDetectionLogic, testAccOneRuleBlock)

// TestDerivedEventType pins the derivation the API performs, which diagnostics
// rely on to tell a practitioner which identifier to import when a create
// conflicts. Confirmed live: "Tf probe detection" -> CUSTOM_TF_PROBE_DETECTION.
func TestDerivedEventType(t *testing.T) {
	for _, tc := range []struct{ name, want string }{
		{"Tf probe detection", "CUSTOM_TF_PROBE_DETECTION"},
		{"Torrent website visit", "CUSTOM_TORRENT_WEBSITE_VISIT"},
		{"already_underscored", "CUSTOM_ALREADY_UNDERSCORED"},
		{"MiXeD Case", "CUSTOM_MIXED_CASE"},
		{"  padded  ", "CUSTOM_PADDED"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := derivedEventType(tc.name); got != tc.want {
				t.Errorf("derivedEventType(%q) = %q, want %q", tc.name, got, tc.want)
			}
		})
	}
}
