package provider

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/pushapi"
)

// The tests in this file drive pushsecurity_custom_detection and the
// pushsecurity_custom_detections data source through real terraform runs against
// tenantStub, so they run on every pull request. The lifecycle mirrors
// TestAccCustomDetection_lifecycle step for step, and the tests that follow,
// a detection deleted or created behind Terraform's back and logic the API
// refuses, each have a TestAcc twin that provokes the same through the API.

// TestCustomDetection_lifecycle is TestAccCustomDetection_lifecycle without
// the tenant: create, edit the logic and add a rule, import, rename.
func TestCustomDetection_lifecycle(t *testing.T) {
	offlineTenant(t)
	var warnID string

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		// A real delete, unlike a control's: nothing is left behind.
		CheckDestroy: checkStoredDetections(),
		Steps: []resource.TestStep{
			{
				Config: testAccDetectionOneRule,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(testDetection, "detection_event_type",
						"CUSTOM_TF_ACCEPTANCE_DETECTION"),
					resource.TestCheckResourceAttr(testDetection, "detection_logic", testDetectionLogic),
					resource.TestCheckResourceAttr(testDetection, "rules.#", "1"),
					resource.TestCheckResourceAttr(testDetection, "rules.0.severity", "MEDIUM"),
					resource.TestCheckResourceAttr(testDetection, "rules.0.detect_on_internal_hosts", "false"),
					captureAttr(testDetection, "rules.0.id", &warnID),
					checkStoredDetection("CUSTOM_TF_ACCEPTANCE_DETECTION", "Tf acceptance detection",
						testDetectionLogic, storedDetectionWarnRule),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
			{
				// The stub refuses a rule identifier the detection does not
				// hold and assigns a fresh one to a rule sent without, so the
				// warn rule keeps its identifier only if the provider sends it.
				Config: testAccDetectionTwoRules,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(testDetection, "rules.#", "2"),
					resource.TestCheckResourceAttr(testDetection, "rules.0.key", "block"),
					resource.TestCheckResourceAttr(testDetection, "rules.1.key", "warn"),
					checkAttr(testDetection, "rules.1.id", &warnID),
					resource.TestCheckResourceAttr(testDetection, "rules.0.detect_on_internal_hosts", "true"),
					resource.TestCheckResourceAttr(testDetection, "detection_logic", testDetectionLogicEdited),
					checkStoredDetection("CUSTOM_TF_ACCEPTANCE_DETECTION", "Tf acceptance detection",
						testDetectionLogicEdited, storedDetectionBlockRule, storedDetectionWarnRule),
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
				ImportStateVerifyIgnore:              []string{"rules.0.key", "rules.1.key"},
			},
			{
				Config: testAccDetectionRenamed,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(testDetection, "detection_event_type",
						"CUSTOM_TF_ACCEPTANCE_RENAMED"),
					// Replaced, not renamed: the old detection is gone.
					checkStoredDetections("CUSTOM_TF_ACCEPTANCE_RENAMED"),
					checkStoredDetection("CUSTOM_TF_ACCEPTANCE_RENAMED", "Tf acceptance renamed",
						testDetectionLogic, storedDetectionWarnRule),
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

// TestCustomDetection_deletedOutsideTerraform: a detection deleted in the
// console drops out of state on refresh, and the next apply creates it again
// rather than failing to update it.
func TestCustomDetection_deletedOutsideTerraform(t *testing.T) {
	stub := offlineTenant(t)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccDetectionOneRule,
			},
			{
				PreConfig: func() { stub.removeDetection("CUSTOM_TF_ACCEPTANCE_DETECTION") },
				Config:    testAccDetectionOneRule,
				Check: checkStoredDetection("CUSTOM_TF_ACCEPTANCE_DETECTION", "Tf acceptance detection",
					testDetectionLogic, storedDetectionWarnRule),
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

// TestCustomDetection_generatedConfigNamingOnlyDepartedEmployees is the
// control tests of the same name for a detection's rules, which are read
// through the same code: an exclusion of departed employees only imports as
// no employee criterion, an inclusion fails plan saying what to write.
func TestCustomDetection_generatedConfigNamingOnlyDepartedEmployees(t *testing.T) {
	for _, tc := range []struct {
		action string
		error  *regexp.Regexp
	}{
		{"EXCLUDE", nil},
		{"INCLUDE", regexp.MustCompile(`Employee criterion names nobody`)},
	} {
		t.Run(tc.action, func(t *testing.T) {
			stub := offlineTenant(t)
			eventType := stub.seedDetection("Tf acceptance detection", testDetectionLogic,
				seedDepartedRule(tc.action, map[string]any{"severity": "LOW"}))
			log := &diagnosticLog{}

			step := generatedImport(testDetection, eventType)
			step.ExpectError = tc.error
			resource.UnitTest(t, resource.TestCase{
				ProtoV6ProviderFactories: log.factories(),
				Steps:                    []resource.TestStep{step},
			})
			if !log.warned(departedEmployeeWarning) {
				t.Errorf("no warning %q was raised", departedEmployeeWarning)
			}
		})
	}
}

// TestCustomDetection_nameInUse: creating a detection whose name derives an
// identifier the tenant already holds fails with the import to run instead,
// and running it adopts the detection without disturbing its rule's identity.
func TestCustomDetection_nameInUse(t *testing.T) {
	stub := offlineTenant(t)
	var warnID string

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// The seed is testAccDetectionOneRule's rule without its key,
				// which the API never sees.
				PreConfig: func() {
					stub.seedDetection("Tf acceptance detection", testDetectionLogic, map[string]any{
						"name": "Warn everyone", "enabled": true, "mode": "WARN", "severity": "MEDIUM",
						"title": "Careful", "subtext": "This looks like a magnet link.",
						"buttonText": "Continue anyway",
					})
				},
				Config: testAccDetectionOneRule,
				ExpectError: regexp.MustCompile(`(?s)A custom detection with this name already exists` +
					`.*id\s+=\s+"CUSTOM_TF_ACCEPTANCE_DETECTION"`),
			},
			{
				Config:             testAccDetectionOneRule,
				ResourceName:       testDetection,
				ImportState:        true,
				ImportStateId:      "CUSTOM_TF_ACCEPTANCE_DETECTION",
				ImportStatePersist: true,
				ImportStateCheck: func(states []*terraform.InstanceState) error {
					if len(states) != 1 {
						return fmt.Errorf("imported %d instances, want 1", len(states))
					}
					if warnID = states[0].Attributes["rules.0.id"]; warnID == "" {
						return errors.New("the imported rule has no id")
					}
					return nil
				},
			},
			{
				// The key is added; nothing else changes, on the tenant or in
				// the rule's identity.
				Config: testAccDetectionOneRule,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(testDetection, "rules.0.key", "warn"),
					checkAttr(testDetection, "rules.0.id", &warnID),
					checkStoredDetection("CUSTOM_TF_ACCEPTANCE_DETECTION", "Tf acceptance detection",
						testDetectionLogic, storedDetectionWarnRule),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
		},
	})
}

// TestCustomDetection_logicRefused: logic the API refuses fails the apply with
// the API's reason, attached to detection_logic rather than to the resource as
// a whole. The plan checks the logic's size and document count, so this uses
// logic only the API refuses: YAML that does not parse.
func TestCustomDetection_logicRefused(t *testing.T) {
	offlineTenant(t)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             checkStoredDetections(),
		Steps: []resource.TestStep{{
			Config: `
resource "pushsecurity_custom_detection" "test" {
  name            = "Tf acceptance detection"
  detection_logic = "\tinput: web_request\n"
  rules           = [{ name = "Monitor", enabled = true, mode = "MONITOR", severity = "LOW" }]
}`,
			ExpectError: regexp.MustCompile(`(?s)Push API rejected the custom detection` +
				`.*detection_logic = .*not\s+valid\s+YAML`),
		}},
	})
}

// TestCustomDetection_createTimedOutLands: a create answered with 504 that
// lands a little later is adopted in the same apply, with each rule keyed by
// its position as after a create that answered in time.
func TestCustomDetection_createTimedOutLands(t *testing.T) {
	stub := offlineTenant(t)
	shortenTimedOutCreateWait(t, time.Minute)
	stub.timeOutCreates(true, 2)
	log := &diagnosticLog{}

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: log.factories(),
		CheckDestroy:             checkStoredDetections(),
		Steps: []resource.TestStep{{
			Config: testAccDetectionTwoRules,
			Check: resource.ComposeAggregateTestCheckFunc(
				checkWarned(log, "Custom detection created after the request timed out"),
				resource.TestCheckResourceAttr(testDetection, "detection_event_type",
					"CUSTOM_TF_ACCEPTANCE_DETECTION"),
				resource.TestCheckResourceAttr(testDetection, "rules.0.key", "block"),
				resource.TestCheckResourceAttr(testDetection, "rules.1.key", "warn"),
				resource.TestCheckResourceAttrSet(testDetection, "rules.0.id"),
				resource.TestCheckResourceAttrSet(testDetection, "rules.1.id"),
				checkStoredDetection("CUSTOM_TF_ACCEPTANCE_DETECTION", "Tf acceptance detection",
					testDetectionLogicEdited, storedDetectionBlockRule, storedDetectionWarnRule),
			),
			ConfigPlanChecks: resource.ConfigPlanChecks{
				PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
			},
		}},
	})
}

// TestCustomDetection_createTimedOutNeverLands: a create that times out and
// has not landed by the time the provider stops looking fails the apply with
// the import that adopts it if it lands later. Once creates answer in time
// again, the next apply creates it.
func TestCustomDetection_createTimedOutNeverLands(t *testing.T) {
	stub := offlineTenant(t)
	shortenTimedOutCreateWait(t, 200*time.Millisecond)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             checkStoredDetections(),
		Steps: []resource.TestStep{
			{
				PreConfig: func() { stub.timeOutCreates(false, 0) },
				Config:    testAccDetectionOneRule,
				ExpectError: regexp.MustCompile(`(?s)Custom detection create timed out` +
					`.*HTTP 504.*can\s+still\s+finish\s+the\s+create` +
					`.*id\s+=\s+"CUSTOM_TF_ACCEPTANCE_DETECTION"`),
			},
			{
				PreConfig: func() { stub.answerCreatesInTime() },
				Config:    testAccDetectionOneRule,
				Check: checkStoredDetection("CUSTOM_TF_ACCEPTANCE_DETECTION", "Tf acceptance detection",
					testDetectionLogic, storedDetectionWarnRule),
			},
		},
	})
}

// TestCustomDetection_createTimedOutOtherDetection: when the detection that
// turns up after a create timed out is not the one sent, here because one
// with the same name was already there, it is not adopted, and the apply
// fails with the import to run if it should be managed.
func TestCustomDetection_createTimedOutOtherDetection(t *testing.T) {
	stub := offlineTenant(t)
	shortenTimedOutCreateWait(t, time.Minute)
	stub.seedDetection("Tf acceptance detection", testDetectionLogicEdited, map[string]any{
		"name": "Monitor", "enabled": true, "mode": "MONITOR", "severity": "LOW",
	})
	stub.timeOutCreates(true, 0)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: testAccDetectionOneRule,
			ExpectError: regexp.MustCompile(`(?s)A custom detection with this name already exists` +
				`.*does\s+not\s+hold\s+the\s+planned\s+logic` +
				`.*id\s+=\s+"CUSTOM_TF_ACCEPTANCE_DETECTION"`),
		}},
	})
	// The detection that was there is left as it was.
	if err := checkStoredDetection("CUSTOM_TF_ACCEPTANCE_DETECTION", "Tf acceptance detection",
		testDetectionLogicEdited, map[string]any{
			"name": "Monitor", "enabled": true, "mode": "MONITOR", "severity": "LOW",
			"detectOnInternalHosts": false, "criteria": map[string]any{},
		})(nil); err != nil {
		t.Error(err)
	}
}

// shortenTimedOutCreateWait makes the provider look for a create that timed
// out for at most wait, every few milliseconds, for the rest of the test.
func shortenTimedOutCreateWait(t *testing.T, wait time.Duration) {
	t.Helper()
	prevWait, prevPoll := timedOutCreateWait, timedOutCreatePoll
	timedOutCreateWait, timedOutCreatePoll = wait, 10*time.Millisecond
	t.Cleanup(func() { timedOutCreateWait, timedOutCreatePoll = prevWait, prevPoll })
}

// TestCustomDetectionsDataSource is TestAccCustomDetectionsDataSource without
// the tenant, which also holds a detection Terraform did not create.
func TestCustomDetectionsDataSource(t *testing.T) {
	stub := offlineTenant(t)
	stub.seedDetection("Torrent website visit", "input: web_request\n", map[string]any{
		"name": "Monitor", "enabled": true, "mode": "MONITOR", "severity": "LOW",
	})
	const all = "data.pushsecurity_custom_detections.all"

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: testAccDetectionOneRule + `
data "pushsecurity_custom_detections" "all" {
  depends_on = [pushsecurity_custom_detection.test]
}`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckTypeSetElemAttr(all, "detection_event_types.*",
					"CUSTOM_TF_ACCEPTANCE_DETECTION"),
				resource.TestCheckTypeSetElemAttr(all, "detection_event_types.*",
					"CUSTOM_TORRENT_WEBSITE_VISIT"),
				resource.TestCheckResourceAttr(all, "detections.#", "2"),
				resource.TestCheckTypeSetElemNestedAttrs(all, "detections.*", map[string]string{
					"name": "Torrent website visit", "detection_event_type": "CUSTOM_TORRENT_WEBSITE_VISIT",
				}),
				resource.TestCheckTypeSetElemNestedAttrs(all, "detections.*", map[string]string{
					"name": "Tf acceptance detection", "detection_event_type": "CUSTOM_TF_ACCEPTANCE_DETECTION",
				}),
				sameLength(all, "detections.#", "detection_event_types.#"),
			),
		}},
	})
}

// storedDetectionWarnRule and storedDetectionBlockRule are the rules of
// testAccDetectionOneRule and testAccDetectionTwoRules as the API should hold
// them: detectOnInternalHosts always present, criteria always present, and
// INCLUDE on a condition configured without an action.
var storedDetectionWarnRule = map[string]any{
	"name": "Warn everyone", "enabled": true, "mode": "WARN", "severity": "MEDIUM",
	"title": "Careful", "subtext": "This looks like a magnet link.", "buttonText": "Continue anyway",
	"detectOnInternalHosts": false,
	"criteria":              map[string]any{},
}

var storedDetectionBlockRule = map[string]any{
	"name": "Block contractors", "enabled": true, "mode": "BLOCK", "severity": "HIGH",
	"title": "Blocked", "subtext": "Not permitted.",
	"detectOnInternalHosts": true,
	"criteria": map[string]any{
		"employeeGroups": map[string]any{"matches": []any{"Contractors"}, "action": "INCLUDE"},
	},
}

// checkStoredDetection asserts what the tenant holds for one custom detection:
// its name, its logic byte for byte, and exactly these rules in this order,
// each written as the JSON the API should serve without its id. Like
// checkStoredRules it reads the tenant over the API, so it holds against a
// real tenant as well as the stub.
func checkStoredDetection(eventType, name, logic string, rules ...map[string]any) resource.TestCheckFunc {
	return func(*terraform.State) error {
		var d struct {
			Name  string           `json:"detectionEventName"`
			Logic string           `json:"detectionLogic"`
			Rules []map[string]any `json:"rules"`
		}
		if err := tenantRequest(http.MethodGet, customDetectionsPath+"/"+eventType, nil, &d); err != nil {
			return err
		}
		var diffs []string
		if d.Name != name {
			diffs = append(diffs, fmt.Sprintf("the name is %q, want %q", d.Name, name))
		}
		if d.Logic != logic {
			diffs = append(diffs, fmt.Sprintf("the logic is %q, want %q", d.Logic, logic))
		}
		if len(d.Rules) != len(rules) {
			diffs = append(diffs, fmt.Sprintf("it holds %d rules, want %d", len(d.Rules), len(rules)))
		} else {
			diffs = append(diffs, ruleDiffs(d.Rules, rules)...)
		}
		if len(diffs) > 0 {
			return fmt.Errorf("%s as stored differs from what was intended:\n  %s",
				eventType, strings.Join(diffs, "\n  "))
		}
		return nil
	}
}

// checkStoredDetections asserts the tenant's custom detections are exactly
// these, by identifier and in any order. With none it asserts there are none,
// which is what destroy leaves when every detection was Terraform's.
func checkStoredDetections(want ...string) resource.TestCheckFunc {
	want = slices.Sorted(slices.Values(want))
	return func(*terraform.State) error {
		var index struct {
			Result []struct {
				EventType string `json:"detectionEventType"`
			} `json:"result"`
		}
		if err := tenantRequest(http.MethodGet, customDetectionsPath, nil, &index); err != nil {
			return err
		}
		got := make([]string, 0, len(index.Result))
		for _, d := range index.Result {
			got = append(got, d.EventType)
		}
		slices.Sort(got)
		if !slices.Equal(got, want) {
			return fmt.Errorf("the tenant holds the custom detections %q, want %q", got, want)
		}
		return nil
	}
}

// TestCustomDetection_createTimedOutDifferentCriteria: a detection that turns
// up after a create timed out, holding the planned logic and rules of the same
// names but applying them to different people, is not adopted. Comparing only
// what the rules are called would adopt it, and the next plan would then show
// nothing to change although the tenant blocks people the configuration does
// not name.
func TestCustomDetection_createTimedOutDifferentCriteria(t *testing.T) {
	stub := offlineTenant(t)
	shortenTimedOutCreateWait(t, time.Minute)
	stub.seedDetection("Tf acceptance detection", testDetectionLogicEdited,
		map[string]any{
			"name": "Block contractors", "enabled": true, "mode": "BLOCK", "severity": "HIGH",
			"title": "Blocked", "subtext": "Not permitted.", "detectOnInternalHosts": true,
			"criteria": map[string]any{"employeeGroups": map[string]any{"matches": []any{"Everyone"}}},
		},
		map[string]any{
			"name": "Warn everyone", "enabled": true, "mode": "WARN", "severity": "MEDIUM",
			"title": "Careful", "subtext": "This looks like a magnet link.",
			"buttonText": "Continue anyway",
		})
	stub.timeOutCreates(true, 0)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: testAccDetectionTwoRules,
			ExpectError: regexp.MustCompile(`(?s)A custom detection with this name already exists` +
				`.*does\s+not\s+hold\s+the\s+planned\s+logic`),
		}},
	})
}

// TestCreatedAsPlanned covers what decides whether a detection that appeared
// after a create timed out is the one the create sent. What a rule applies to
// and what it does count as much as its name; the values a condition matches
// are a set, and what the API fills in that the plan left out is not
// compared.
func TestCreatedAsPlanned(t *testing.T) {
	const name, logic = "Tf probe detection", "input: web_request\n"
	planned := func() []planRule {
		return []planRule{{Rule: pushapi.Rule{
			Name: "Block contractors", Enabled: true, Mode: "BLOCK",
			Fields: map[string]any{"severity": "HIGH", "title": "Blocked", "subtext": "No."},
			Criteria: map[string]pushapi.Condition{
				"employeeGroups": {Matches: []string{"Contractors", "Interns"}},
				"employeeIds":    {Matches: []string{"emp-1"}, Action: "EXCLUDE"},
			},
		}}}
	}
	stored := func(edit func(*pushapi.Rule)) *pushapi.CustomDetection {
		rule := pushapi.Rule{
			ID: "rule-1", Name: "Block contractors", Enabled: true, Mode: "BLOCK",
			Fields: map[string]any{
				"severity": "HIGH", "title": "Blocked", "subtext": "No.",
				"detectOnInternalHosts": false,
			},
			Criteria: map[string]pushapi.Condition{
				"employeeGroups": {Matches: []string{"Interns", "Contractors"}, Action: "INCLUDE"},
				"employeeIds":    {Matches: []string{"emp-1"}, Action: "EXCLUDE"},
			},
		}
		if edit != nil {
			edit(&rule)
		}
		return &pushapi.CustomDetection{
			DetectionEventType: "CUSTOM_TF_PROBE_DETECTION", DetectionEventName: name,
			DetectionLogic: logic, Rules: []pushapi.Rule{rule},
		}
	}

	for _, tc := range []struct {
		name string
		edit func(*pushapi.Rule)
		want bool
	}{
		{"as planned, with what the API fills in", nil, true},
		{"other groups", func(r *pushapi.Rule) {
			r.Criteria["employeeGroups"] = pushapi.Condition{Matches: []string{"Everyone"}, Action: "INCLUDE"}
		}, false},
		{"a condition dropped", func(r *pushapi.Rule) { delete(r.Criteria, "employeeIds") }, false},
		{"a condition added", func(r *pushapi.Rule) {
			r.Criteria["employeeIds"] = pushapi.Condition{Matches: []string{"emp-1"}, Action: "EXCLUDE"}
			r.Criteria["other"] = pushapi.Condition{Matches: []string{"x"}}
		}, false},
		{"the opposite action", func(r *pushapi.Rule) {
			r.Criteria["employeeIds"] = pushapi.Condition{Matches: []string{"emp-1"}, Action: "INCLUDE"}
		}, false},
		{"another severity", func(r *pushapi.Rule) { r.Fields["severity"] = "LOW" }, false},
		{"a field missing", func(r *pushapi.Rule) { delete(r.Fields, "title") }, false},
		{"another mode", func(r *pushapi.Rule) { r.Mode = "WARN" }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := createdAsPlanned(stored(tc.edit), name, logic, planned()); got != tc.want {
				t.Errorf("createdAsPlanned = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestCustomDetection_conflictIsNamedByOperation: a conflict on create means
// the name is taken, and the answer is to import the detection that holds it.
// On an update or a delete the detection is already this resource's, so the
// conflict can only be another write that would not clear, and saying the
// name is taken would send the practitioner to import what they manage.
func TestCustomDetection_conflictIsNamedByOperation(t *testing.T) {
	conflict := &pushapi.APIError{
		Method: http.MethodPut, Path: customDetectionsPath + "/CUSTOM_TF_PROBE_DETECTION",
		StatusCode: http.StatusConflict, Status: "CONCURRENT_MODIFICATION",
		Message: "Another write is in progress.",
	}
	r := &customDetectionResource{}

	for _, tc := range []struct {
		op, subject, summary string
		importBlock          bool
	}{
		{"create", "Tf probe detection", "A custom detection with this name already exists", true},
		{"update", "CUSTOM_TF_PROBE_DETECTION", "Push API refused the write as a conflict", false},
		{"delete", "CUSTOM_TF_PROBE_DETECTION", "Push API refused the write as a conflict", false},
	} {
		t.Run(tc.op, func(t *testing.T) {
			var diags diag.Diagnostics
			r.addAPIError(&diags, tc.op, tc.subject, conflict)
			if len(diags) != 1 {
				t.Fatalf("got %d diagnostics, want 1: %v", len(diags), diags)
			}
			if got := diags[0].Summary(); got != tc.summary {
				t.Errorf("summary = %q, want %q", got, tc.summary)
			}
			detail := diags[0].Detail()
			if !strings.Contains(detail, "Could not "+tc.op) {
				t.Errorf("detail does not say what failed: %q", detail)
			}
			if got := strings.Contains(detail, "import {"); got != tc.importBlock {
				t.Errorf("detail offers an import: %v, want %v\n%s", got, tc.importBlock, detail)
			}
		})
	}
}
