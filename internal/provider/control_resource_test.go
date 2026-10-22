package provider

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/provider/controlspec"
	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/pushapi"
)

// These acceptance tests run against a real tenant and replace the whole
// fileDownloadBlocking configuration, so they must only be pointed at a
// dedicated test tenant. See testAccPreCheck.

const testResource = "pushsecurity_file_download_blocking.test"

// TestAccControlResource_lifecycle covers the operations the engine has to get
// right for every control: create, update, reorder, add, remove and destroy.
//
// State is checked, and after every step the tenant's own copy of
// the configuration is read back as plain JSON and compared with what the step
// intended, since state comes from the provider's read path and cannot show a
// mistake that path shares with the write.
func TestAccControlResource_lifecycle(t *testing.T) {
	spec := controlspec.FileDownloadBlocking
	// Captured across steps so that identifier stability can be asserted
	// between them, which is the property the key mechanism exists to provide.
	var blockID, monitorID string

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
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
					// The server echoes the action it defaulted, and the schema
					// default has to agree with it or every plan would diff.
					resource.TestCheckResourceAttr(testResource, "rules.0.criteria.file_extensions.action", "INCLUDE"),
					resource.TestCheckResourceAttr(testResource, "rules.0.criteria.employee_groups.action", "EXCLUDE"),
					// profileScope is injected by the server into every rule,
					// including one sent with no criteria at all.
					resource.TestCheckResourceAttr(testResource, "rules.0.criteria.profile_scope", "ALL"),
					resource.TestCheckResourceAttr(testResource, "rules.1.criteria.profile_scope", "ALL"),
					// Absent text fields must be null, not "": the API
					// returns an empty string it was sent, so the two differ.
					resource.TestCheckNoResourceAttr(testResource, "rules.1.title"),
					captureRuleID(testResource, 0, &blockID),
					captureRuleID(testResource, 1, &monitorID),
					checkStoredRules(spec, storedBlockRule("Download blocked"), storedMonitorRule),
				),
			},
			{
				// Editing text must not disturb identity.
				Config: testAccTwoRulesEdited,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(testResource, "rules.0.title", "Blocked by policy"),
					checkRuleID(testResource, 0, &blockID),
					checkRuleID(testResource, 1, &monitorID),
					checkStoredRules(spec, storedBlockRule("Blocked by policy"), storedMonitorRule),
				),
			},
			{
				// The decisive case. Reordering keyed rules must move
				// identifiers with the rules, not with the positions: the API
				// accepts either, so getting it wrong raises no error.
				Config: testAccTwoRulesReordered,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(testResource, "rules.0.key", "monitor"),
					resource.TestCheckResourceAttr(testResource, "rules.1.key", "block"),
					checkRuleID(testResource, 0, &monitorID),
					checkRuleID(testResource, 1, &blockID),
					checkStoredRules(spec, storedMonitorRule, storedBlockRule("Blocked by policy")),
				),
			},
			{
				// Inserting must create exactly one rule and leave the other
				// two identifiers alone.
				Config: testAccThreeRules,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(testResource, "rules.#", "3"),
					resource.TestCheckResourceAttr(testResource, "rules.0.key", "inserted"),
					checkRuleID(testResource, 1, &monitorID),
					checkRuleID(testResource, 2, &blockID),
					checkStoredRules(spec, storedInsertedRule, storedMonitorRule, storedBlockRule("Blocked by policy")),
				),
			},
			{
				// Removing rules deletes them server-side, because the PUT
				// replaces the whole document.
				Config: testAccOneRule,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(testResource, "rules.#", "1"),
					checkRuleID(testResource, 0, &blockID),
					checkStoredRules(spec, storedBlockRule("Blocked by policy")),
				),
			},
			{
				// Import is the adoption path, and a zero-diff plan afterwards
				// is the definition of done for the Read implementation.
				ResourceName:  testResource,
				ImportState:   true,
				ImportStateId: "default",
				// Keys are provider-side only and cannot come back from the
				// API, so imported state has none. Everything else must match.
				ImportStateVerify:                    true,
				ImportStateVerifyIgnore:              []string{"rules.0.key"},
				ImportStateVerifyIdentifierAttribute: "rules.#",
			},
		},
	})
}

// TestAccControlResource_accountConditionEnforcement is the offline test of
// the same name against a real tenant. Rules are seeded as a client writes
// them, imported, keyed, and one is switched to BLOCK with a company domain
// scope, and the tenant's copy is compared with what was intended at every
// step. That comparison is the check on the provider's assumptions about this
// control: where the API leaves an action or the profile scope out, and what
// it holds once a mode or scope makes a field or criterion inapplicable.
func TestAccControlResource_accountConditionEnforcement(t *testing.T) {
	spec := controlspec.AccountConditionEnforcement
	const addr = "pushsecurity_account_condition_enforcement.test"
	var warnID, monitorID string

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             checkStoredRules(spec),
		Steps: []resource.TestStep{
			{
				PreConfig: func() {
					ids := seedStoredRules(t, spec, aceSeedRules()...)
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
				Config: testACEWarn,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(addr, "rules.#", "2"),
					checkRuleID(addr, 0, &warnID),
					checkRuleID(addr, 1, &monitorID),
					checkStoredRules(spec, storedACEWarnRule, storedACEMonitorRule),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
			{
				Config: testACEBlock,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(addr, "rules.0.mode", "BLOCK"),
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

// TestAccControlResource_emptyRules checks the destroy semantics explicitly:
// there is no delete verb, so an empty rules list is a legitimate state and is
// what destroy writes.
func TestAccControlResource_emptyRules(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `resource "pushsecurity_file_download_blocking" "test" { rules = [] }`,
				Check:  resource.TestCheckResourceAttr(testResource, "rules.#", "0"),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
		},
	})
}

// TestAccControlResource_unkeyedWarning pins the documented degradation: rules
// without a key still work, and the practitioner is told why that is risky.
func TestAccControlResource_unkeyedWarning(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "pushsecurity_file_download_blocking" "test" {
  rules = [
    { name = "one", enabled = true, mode = "MONITOR" },
    { name = "two", enabled = true, mode = "OFF" },
  ]
}`,
				Check: resource.TestCheckResourceAttr(testResource, "rules.#", "2"),
			},
		},
	})
}

// TestAccControlResource_adoption walks the adoption guide end to end: rules
// that already exist are imported, and the keys are added afterwards.
//
// The step that matters is the last one. Imported state has identifiers and no
// keys — the API does not store keys, so a Read cannot produce them — so a
// keyed configuration matches nothing by key. Without the positional fallback,
// every rule would then be sent without an identifier and the API would
// replace the whole document with fresh rules. Nothing would fail: the plan
// shows `+ key` either way, the apply succeeds, and the resulting
// configuration is correct. Only the identifiers would change — which nothing
// inside Push reads, so this is about keeping a public API's identifiers
// stable rather than about correctness.
//
// The lifecycle test's import step could not catch this. It verifies imported
// state and stops; the apply that follows an import is what goes wrong.
func TestAccControlResource_adoption(t *testing.T) {
	// Captured before the import and asserted after the keyed apply: the whole
	// point is that these survive.
	var blockID, monitorID string

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// The rules have to exist without Terraform having made them,
				// or the import has nothing to adopt and the framework refuses
				// to import over state it already manages. Seeding through the
				// API is also the more faithful rehearsal: this is what a
				// console-configured tenant looks like.
				PreConfig: func() { seedUnkeyedRules(t, &blockID, &monitorID) },
				Config:    testAccTwoRules,

				ResourceName:       testResource,
				ImportState:        true,
				ImportStateId:      "default",
				ImportStatePersist: true,
				// Guards the seed against drifting from testAccTwoRules: the
				// next step is only meaningful if adding the keys is the one
				// difference between what was imported and what is configured.
				ImportStateCheck: checkImportedUnkeyedRules,
			},
			{
				// The same two rules, in the same order, with keys added —
				// guide step 4. A no-op on the API, and it has to be a no-op
				// on rule identity too. This is the step the fix is for.
				Config: testAccTwoRules,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(testResource, "rules.#", "2"),
					resource.TestCheckResourceAttr(testResource, "rules.0.key", "block"),
					resource.TestCheckResourceAttr(testResource, "rules.1.key", "monitor"),
					checkRuleID(testResource, 0, &blockID),
					checkRuleID(testResource, 1, &monitorID),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			{
				// And the apply after adoption behaves like any other: state
				// now carries keys, so a reorder moves identifiers with the
				// rules rather than falling back to position.
				Config: testAccTwoRulesReordered,
				Check: resource.ComposeAggregateTestCheckFunc(
					checkRuleID(testResource, 0, &monitorID),
					checkRuleID(testResource, 1, &blockID),
				),
			},
		},
	})
}

// TestControlResource_validationIsClientSide checks that a configuration the
// API would reject fails during plan instead. There is no dry-run endpoint, so
// anything not caught here is only caught after a merge.
func TestControlResource_validationIsClientSide(t *testing.T) {
	for _, tc := range []struct {
		name, config string
		wantErr      *regexp.Regexp
	}{
		{
			name: "title required for BLOCK",
			config: `
resource "pushsecurity_file_download_blocking" "test" {
  rules = [{ name = "n", enabled = true, mode = "BLOCK", subtext = "s" }]
}`,
			wantErr: regexp.MustCompile("`title` is required for mode BLOCK"),
		},
		{
			name: "button_text forbidden outside WARN",
			config: `
resource "pushsecurity_file_download_blocking" "test" {
  rules = [{ name = "n", enabled = true, mode = "MONITOR", button_text = "go" }]
}`,
			wantErr: regexp.MustCompile("`button_text` must not be set for mode MONITOR"),
		},
		{
			// The API rejects a message outside WARN and BLOCK. Easy to hit by
			// switching a BLOCK rule to MONITOR for a soak period.
			name: "title forbidden for MONITOR",
			config: `
resource "pushsecurity_file_download_blocking" "test" {
  rules = [{ name = "n", enabled = true, mode = "MONITOR", title = "t" }]
}`,
			wantErr: regexp.MustCompile("`title` must not be set for mode MONITOR"),
		},
		{
			// The API stores it with `/*`, so the read-back would differ.
			name: "URL pattern with no path rejected",
			config: `
resource "pushsecurity_file_download_blocking" "test" {
  rules = [{
    name = "n", enabled = true, mode = "MONITOR"
    criteria = { url_patterns = { matches = ["*://*.anydesk.com"] } }
  }]
}`,
			wantErr: regexp.MustCompile(`(?s)rewrites this URL pattern.*Write\s+"\*://\*\.anydesk\.com/\*"`),
		},
		{
			name: "URL pattern with a port rejected for downloads",
			config: `
resource "pushsecurity_file_download_blocking" "test" {
  rules = [{
    name = "n", enabled = true, mode = "MONITOR"
    criteria = { url_patterns = { matches = ["*://203.0.113.5:8040/*"] } }
  }]
}`,
			wantErr: regexp.MustCompile(`(?s)URL pattern never matches.*has\s+a\s+port`),
		},
		{
			name: "URL pattern with a query rejected for clipboard",
			config: `
resource "pushsecurity_clipboard_blocking" "test" {
  rules = [{
    name = "n", enabled = true, mode = "MONITOR", operation = "PASTE", content_capture = false
    criteria = { url_patterns = { matches = ["*://example.com/search?q=*"] } }
  }]
}`,
			wantErr: regexp.MustCompile(`(?s)URL pattern never matches.*query\s+string\s+or\s+fragment`),
		},
		{
			name: "inline regex flag rejected",
			config: `
resource "pushsecurity_file_upload_blocking" "test" {
  rules = [{
    name = "n", enabled = true, mode = "MONITOR"
    criteria = { file_name_patterns = { matches = ["(?i)anydesk"] } }
  }]
}`,
			wantErr: regexp.MustCompile(`(?s)File name pattern never matches.*sets\s+flags`),
		},
		{
			// The API stores it as "&amp;", so the read-back would differ.
			name: "ampersand in a title rejected",
			config: `
resource "pushsecurity_file_download_blocking" "test" {
  rules = [{ name = "n", enabled = true, mode = "BLOCK", title = "Terms & Conditions", subtext = "s" }]
}`,
			wantErr: regexp.MustCompile("(?s)Text must not contain `&`.*HTML-escaped"),
		},
		{
			name: "banned word in subtext rejected",
			config: `
resource "pushsecurity_file_download_blocking" "test" {
  rules = [{ name = "n", enabled = true, mode = "BLOCK", title = "t", subtext = "Enable JavaScript" }]
}`,
			wantErr: regexp.MustCompile(`Text\s+must\s+not\s+contain\s+"javascript"`),
		},
		{
			name: "mask_pii without content capture rejected",
			config: `
resource "pushsecurity_clipboard_blocking" "test" {
  rules = [{
    name = "n", enabled = true, mode = "MONITOR", operation = "PASTE"
    content_capture = false, mask_pii = true
    criteria = { url_patterns = { matches = ["*://example.com/*"] } }
  }]
}`,
			wantErr: regexp.MustCompile("(?s)`mask_pii` must not be set when\\s+`content_capture` is\\s+false"),
		},
		{
			name: "banner BLOCK button_text without reasons rejected",
			config: `
resource "pushsecurity_app_banner_url_pattern" "test" {
  rules = [{
    name = "n", enabled = true, mode = "BLOCK", title = "t", subtext = "s"
    allow_reason_submission = false, button_text = "Go"
  }]
}`,
			wantErr: regexp.MustCompile("(?s)`button_text` must not be set when\\s+`allow_reason_submission`\\s+is\\s+false"),
		},
		{
			name: "rule name too long",
			config: `
resource "pushsecurity_file_download_blocking" "test" {
  rules = [{ name = "` + strings.Repeat("n", 251) + `", enabled = true, mode = "OFF" }]
}`,
			wantErr: regexp.MustCompile(`string\s+length\s+must\s+be\s+at\s+most\s+250`),
		},
		{
			name: "too many rules",
			config: `
resource "pushsecurity_file_download_blocking" "test" {
  rules = [for i in range(51) : { name = "r${i}", enabled = true, mode = "OFF" }]
}`,
			wantErr: regexp.MustCompile(`list\s+must\s+contain\s+at\s+most\s+50\s+elements`),
		},
		{
			name: "too many matches",
			config: `
resource "pushsecurity_file_download_blocking" "test" {
  rules = [{
    name = "n", enabled = true, mode = "MONITOR"
    criteria = { employee_groups = { matches = [for i in range(51) : "g${i}"] } }
  }]
}`,
			wantErr: regexp.MustCompile(`set\s+must\s+contain\s+at\s+least\s+1\s+elements\s+and\s+at\s+most\s+50`),
		},
		{
			name: "file extensions take more matches",
			config: `
resource "pushsecurity_file_download_blocking" "test" {
  rules = [{
    name = "n", enabled = true, mode = "MONITOR"
    criteria = { file_extensions = { matches = [for i in range(201) : ".x${i}"] } }
  }]
}`,
			wantErr: regexp.MustCompile(`set\s+must\s+contain\s+at\s+least\s+1\s+elements\s+and\s+at\s+most\s+200`),
		},
		{
			name: "too many ignored hosts",
			config: `
resource "pushsecurity_phishing_tool_detection" "test" {
  rules   = []
  globals = { ignored_hosts = [for i in range(101) : "h${i}.example.com"] }
}`,
			wantErr: regexp.MustCompile(`set\s+must\s+contain\s+at\s+most\s+100\s+elements`),
		},
		{
			name: "whitespace in an excluded extension",
			config: `
resource "pushsecurity_malicious_browser_extension_detection" "test" {
  rules   = []
  globals = { excluded_extensions = [{ extension_id = "abc def" }] }
}`,
			wantErr: regexp.MustCompile(`Value\s+must\s+not\s+contain\s+whitespace`),
		},
		{
			name: "account condition rule without a domain scope",
			config: `
resource "pushsecurity_account_condition_enforcement" "test" {
  rules = [{
    name = "n", enabled = true, mode = "MONITOR"
    criteria = { app_types = { matches = ["GITHUB"] } }
  }]
}`,
			wantErr: regexp.MustCompile(`attribute\s+"domain_scope"\s+is\s+required`),
		},
		{
			name: "account condition rule without app types",
			config: `
resource "pushsecurity_account_condition_enforcement" "test" {
  rules = [{
    name = "n", enabled = true, mode = "MONITOR"
    criteria = { domain_scope = "COMPANY_DOMAINS" }
  }]
}`,
			wantErr: regexp.MustCompile(`attribute\s+"app_types"\s+is\s+required`),
		},
		{
			name: "login domains without specific domains",
			config: `
resource "pushsecurity_account_condition_enforcement" "test" {
  rules = [{
    name = "n", enabled = true, mode = "MONITOR"
    criteria = {
      app_types     = { matches = ["GITHUB"] }
      domain_scope  = "COMPANY_DOMAINS"
      login_domains = { matches = ["example.com"] }
    }
  }]
}`,
			wantErr: regexp.MustCompile("(?s)`criteria.login_domains` must not be set when\\s+`criteria.domain_scope` is\\s+COMPANY_DOMAINS"),
		},
		{
			name: "specific domains without login domains",
			config: `
resource "pushsecurity_account_condition_enforcement" "test" {
  rules = [{
    name = "n", enabled = true, mode = "MONITOR"
    criteria = {
      app_types    = { matches = ["GITHUB"] }
      domain_scope = "SPECIFIC_DOMAINS"
    }
  }]
}`,
			wantErr: regexp.MustCompile("(?s)`criteria.login_domains` is required when\\s+`criteria.domain_scope` is\\s+SPECIFIC_DOMAINS"),
		},
		{
			// The API uppercases it, so the read-back would differ.
			name: "lowercase app type rejected",
			config: `
resource "pushsecurity_account_condition_enforcement" "test" {
  rules = [{
    name = "n", enabled = true, mode = "MONITOR"
    criteria = {
      app_types    = { matches = ["github"] }
      domain_scope = "COMPANY_DOMAINS"
    }
  }]
}`,
			wantErr: regexp.MustCompile(`value\s+must\s+be\s+one\s+of`),
		},
		{
			// The API lowercases it, so the read-back would differ.
			name: "uppercase login domain rejected",
			config: `
resource "pushsecurity_account_condition_enforcement" "test" {
  rules = [{
    name = "n", enabled = true, mode = "MONITOR"
    criteria = {
      app_types     = { matches = ["GITHUB"] }
      domain_scope  = "SPECIFIC_DOMAINS"
      login_domains = { matches = ["Example.com"] }
    }
  }]
}`,
			wantErr: regexp.MustCompile(`Write\s+"example\.com"`),
		},
		{
			name: "continue button on a BLOCK account condition rule",
			config: `
resource "pushsecurity_account_condition_enforcement" "test" {
  rules = [{
    name = "n", enabled = true, mode = "BLOCK"
    title = "t", subtext = "s", terminate_button_text = "Sign out", continue_button_text = "Go"
    criteria = {
      app_types    = { matches = ["GITHUB"] }
      domain_scope = "COMPANY_DOMAINS"
    }
  }]
}`,
			wantErr: regexp.MustCompile("`continue_button_text` must not be set for mode BLOCK"),
		},
		{
			// Most controls store an empty string; this one refuses it.
			name: "empty account condition title",
			config: `
resource "pushsecurity_account_condition_enforcement" "test" {
  rules = [{
    name = "n", enabled = true, mode = "OFF", title = ""
    criteria = {
      app_types    = { matches = ["GITHUB"] }
      domain_scope = "COMPANY_DOMAINS"
    }
  }]
}`,
			wantErr: regexp.MustCompile(`string\s+length\s+must\s+be\s+between\s+1\s+and\s+75`),
		},
		{
			name: "duplicate keys rejected",
			config: `
resource "pushsecurity_file_download_blocking" "test" {
  rules = [
    { key = "same", name = "a", enabled = true, mode = "OFF" },
    { key = "same", name = "b", enabled = true, mode = "OFF" },
  ]
}`,
			wantErr: regexp.MustCompile("Duplicate rule key"),
		},
		{
			name: "unknown mode rejected",
			config: `
resource "pushsecurity_file_download_blocking" "test" {
  rules = [{ name = "n", enabled = true, mode = "NOPE" }]
}`,
			wantErr: regexp.MustCompile(`Attribute rules\[0\].mode value must be one of`),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// No PreCheck and no credentials needed: these must all fail before
			// the provider talks to the API.
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

// captureRuleID records a rule's server identifier for comparison in a later
// step.
func captureRuleID(name string, index int, into *string) resource.TestCheckFunc {
	return captureAttr(name, fmt.Sprintf("rules.%d.id", index), into)
}

// checkRuleID asserts a rule still holds a previously captured identifier.
func checkRuleID(name string, index int, want *string) resource.TestCheckFunc {
	return checkAttr(name, fmt.Sprintf("rules.%d.id", index), want)
}

// seedUnkeyedRules writes the two rules directly to the API, without
// Terraform, and returns the identifiers the server assigned them. It is the
// adoption test's stand-in for a tenant configured in the console.
//
// The content mirrors testAccTwoRules exactly, minus the keys — keys are never
// sent to the API. checkImportedUnkeyedRules holds the two in step.
func seedUnkeyedRules(t *testing.T, blockID, monitorID *string) {
	t.Helper()

	client, err := pushapi.New(os.Getenv(envBaseURL), os.Getenv(envAPIKey))
	if err != nil {
		t.Fatalf("pushapi.New: %v", err)
	}

	stored, err := client.PutControlConfig(context.Background(), "fileDownloadBlocking",
		&pushapi.ControlConfig{Rules: []pushapi.Rule{
			{
				Name: "Block executables", Enabled: true, Mode: "BLOCK",
				Fields: map[string]any{
					"title":   "Download blocked",
					"subtext": "Not permitted on company devices.",
				},
				Criteria: map[string]pushapi.Condition{
					"fileExtensions": {Matches: []string{".exe", ".msi"}},
					"employeeGroups": {Matches: []string{"Contractors"}, Action: "EXCLUDE"},
				},
			},
			{Name: "Monitor the rest", Enabled: true, Mode: "MONITOR"},
		}})
	if err != nil {
		t.Fatalf("seeding rules: %v", err)
	}
	if len(stored.Rules) != 2 {
		t.Fatalf("seeded %d rules, want 2", len(stored.Rules))
	}
	*blockID, *monitorID = stored.Rules[0].ID, stored.Rules[1].ID
}

// checkImportedUnkeyedRules asserts that what the import read back is the
// configuration under test with its keys removed. Without this the adoption
// step would keep passing if the seed drifted, while no longer testing that
// adding a key on its own preserves identity.
func checkImportedUnkeyedRules(states []*terraform.InstanceState) error {
	if len(states) != 1 {
		return fmt.Errorf("imported %d instances, want 1", len(states))
	}
	for attr, want := range map[string]string{
		"rules.#":       "2",
		"rules.0.name":  "Block executables",
		"rules.0.mode":  "BLOCK",
		"rules.0.title": "Download blocked",
		"rules.1.name":  "Monitor the rest",
		"rules.1.mode":  "MONITOR",
	} {
		if got := states[0].Attributes[attr]; got != want {
			return fmt.Errorf("imported %s = %q, want %q — the seed and testAccTwoRules have drifted apart", attr, got, want)
		}
	}
	// The property the whole test turns on: the API does not store keys, so
	// imported state cannot have any.
	for _, attr := range []string{"rules.0.key", "rules.1.key"} {
		if got, ok := states[0].Attributes[attr]; ok && got != "" {
			return fmt.Errorf("imported %s = %q, want no key", attr, got)
		}
	}
	return nil
}

const testAccTwoRules = `
resource "pushsecurity_file_download_blocking" "test" {
  rules = [
    {
      key     = "block"
      name    = "Block executables"
      enabled = true
      mode    = "BLOCK"
      title   = "Download blocked"
      subtext = "Not permitted on company devices."
      criteria = {
        file_extensions = { matches = [".exe", ".msi"] }
        employee_groups = { matches = ["Contractors"], action = "EXCLUDE" }
      }
    },
    {
      key     = "monitor"
      name    = "Monitor the rest"
      enabled = true
      mode    = "MONITOR"
    },
  ]
}
`

const testAccTwoRulesEdited = `
resource "pushsecurity_file_download_blocking" "test" {
  rules = [
    {
      key     = "block"
      name    = "Block executables"
      enabled = true
      mode    = "BLOCK"
      title   = "Blocked by policy"
      subtext = "Not permitted on company devices."
      criteria = {
        file_extensions = { matches = [".exe", ".msi"] }
        employee_groups = { matches = ["Contractors"], action = "EXCLUDE" }
      }
    },
    {
      key     = "monitor"
      name    = "Monitor the rest"
      enabled = true
      mode    = "MONITOR"
    },
  ]
}
`

const testAccTwoRulesReordered = `
resource "pushsecurity_file_download_blocking" "test" {
  rules = [
    {
      key     = "monitor"
      name    = "Monitor the rest"
      enabled = true
      mode    = "MONITOR"
    },
    {
      key     = "block"
      name    = "Block executables"
      enabled = true
      mode    = "BLOCK"
      title   = "Blocked by policy"
      subtext = "Not permitted on company devices."
      criteria = {
        file_extensions = { matches = [".exe", ".msi"] }
        employee_groups = { matches = ["Contractors"], action = "EXCLUDE" }
      }
    },
  ]
}
`

const testAccThreeRules = `
resource "pushsecurity_file_download_blocking" "test" {
  rules = [
    {
      key     = "inserted"
      name    = "Warn on archives"
      enabled = true
      mode    = "WARN"
      title   = "Careful"
      subtext = "Archives can hide executables."
      button_text = "Download anyway"
      criteria = {
        file_extensions = { matches = [".zip"] }
      }
    },
    {
      key     = "monitor"
      name    = "Monitor the rest"
      enabled = true
      mode    = "MONITOR"
    },
    {
      key     = "block"
      name    = "Block executables"
      enabled = true
      mode    = "BLOCK"
      title   = "Blocked by policy"
      subtext = "Not permitted on company devices."
      criteria = {
        file_extensions = { matches = [".exe", ".msi"] }
        employee_groups = { matches = ["Contractors"], action = "EXCLUDE" }
      }
    },
  ]
}
`

// storedBlockRule, storedMonitorRule and storedInsertedRule are the rules of
// the configurations above as the API should hold them, carrying the title
// the block rule has at that step. The lifecycle tests compare the tenant with
// them after every step, offline and live, which is what keeps the stub honest
// about what the API stores.
//
// The provider sends profileScope on every rule, the schema's default when
// configuration leaves it out, and the API stores it as sent: with no action,
// which the condition does not take. An excludable condition holds the action
// it was sent, and a text field configuration leaves out is absent.
func storedBlockRule(title string) map[string]any {
	return map[string]any{
		"name": "Block executables", "enabled": true, "mode": "BLOCK",
		"title": title, "subtext": "Not permitted on company devices.",
		"criteria": map[string]any{
			"fileExtensions": map[string]any{"matches": []any{".exe", ".msi"}, "action": "INCLUDE"},
			"employeeGroups": map[string]any{"matches": []any{"Contractors"}, "action": "EXCLUDE"},
			"profileScope":   map[string]any{"matches": []any{"ALL"}},
		},
	}
}

var storedMonitorRule = map[string]any{
	"name": "Monitor the rest", "enabled": true, "mode": "MONITOR",
	"criteria": map[string]any{
		"profileScope": map[string]any{"matches": []any{"ALL"}},
	},
}

var storedInsertedRule = map[string]any{
	"name": "Warn on archives", "enabled": true, "mode": "WARN",
	"title": "Careful", "subtext": "Archives can hide executables.", "buttonText": "Download anyway",
	"criteria": map[string]any{
		"fileExtensions": map[string]any{"matches": []any{".zip"}, "action": "INCLUDE"},
		"profileScope":   map[string]any{"matches": []any{"ALL"}},
	},
}

const testAccOneRule = `
resource "pushsecurity_file_download_blocking" "test" {
  rules = [
    {
      key     = "block"
      name    = "Block executables"
      enabled = true
      mode    = "BLOCK"
      title   = "Blocked by policy"
      subtext = "Not permitted on company devices."
      criteria = {
        file_extensions = { matches = [".exe", ".msi"] }
        employee_groups = { matches = ["Contractors"], action = "EXCLUDE" }
      }
    },
  ]
}
`
