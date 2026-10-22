package provider

import (
	"context"
	"fmt"
	"maps"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/provider/controlspec"
	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/pushapi"
)

// TestAccControlResource_changedOutsideTerraform applies two keyed rules, then
// edits the control over the API the way the console would: one rule changed,
// one added and one deleted. The plan that follows must report all three as
// drift, and the apply must put the configuration back while the rule that
// survived keeps its identifier.
//
// It uses passwordLoggingPrevention, which no other acceptance test configures
// apart from those that cover every control, and replaces its whole
// configuration. TestControlResource_changedOutsideTerraform runs the same
// steps against tenantStub.
func TestAccControlResource_changedOutsideTerraform(t *testing.T) {
	tc := driftTestCase(t)
	tc.PreCheck = func() { testAccPreCheck(t) }
	resource.Test(t, tc)
}

const testDriftResource = "pushsecurity_password_logging_prevention.tf_acc"

// driftTestCase is the drift test, for a real tenant or tenantStub, whichever
// the provider is pointed at.
func driftTestCase(t *testing.T) resource.TestCase {
	spec := controlspec.PasswordLoggingPrevention
	var blockID, monitorID, addedID, restoredID string

	return resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             checkStoredRules(spec),
		Steps: []resource.TestStep{
			{
				Config: testAccDriftRules,
				Check: resource.ComposeAggregateTestCheckFunc(
					captureRuleID(testDriftResource, 0, &blockID),
					captureRuleID(testDriftResource, 1, &monitorID),
					checkStoredRules(spec, storedDriftBlockRule(driftBlockTitle), storedDriftMonitorRule),
				),
			},
			{
				PreConfig: func() { addedID = editOutsideTerraform(t, spec, blockID, monitorID) },
				Config:    testAccDriftRules,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(testDriftResource, plancheck.ResourceActionUpdate),
						// The refresh has to have read the tenant as it now is,
						// in its order: the added rule first, with no key, then
						// the changed one, which keeps its key.
						expectRulesDrifted(testDriftResource,
							driftedRule{id: &addedID, name: driftAddedName},
							driftedRule{id: &blockID, key: "tf-acc-block", name: driftBlockName, title: driftChangedTitle},
						),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(testDriftResource, "rules.#", "2"),
					resource.TestCheckResourceAttr(testDriftResource, "rules.0.title", driftBlockTitle),
					// The survivor keeps its identifier through the edit and
					// the restore.
					checkRuleID(testDriftResource, 0, &blockID),
					// The deleted rule is recreated, so it is new to the
					// tenant, and must not have taken over the added rule's
					// identifier on its way back: that rule is gone.
					captureRuleID(testDriftResource, 1, &restoredID),
					checkNotEqual("the restored rule's identifier", &restoredID, "the added rule's", &addedID),
					checkNotEqual("the restored rule's identifier", &restoredID, "the deleted rule's", &monitorID),
					checkStoredRules(spec, storedDriftBlockRule(driftBlockTitle), storedDriftMonitorRule),
				),
			},
		},
	}
}

const (
	driftBlockName    = "Terraform acceptance: block password entry"
	driftBlockTitle   = "Password entry blocked"
	driftChangedTitle = "Changed outside Terraform"
	driftMonitorName  = "Terraform acceptance: monitor password entry"
	driftAddedName    = "Terraform acceptance: added outside Terraform"
)

const testAccDriftRules = `
resource "pushsecurity_password_logging_prevention" "tf_acc" {
  rules = [
    {
      key     = "tf-acc-block"
      name    = "Terraform acceptance: block password entry"
      enabled = true
      mode    = "BLOCK"
      title   = "Password entry blocked"
      subtext = "Company passwords only go into company login pages."
      criteria = {
        app_types = { matches = ["GITHUB"] }
      }
    },
    {
      key     = "tf-acc-monitor"
      name    = "Terraform acceptance: monitor password entry"
      enabled = true
      mode    = "MONITOR"
    },
  ]
}
`

// storedDriftBlockRule and storedDriftMonitorRule are testAccDriftRules as the
// API should hold them. This control has no profile scope, so none is sent.
func storedDriftBlockRule(title string) map[string]any {
	return map[string]any{
		"name": driftBlockName, "enabled": true, "mode": "BLOCK",
		"title": title, "subtext": "Company passwords only go into company login pages.",
		"criteria": map[string]any{
			"appTypes": map[string]any{"matches": []any{"GITHUB"}, "action": "INCLUDE"},
		},
	}
}

var storedDriftMonitorRule = map[string]any{
	"name": driftMonitorName, "enabled": true, "mode": "MONITOR", "criteria": map[string]any{},
}

// editOutsideTerraform changes the control over the API, without Terraform:
// the stand-in for edits made in the console. It retitles the block rule,
// deletes the monitor rule, and adds a rule ahead of the rest, then returns
// the identifier the added rule was given.
//
// The block rule is sent back as it was read, so it keeps its identifier and
// everything but its title.
func editOutsideTerraform(t *testing.T, spec controlspec.Spec, blockID, monitorID string) string {
	t.Helper()
	ctx := context.Background()
	client, err := pushapi.New(firstNonEmpty(os.Getenv(envBaseURL), pushapi.DefaultBaseURL), os.Getenv(envAPIKey))
	if err != nil {
		t.Fatalf("pushapi.New: %v", err)
	}
	cfg, err := client.GetControlConfig(ctx, spec.APIName)
	if err != nil {
		t.Fatalf("reading %s: %v", spec.APIName, err)
	}
	if len(cfg.Rules) != 2 || cfg.Rules[0].ID != blockID || cfg.Rules[1].ID != monitorID {
		t.Fatalf("%s holds %d rules, not the two the first step applied", spec.APIName, len(cfg.Rules))
	}

	block := cfg.Rules[0]
	block.Fields = maps.Clone(block.Fields)
	block.Fields["title"] = driftChangedTitle
	added := pushapi.Rule{Name: driftAddedName, Enabled: true, Mode: "MONITOR"}
	cfg.Rules = []pushapi.Rule{added, block}

	stored, err := client.PutControlConfig(ctx, spec.APIName, cfg)
	if err != nil {
		t.Fatalf("editing %s outside Terraform: %v", spec.APIName, err)
	}
	if len(stored.Rules) != 2 || stored.Rules[1].ID != blockID {
		t.Fatalf("editing %s outside Terraform: the changed rule did not keep its identifier", spec.APIName)
	}
	return stored.Rules[0].ID
}

// driftedRule is what the refresh should have read of one rule. An empty key
// or title means the attribute is null.
type driftedRule struct {
	id               *string
	key, name, title string
}

// expectRulesDrifted asserts the plan reports, as a change made outside
// Terraform, that a control now holds exactly these rules, in this order.
func expectRulesDrifted(addr string, want ...driftedRule) plancheck.PlanCheck {
	return rulesDrift{addr: addr, want: want}
}

type rulesDrift struct {
	addr string
	want []driftedRule
}

func (d rulesDrift) CheckPlan(_ context.Context, req plancheck.CheckPlanRequest, resp *plancheck.CheckPlanResponse) {
	for _, rc := range req.Plan.ResourceDrift {
		if rc.Address != d.addr || rc.Change == nil {
			continue
		}
		after, _ := rc.Change.After.(map[string]any)
		rules, _ := after["rules"].([]any)
		if len(rules) != len(d.want) {
			resp.Error = fmt.Errorf("%s drifted to %d rules, want %d", d.addr, len(rules), len(d.want))
			return
		}
		for i, w := range d.want {
			rule, _ := rules[i].(map[string]any)
			for attr, want := range map[string]any{
				"id": *w.id, "key": nullIfEmpty(w.key), "name": w.name, "title": nullIfEmpty(w.title),
			} {
				if got := rule[attr]; got != want {
					resp.Error = fmt.Errorf("%s drifted, but its refreshed rules[%d].%s is %v, want %v",
						d.addr, i, attr, got, want)
					return
				}
			}
		}
		return
	}
	resp.Error = fmt.Errorf("the plan reports no drift in %s, want the rules changed outside Terraform", d.addr)
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// checkNotEqual asserts two captured values differ.
func checkNotEqual(what string, got *string, other string, otherValue *string) resource.TestCheckFunc {
	return func(*terraform.State) error {
		if *got == *otherValue {
			return fmt.Errorf("%s is %q, the same as %s", what, *got, other)
		}
		return nil
	}
}
