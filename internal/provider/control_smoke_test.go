package provider

import (
	"fmt"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"

	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/provider/controlspec"
)

// TestAccAllControls_smoke applies a minimal valid rule to every one of the
// sixteen controls and requires the follow-up plan to be empty.
//
// This is the test that checks the specs against the API itself rather than
// against its published OpenAPI document.
//
// An empty plan only shows that the provider reads back what it planned, and
// both go through the provider's own conversion code. So each control's rule
// is also read back as the API holds it and compared with what was sent.
//
// Each control is a separate subtest so that one failure does not mask the
// rest, and each restores the control to empty when it finishes.
//
// The subtests run in parallel, since each touches only its own control. The
// API answers writes that collide with 409, which the client retries, as
// TestAccAllControls_parallel shows. No other test runs alongside them: Go
// finishes a test's parallel subtests before it starts the next test.
func TestAccAllControls_smoke(t *testing.T) {
	for _, spec := range controlspec.All {
		t.Run(spec.TypeName, func(t *testing.T) {
			t.Parallel()
			rule := minimalConfig(spec)
			addr := spec.ResourceName() + ".smoke"

			resource.Test(t, resource.TestCase{
				PreCheck:                 func() { testAccPreCheck(t) },
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				CheckDestroy:             checkStoredRules(spec),
				Steps: []resource.TestStep{
					{
						Config: rule.config,
						Check: resource.ComposeAggregateTestCheckFunc(
							resource.TestCheckResourceAttr(addr, "rules.#", "1"),
							resource.TestCheckResourceAttr(addr, "rules.0.mode", rule.mode),
							resource.TestCheckResourceAttrSet(addr, "rules.0.id"),
							resource.TestCheckResourceAttr(addr, "rules.0.key", "smoke"),
							checkStoredRules(spec, rule.stored),
						),
						ConfigPlanChecks: resource.ConfigPlanChecks{
							// The engine's core promise: what was planned is
							// what the server stores, so a refresh finds
							// nothing to change.
							PostApplyPostRefresh: []plancheck.PlanCheck{
								plancheck.ExpectEmptyPlan(),
							},
						},
					},
				},
			})
		})
	}
}

// TestAccAllControls_parallel applies the smoke test's minimal rule to every
// control in one configuration, so that Terraform writes them all at once at
// its default parallelism of ten. That is what a configuration managing the
// whole tenant does on its first apply and its last destroy, and the smoke
// test, one control at a time, never does.
//
// The API serialises configuration writes per tenant and answers the ones
// that collide with 409, which the client retries. What must not happen is a
// 429: the client retries that too, so the apply would still pass, but a
// burst of this size tripping the rate limit means a larger configuration
// would spend its retry budget waiting. Every request the provider makes is
// recorded to tell. Each control is empty again at the end.
//
// TestAllControls_parallelOffline runs it against tenantStub.
func TestAccAllControls_parallel(t *testing.T) {
	if os.Getenv(resource.EnvTfAcc) == "" {
		t.Skipf("acceptance tests skipped unless env %q is set", resource.EnvTfAcc)
	}
	testAccPreCheck(t)
	log := logRequests(t)
	t.Cleanup(func() { checkNotRateLimited(t, log) })
	tc := parallelTestCase()
	tc.PreCheck = func() { testAccPreCheck(t) }
	resource.Test(t, tc)
}

// parallelTestCase applies every control's minimal rule in one configuration,
// requires the plan after it to be empty, and compares what each control then
// holds with what was sent.
func parallelTestCase() resource.TestCase {
	var config strings.Builder
	var checks, destroyed []resource.TestCheckFunc
	for _, spec := range controlspec.All {
		rule := minimalConfig(spec)
		addr := spec.ResourceName() + ".smoke"
		config.WriteString(rule.config)
		checks = append(checks,
			resource.TestCheckResourceAttr(addr, "rules.#", "1"),
			resource.TestCheckResourceAttrSet(addr, "rules.0.id"),
			checkStoredRules(spec, rule.stored),
		)
		destroyed = append(destroyed, checkStoredRules(spec))
	}

	return resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             resource.ComposeAggregateTestCheckFunc(destroyed...),
		Steps: []resource.TestStep{{
			Config: config.String(),
			Check:  resource.ComposeAggregateTestCheckFunc(checks...),
			ConfigPlanChecks: resource.ConfigPlanChecks{
				PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
			},
		}},
	}
}

// checkNotRateLimited fails the test if the API answered any of the provider's
// requests with 429, and logs how many collided with another write.
func checkNotRateLimited(t *testing.T, log *requestLog) {
	t.Helper()
	t.Logf("the provider made %d requests; %d were answered 409 and retried",
		len(log.all()), log.answered(http.StatusConflict))
	if n := log.answered(http.StatusTooManyRequests); n > 0 {
		t.Errorf("the API rate-limited %d of the provider's requests; "+
			"the apply only got through because the client retried them", n)
	}
}

// minimalRule is the smallest rule the API will accept for a control: the
// configuration that sets it, the mode it uses, and the rule as the API should
// then hold it.
type minimalRule struct {
	config string
	mode   string
	stored map[string]any
}

// minimalConfig generates the smallest configuration the API will accept for a
// control, driven by the spec rather than hand-written per control — otherwise
// this test would be sixteen more blocks of transcription to keep in step.
//
// The stored rule is what the provider sends for that configuration: the
// values it sets, and those the schema plans for what it leaves out.
func minimalConfig(s controlspec.Spec) minimalRule {
	mode := leastDemandingMode(s)
	stored := map[string]any{"name": "terraform acceptance test", "enabled": false, "mode": mode}

	var rule []string
	rule = append(rule,
		`key     = "smoke"`,
		`name    = "terraform acceptance test"`,
		`enabled = false`,
		fmt.Sprintf("mode    = %q", mode),
	)

	// Fields the API requires regardless of mode, then fields this mode
	// requires. Anything forbidden in this mode is left out, and a field left
	// out that has a server default is planned, and sent, as that default.
	for _, f := range s.Fields {
		set := (f.Required || requiredForMode(s, f.Name, mode)) && !forbiddenForMode(s, f.Name, mode)
		switch {
		case set:
			v := placeholderFor(f)
			rule = append(rule, fmt.Sprintf("%s = %s", f.Name, hclValue(v)))
			stored[f.APIName] = v
		case f.ServerDefault != nil:
			stored[f.APIName] = f.ServerDefault
		}
	}

	crit, sent := minimalCriteria(s)
	if crit != "" {
		rule = append(rule, crit)
	}
	stored["criteria"] = sent

	var b strings.Builder
	fmt.Fprintf(&b, "resource %q \"smoke\" {\n", s.ResourceName())
	b.WriteString("  rules = [{\n")
	for _, line := range rule {
		fmt.Fprintf(&b, "    %s\n", line)
	}
	b.WriteString("  }]\n}\n")
	return minimalRule{config: b.String(), mode: mode, stored: stored}
}

// leastDemandingMode picks the mode with the fewest required fields, so that
// the generated rule stays minimal and does not depend on placeholder text
// being acceptable.
func leastDemandingMode(s controlspec.Spec) string {
	best, bestCost := s.Modes[0], -1
	for _, m := range s.Modes {
		cost := 0
		for _, c := range s.Constraints {
			switch c.Kind {
			case controlspec.RequiredForModes:
				if slices.Contains(c.Modes, m) {
					cost++
				}
			case controlspec.RequiredWhenCriterionAbsent:
				// These demand a field precisely when a criterion is missing,
				// which is the situation a minimal rule is in.
				if len(c.Modes) == 0 || slices.Contains(c.Modes, m) {
					cost++
				}
			}
		}
		if bestCost == -1 || cost < bestCost {
			best, bestCost = m, cost
		}
	}
	return best
}

func requiredForMode(s controlspec.Spec, field, mode string) bool {
	for _, c := range s.Constraints {
		if c.Kind != controlspec.RequiredForModes || c.Field != field {
			continue
		}
		if slices.Contains(c.Modes, mode) {
			return true
		}
	}
	return false
}

func forbiddenForMode(s controlspec.Spec, field, mode string) bool {
	for _, c := range s.Constraints {
		switch c.Kind {
		case controlspec.ForbiddenForModes:
			if c.Field == field && slices.Contains(c.Modes, mode) {
				return true
			}
		case controlspec.RequiredWhenCriterionSet:
			// Forbidden when the criterion is absent, which it is here.
			if c.Field == field {
				return true
			}
		case controlspec.RequiredWhenCriterionAbsent:
			// Forbidden outside the modes it applies to.
			if c.Field == field && len(c.Modes) > 0 && !slices.Contains(c.Modes, mode) {
				return true
			}
		}
	}
	return false
}

// minimalCriteria satisfies a control's criteria requirements, and nothing
// more. It returns the criteria block, if one is needed, and the criteria the
// provider sends for it: an excludable condition carries the schema's default
// action, and a single-valued criterion with a server default is sent as that
// default when the block leaves it out.
func minimalCriteria(s controlspec.Spec) (string, map[string]any) {
	need := s.CriteriaRequired
	var parts []string
	sent := map[string]any{}

	add := func(c controlspec.Criterion, v string) {
		if c.Single {
			parts = append(parts, fmt.Sprintf("      %s = %q", c.Name, v))
			sent[c.APIName] = map[string]any{"matches": []any{v}}
			return
		}
		parts = append(parts, fmt.Sprintf("      %s = { matches = [%q] }", c.Name, v))
		cond := map[string]any{"matches": []any{v}}
		if c.Excludable {
			cond["action"] = actionInclude
		}
		sent[c.APIName] = cond
	}

	// Criteria the API requires on every rule come first, and may be all the
	// block needs.
	for _, c := range s.Criteria {
		if !c.Required {
			continue
		}
		if c.Single {
			add(c, undemandingValue(s, c))
			continue
		}
		v := criterionPlaceholders[c.Name]
		if v == "" && len(c.Enum) > 0 {
			v = c.Enum[0]
		}
		add(c, v)
	}

	var wanted []string
	for _, c := range s.Constraints {
		if c.Kind != controlspec.AtLeastOneCriterion {
			continue
		}
		need = true
		for _, name := range c.Others {
			if criterionPlaceholders[name] != "" {
				wanted = append(wanted, name)
				break
			}
		}
	}

	if need {
		// A control with required criteria and no at-least-one rule still
		// needs something in the block; employee_groups is universally
		// available.
		if len(wanted) == 0 && len(parts) == 0 {
			wanted = append(wanted, "employee_groups")
		}
		for _, name := range wanted {
			for _, c := range s.Criteria {
				if c.Name == name && criterionPlaceholders[name] != "" {
					add(c, criterionPlaceholders[name])
				}
			}
		}
	}

	for _, c := range s.Criteria {
		if _, ok := sent[c.APIName]; !ok && c.Single && c.ServerDefault != "" {
			sent[c.APIName] = map[string]any{"matches": []any{c.ServerDefault}}
		}
	}

	if !need {
		return "", sent
	}
	return "criteria = {\n" + strings.Join(parts, "\n") + "\n    }", sent
}

// undemandingValue picks a value for a single-valued criterion that does not in
// turn require another criterion: COMPANY_DOMAINS rather than SPECIFIC_DOMAINS,
// which would need login domains.
func undemandingValue(s controlspec.Spec, c controlspec.Criterion) string {
	for _, v := range c.Enum {
		demanding := false
		for _, k := range s.Constraints {
			if k.Kind == controlspec.CriterionRequiredForValues && k.Other == c.Name &&
				slices.Contains(k.Values, v) {
				demanding = true
			}
		}
		if !demanding {
			return v
		}
	}
	return c.Enum[0]
}

// criterionPlaceholders are values the API accepts for each criterion. Values
// have to be plausible, not merely well-typed: url_patterns must be
// `*://`-prefixed, and app_categories takes numeric category identifiers.
var criterionPlaceholders = map[string]string{
	"employee_groups":              "terraform-acceptance-tests",
	"url_patterns":                 "*://terraform-acceptance.example.com/",
	"file_extensions":              ".tfacc",
	"browser_extension_severities": "HIGH",
	"app_categories":               "2",
	"approval_statuses":            "NOT_REVIEWED",
	"sensitivity_levels":           "NOT_REVIEWED",
}

// placeholderFor returns a value for a field as the wire carries it; hclValue
// writes it as configuration.
func placeholderFor(f controlspec.Field) any {
	switch f.Type {
	case controlspec.TypeBool:
		// False keeps the rule minimal: content_capture true would in turn
		// require mask_pii.
		return false
	case controlspec.TypeEnum:
		return f.Enum[0]
	case controlspec.TypeEnumSet:
		return []any{f.Enum[0]}
	default:
		return "terraform acceptance test"
	}
}

func hclValue(v any) string {
	switch v := v.(type) {
	case bool:
		return strconv.FormatBool(v)
	case []any:
		items := make([]string, 0, len(v))
		for _, e := range v {
			items = append(items, hclValue(e))
		}
		return "[" + strings.Join(items, ", ") + "]"
	default:
		return fmt.Sprintf("%q", v)
	}
}
