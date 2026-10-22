package provider

import (
	"fmt"
	"maps"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/provider/controlspec"
	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/pushapi"
)

// TestAccAllControls_maximal is the counterpart of TestAccAllControls_smoke.
// Where that applies the smallest rule each control accepts, this applies one
// that sets every field and every criterion the spec allows, and every global.
//
// The smoke test can only catch a disagreement with the API about what a rule
// must have. This one covers what a rule may have, which otherwise only the
// stub checks: optional fields and criteria, enum sets the server reorders,
// fields with a server default set away from it, globals the server sorts or
// derives values for, and criteria holding several values.
//
// As with the smoke test, each control is its own subtest, the subtests run in
// parallel, each restores its control to empty when it finishes, and each is
// read back as the API holds it as well as through the provider.
func TestAccAllControls_maximal(t *testing.T) {
	if os.Getenv(resource.EnvTfAcc) == "" {
		t.Skipf("acceptance tests skipped unless env %q is set", resource.EnvTfAcc)
	}
	testAccPreCheck(t)
	// The employee criterion names real people, so they come from the tenant.
	employees := tenantEmployees(t, 2)

	for _, spec := range controlspec.All {
		t.Run(spec.TypeName, func(t *testing.T) {
			t.Parallel()
			rule := mustMaximalConfig(t, spec, employees)
			tc := maximalTestCase(spec, rule)
			tc.PreCheck = func() { testAccPreCheck(t) }
			resource.Test(t, tc)
		})
	}
}

// maximalTestCase applies a maximal rule, requires the plan after it to be
// empty, and compares what the tenant then holds with what was sent.
func maximalTestCase(spec controlspec.Spec, rule maximalRule) resource.TestCase {
	addr := spec.ResourceName() + ".maximal"
	return resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: resource.ComposeAggregateTestCheckFunc(
			checkStoredRules(spec),
			checkStoredGlobalsEmpty(spec),
		),
		Steps: []resource.TestStep{{
			Config: rule.config,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr(addr, "rules.#", "1"),
				resource.TestCheckResourceAttr(addr, "rules.0.mode", rule.mode),
				resource.TestCheckResourceAttrSet(addr, "rules.0.id"),
				resource.TestCheckResourceAttr(addr, "rules.0.key", "maximal"),
				checkStoredRules(spec, rule.stored),
				checkStoredGlobals(spec, rule.globals),
			),
			ConfigPlanChecks: resource.ConfigPlanChecks{
				PostApplyPostRefresh: []plancheck.PlanCheck{
					plancheck.ExpectEmptyPlan(),
				},
			},
		}},
	}
}

// maximalRule is the fullest rule a control accepts: the configuration that
// sets it, its mode, the rule and globals as the API should then hold them,
// and what was left out and why.
type maximalRule struct {
	config  string
	mode    string
	stored  map[string]any
	globals map[string]any
	omitted []string
}

// mustMaximalConfig generates a control's maximal rule, failing the test if
// the spec has something the generator has no value for, and logs what the
// spec's constraints kept out of it.
func mustMaximalConfig(t *testing.T, spec controlspec.Spec, employees []pushapi.Employee) maximalRule {
	t.Helper()
	rule, err := maximalConfig(spec, employees)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range rule.omitted {
		t.Logf("left out of the maximal %s rule: %s", spec.TypeName, o)
	}
	return rule
}

// maximalConfig generates a control's maximal rule from the spec, as
// minimalConfig does its minimal one.
//
// It starts from every criterion and every field, then lets the spec's own
// constraints, through CheckRule, say what has to go: a field a mode forbids,
// or one that a criterion it needs to be absent rules out. Criteria are kept
// over fields where the two conflict, since a criterion carries more of the
// rule's meaning. The mode chosen is the one that keeps the most fields.
//
// Values are chosen to exercise what a minimal rule cannot: enum sets hold
// several values, in reverse order, and so do criteria; booleans are true and
// enums take their last value, which keeps both away from the server
// defaults; a single-valued criterion takes a value that brings in another
// criterion where it can, and otherwise one that is not its default; and
// excludable criteria are EXCLUDE.
func maximalConfig(s controlspec.Spec, employees []pushapi.Employee) (maximalRule, error) {
	excluded := maximalExclusions[s.TypeName]
	var omitted []string
	for _, name := range slices.Sorted(maps.Keys(excluded)) {
		omitted = append(omitted, fmt.Sprintf("%s (excluded: %s)", name, excluded[name]))
	}

	globals, globalsHCL, enums, err := maximalGlobals(s)
	if err != nil {
		return maximalRule{}, err
	}

	cand := maximalCandidate{fields: map[string]any{}, criteria: map[string]string{}}
	for _, c := range s.Criteria {
		if _, ok := excluded[c.Name]; ok {
			continue
		}
		cand.criteria[c.Name] = ""
		if c.Single {
			cand.criteria[c.Name] = maximalSingleValue(s, c)
		}
	}

	var best *maximalCandidate
	var bestDropped []string
	for _, mode := range s.Modes {
		c, dropped, ok := cand.settle(s, mode, excluded)
		if !ok {
			continue
		}
		if best == nil || c.better(*best) {
			best, bestDropped = &c, dropped
		}
	}
	if best == nil {
		return maximalRule{}, fmt.Errorf("%s: no mode accepts a rule with every criterion; "+
			"add an exclusion to maximalExclusions", s.TypeName)
	}
	omitted = append(omitted, bestDropped...)

	stored := map[string]any{"name": "terraform acceptance test", "enabled": false, "mode": best.mode}
	rule := []string{
		`key     = "maximal"`,
		`name    = "terraform acceptance test"`,
		// Disabled, as in the smoke test: a rule this broad, naming real
		// employees, must not act on anyone while the test runs.
		`enabled = false`,
		fmt.Sprintf("mode    = %q", best.mode),
	}

	for _, f := range s.Fields {
		v, set := best.fields[f.Name]
		switch {
		case set:
			rule = append(rule, fmt.Sprintf("%s = %s", f.Name, hclValue(v)))
			stored[f.APIName] = v
		case f.ServerDefault != nil:
			stored[f.APIName] = f.ServerDefault
		}
	}

	crit, sent, err := maximalCriteria(s, best.criteria, employees, enums)
	if err != nil {
		return maximalRule{}, err
	}
	if crit != "" {
		rule = append(rule, crit)
	}
	stored["criteria"] = sent

	var b strings.Builder
	fmt.Fprintf(&b, "resource %q \"maximal\" {\n", s.ResourceName())
	if globalsHCL != "" {
		b.WriteString(globalsHCL)
	}
	b.WriteString("  rules = [{\n")
	for _, line := range rule {
		fmt.Fprintf(&b, "    %s\n", line)
	}
	b.WriteString("  }]\n}\n")

	return maximalRule{
		config: b.String(), mode: best.mode, stored: stored, globals: globals, omitted: omitted,
	}, nil
}

// maximalExclusions are fields and criteria left out of a control's maximal
// rule for reasons the spec does not encode, by control and then by
// attribute, each with the reason. Conflicts the spec does encode are worked
// out from its constraints and need no entry here.
//
// It is empty because no such conflict is known. An entry belongs here only
// once the API has shown one, and its reason should say what the API did.
var maximalExclusions = map[string]map[string]string{}

// maximalCandidate is a rule being settled: its mode, the fields it sets with
// their values, and the criteria it sets, with the value of each
// single-valued one.
type maximalCandidate struct {
	mode     string
	fields   map[string]any
	criteria map[string]string
}

func (c maximalCandidate) Mode() string { return c.mode }

func (c maximalCandidate) IsSet(field string) bool {
	v, ok := c.fields[field]
	return ok && v != ""
}

func (c maximalCandidate) IsTrue(field string) bool  { return c.fields[field] == true }
func (c maximalCandidate) IsFalse(field string) bool { return c.fields[field] == false }

func (c maximalCandidate) HasCriterion(name string) bool {
	_, ok := c.criteria[name]
	return ok
}

func (c maximalCandidate) CriterionValue(name string) string { return c.criteria[name] }

// settle starts from every field in mode and removes what CheckRule objects
// to until nothing is left to object to. A boolean is turned false before it
// is removed. It reports what it removed, and false if a violation remains
// that removing something cannot fix: a field or criterion the mode requires
// and the candidate cannot have.
func (c maximalCandidate) settle(s controlspec.Spec, mode string, excluded map[string]string) (maximalCandidate, []string, bool) {
	out := maximalCandidate{mode: mode, fields: map[string]any{}, criteria: maps.Clone(c.criteria)}
	for _, f := range s.Fields {
		if _, ok := excluded[f.Name]; !ok {
			out.fields[f.Name] = maximalFieldValue(f)
		}
	}

	var dropped []string
	for range len(s.Fields) + len(s.Criteria) + 1 {
		violations := s.CheckRule(out)
		if len(violations) == 0 {
			return out, dropped, true
		}
		v := violations[0]
		switch {
		case v.Field != "" && out.fields[v.Field] == true:
			out.fields[v.Field] = false
		case v.Field != "" && out.IsSet(v.Field):
			delete(out.fields, v.Field)
			dropped = append(dropped, fmt.Sprintf("%s (%s)", v.Field, v.Summary))
		case v.Criterion != "" && out.HasCriterion(v.Criterion):
			delete(out.criteria, v.Criterion)
			dropped = append(dropped, fmt.Sprintf("criteria.%s (%s)", v.Criterion, v.Summary))
		default:
			return out, nil, false
		}
	}
	return out, nil, false
}

// better prefers the candidate that sets more fields, then more of them true,
// then one whose mode is not OFF: telemetry has no fields, and an OFF rule
// says little about the others.
func (c maximalCandidate) better(than maximalCandidate) bool {
	if len(c.fields) != len(than.fields) {
		return len(c.fields) > len(than.fields)
	}
	if c.trues() != than.trues() {
		return c.trues() > than.trues()
	}
	return than.mode == "OFF" && c.mode != "OFF"
}

func (c maximalCandidate) trues() int {
	n := 0
	for _, v := range c.fields {
		if v == true {
			n++
		}
	}
	return n
}

// maximalFieldValue returns a value for a field as the wire carries it,
// chosen to differ from any server default.
func maximalFieldValue(f controlspec.Field) any {
	switch f.Type {
	case controlspec.TypeBool:
		return true
	case controlspec.TypeEnum:
		for i := len(f.Enum) - 1; i >= 0; i-- {
			if f.Enum[i] != f.ServerDefault {
				return f.Enum[i]
			}
		}
		return f.Enum[0]
	case controlspec.TypeEnumSet:
		// Every value, in reverse: an order the server is unlikely to keep.
		vals := make([]any, 0, len(f.Enum))
		for i := len(f.Enum) - 1; i >= 0; i-- {
			vals = append(vals, f.Enum[i])
		}
		return vals
	default:
		v := "Terraform acceptance: " + f.Name
		if f.MaxLength > 0 && len(v) > f.MaxLength {
			v = v[:f.MaxLength]
		}
		return v
	}
}

// maximalSingleValue picks a value for a single-valued criterion: one that
// brings in another criterion where there is one, as SPECIFIC_DOMAINS brings
// in login domains, and otherwise the first that is not the server default.
func maximalSingleValue(s controlspec.Spec, c controlspec.Criterion) string {
	for _, v := range c.Enum {
		for _, k := range s.Constraints {
			if k.Kind == controlspec.CriterionRequiredForValues && k.Other == c.Name &&
				slices.Contains(k.Values, v) {
				return v
			}
		}
	}
	for _, v := range c.Enum {
		if v != c.ServerDefault {
			return v
		}
	}
	return c.Enum[0]
}

// maximalCriteria writes the criteria block for the criteria a candidate
// sets, and returns the criteria the API should hold for it.
func maximalCriteria(s controlspec.Spec, set map[string]string, employees []pushapi.Employee, enums []string) (string, map[string]any, error) {
	var parts []string
	sent := map[string]any{}

	for _, c := range s.Criteria {
		single, ok := set[c.Name]
		if !ok {
			// Left out: the server default, if it has one, is what it holds.
			if c.Single && c.ServerDefault != "" {
				sent[c.APIName] = map[string]any{"matches": []any{c.ServerDefault}}
			}
			continue
		}
		if c.Single {
			parts = append(parts, fmt.Sprintf("      %s = %q", c.Name, single))
			sent[c.APIName] = map[string]any{"matches": []any{single}}
			continue
		}

		config, wire, err := maximalMatches(c, employees, enums)
		if err != nil {
			return "", nil, fmt.Errorf("%s: %w", s.TypeName, err)
		}
		cond := map[string]any{"matches": wire}
		line := fmt.Sprintf("      %s = { matches = %s", c.Name, hclValue(config))
		if c.Excludable {
			cond["action"] = "EXCLUDE"
			line += `, action = "EXCLUDE"`
		}
		parts = append(parts, line+" }")
		sent[c.APIName] = cond
	}

	if len(parts) == 0 {
		return "", sent, nil
	}
	return "criteria = {\n" + strings.Join(parts, "\n") + "\n    }", sent, nil
}

// maximalMatches returns the values for a multi-valued criterion, as
// configuration writes them and as the wire carries them, which differ only
// for employees. Every value must pass the criterion's own checks, and there
// must be more than one wherever the API allows it.
func maximalMatches(c controlspec.Criterion, employees []pushapi.Employee, enums []string) ([]any, []any, error) {
	var config, wire []any
	switch {
	case c.ResolvesEmails():
		for _, e := range employees {
			config = append(config, e.Email)
			wire = append(wire, e.ID)
		}
	case c.Name == "regex_patterns":
		// The custom content patterns the globals declare, by the enum the
		// server derives from each name, in reverse.
		for i := len(enums) - 1; i >= 0; i-- {
			config = append(config, enums[i])
		}
	case len(c.Enum) > 0:
		// The last, middle and first values, which no sort leaves in this
		// order.
		for _, i := range []int{len(c.Enum) - 1, len(c.Enum) / 2, 0} {
			if !slices.Contains(config, any(c.Enum[i])) {
				config = append(config, c.Enum[i])
			}
		}
	default:
		for _, v := range maximalCriterionValues[c.Name] {
			config = append(config, v)
		}
	}
	if wire == nil {
		wire = config
	}

	if len(config) > c.MatchesLimit() {
		config, wire = config[:c.MatchesLimit()], wire[:c.MatchesLimit()]
	}
	if want := min(2, c.MatchesLimit()); len(config) < want {
		return nil, nil, fmt.Errorf("criteria.%s has %d values, want at least %d: add them to "+
			"maximalCriterionValues", c.Name, len(config), want)
	}
	for _, v := range config {
		if p := c.CheckValue(v.(string)); p != nil {
			return nil, nil, fmt.Errorf("criteria.%s value %q: %s", c.Name, v, p.Summary)
		}
	}
	return config, wire, nil
}

// maximalCriterionValues are values for the criteria that have no enum to
// choose from, several of each where the API allows it, and none in sorted
// order. As with criterionPlaceholders they have to be plausible: the URL
// patterns, file names, extensions and domains pass the checks the provider
// makes during plan.
var maximalCriterionValues = map[string][]string{
	"employee_groups":    {"terraform-acceptance-tests-b", "terraform-acceptance-tests-a"},
	"url_patterns":       {"*://terraform-acceptance.example.com/*", "*://*.terraform-acceptance.example.org/path/*"},
	"file_names":         {"tfacc-setup", "terraform-acceptance"},
	"file_name_patterns": {`^tfacc-[0-9]+\.bin$`, `[Tt]erraform[Aa]cceptance`},
	"file_extensions":    {".tfacc", ".tfacc.gz"},
	"app_types":          {"SLACK", "GITHUB"},
	"app_labels":         {"terraform-acceptance-b", "terraform-acceptance-a"},
	"login_domains":      {"tfacc.example.org", "terraform-acceptance.example.com"},
	// The API allows one value.
	"browser_extension_profile":         {"NON_COMPANY_DOMAINS"},
	"browser_extensions":                {"ponmlkjihgfedcbaponmlkjihgfedcba", "abcdefghijklmnopabcdefghijklmnop"},
	"browser_extension_permissions":     {"tabs", "cookies"},
	"browser_extension_deployment_type": {"SIDELOAD", "DEVELOPMENT"},
	"browser_extension_severities":      {"HIGH", "LOW"},
}

// maximalGlobals sets every global a control has, with several entries each.
// It returns the globals as the API should hold them, the globals block, and
// the enums the server derives for custom content patterns, which the rule's
// criteria refer to.
func maximalGlobals(s controlspec.Spec) (map[string]any, string, []string, error) {
	if len(s.Globals) == 0 {
		return nil, "", nil, nil
	}
	stored := map[string]any{}
	var enums, parts []string

	for _, g := range s.Globals {
		switch g.Type {
		case controlspec.GlobalObjectList:
			entries := maximalGlobalObjects[g.Name]
			if len(entries) < 2 {
				return nil, "", nil, fmt.Errorf("%s: globals.%s needs at least two entries in "+
					"maximalGlobalObjects", s.TypeName, g.Name)
			}
			var items []any
			var objs []string
			for _, entry := range entries {
				item := map[string]any{}
				var attrs []string
				for _, f := range g.Attributes {
					if f.Computed {
						// The only computed attribute is a custom content
						// pattern's enum, which the server derives from the
						// name.
						enum := derivedPatternEnum(entry["name"])
						item[f.APIName] = enum
						enums = append(enums, enum)
						continue
					}
					v, ok := entry[f.Name]
					if !ok {
						return nil, "", nil, fmt.Errorf("%s: maximalGlobalObjects has no value "+
							"for globals.%s.%s", s.TypeName, g.Name, f.Name)
					}
					item[f.APIName] = v
					attrs = append(attrs, fmt.Sprintf("%s = %q", f.Name, v))
				}
				items = append(items, item)
				objs = append(objs, "      { "+strings.Join(attrs, ", ")+" },")
			}
			stored[g.APIName] = items
			parts = append(parts, fmt.Sprintf("    %s = [\n%s\n    ]", g.Name, strings.Join(objs, "\n")))

		default:
			vals := maximalGlobalStrings[g.Name]
			if len(vals) < 2 {
				return nil, "", nil, fmt.Errorf("%s: globals.%s needs at least two entries in "+
					"maximalGlobalStrings", s.TypeName, g.Name)
			}
			wire := make([]any, 0, len(vals))
			for _, v := range vals {
				wire = append(wire, v)
			}
			stored[g.APIName] = wire
			parts = append(parts, fmt.Sprintf("    %s = %s", g.Name, hclValue(wire)))
		}
	}

	return stored, "  globals = {\n" + strings.Join(parts, "\n") + "\n  }\n", enums, nil
}

// maximalGlobalStrings and maximalGlobalObjects are the values for each
// global, by its Terraform name and then, for an object, by attribute.
var (
	// One host of each form the API documents, in an order a sort changes.
	maximalGlobalStrings = map[string][]string{
		"ignored_hosts": {"tfacc-b.example.com", "10.0.1.1", "*.tfacc-a.example.com", "tfacchost"},
	}
	maximalGlobalObjects = map[string][]map[string]string{
		"excluded_extensions": {
			{"extension_id": "ponmlkjihgfedcbaponmlkjihgfedcba", "notes": "Terraform acceptance: second"},
			{"extension_id": "abcdefghijklmnopabcdefghijklmnop", "notes": "Terraform acceptance: first"},
		},
		"custom_content_patterns": {
			{"name": "Terraform acceptance ticket", "regex": `TFACC-\d{6}`},
			{"name": "Terraform acceptance change", "regex": `TFCHG-[0-9]{4}`},
		},
	}
)

// storedGlobals returns a control's globals as the tenant holds them.
func storedGlobals(spec controlspec.Spec) (map[string]any, error) {
	var doc struct {
		Globals map[string]any `json:"globals"`
	}
	if err := tenantRequest(http.MethodGet, spec.Path(), nil, &doc); err != nil {
		return nil, err
	}
	return doc.Globals, nil
}

// checkStoredGlobals asserts that the tenant holds exactly these globals for a
// control, as checkStoredRules does for rules: a list of strings may come back
// in any order, and everything else must match.
func checkStoredGlobals(spec controlspec.Spec, want map[string]any) resource.TestCheckFunc {
	return func(*terraform.State) error {
		if len(spec.Globals) == 0 {
			return nil
		}
		got, err := storedGlobals(spec)
		if err != nil {
			return err
		}
		if diffs := diffJSON("globals", normaliseJSON(got), normaliseJSON(want)); len(diffs) > 0 {
			return fmt.Errorf("%s globals as stored differ from what was intended:\n  %s",
				spec.APIName, strings.Join(diffs, "\n  "))
		}
		return nil
	}
}

// checkStoredGlobalsEmpty asserts that every global a control holds is empty,
// which is what destroy leaves. Absent and null count as empty: the provider
// reads both that way.
func checkStoredGlobalsEmpty(spec controlspec.Spec) resource.TestCheckFunc {
	return func(*terraform.State) error {
		got, err := storedGlobals(spec)
		if err != nil {
			return err
		}
		for k, v := range got {
			if items, ok := v.([]any); v != nil && (!ok || len(items) > 0) {
				return fmt.Errorf("%s globals.%s is %s after destroy, want empty",
					spec.APIName, k, compactJSON(v))
			}
		}
		return nil
	}
}

// tenantEmployees returns up to n of the tenant's employees, the first by
// email address, so that the choice is the same from run to run.
func tenantEmployees(t *testing.T, n int) []pushapi.Employee {
	t.Helper()
	var page struct {
		Result []pushapi.Employee `json:"result"`
	}
	if err := tenantRequest(http.MethodGet, "/v1/employees", nil, &page); err != nil {
		t.Fatalf("listing employees: %v", err)
	}
	if len(page.Result) == 0 {
		t.Fatal("the tenant has no employees for the employee criterion to name")
	}
	slices.SortFunc(page.Result, func(a, b pushapi.Employee) int { return strings.Compare(a.Email, b.Email) })
	return page.Result[:min(n, len(page.Result))]
}
