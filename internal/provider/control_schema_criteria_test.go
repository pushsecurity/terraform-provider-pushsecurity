package provider

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/provider/controlspec"
	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/pushapi"
)

func criteriaAttribute(t *testing.T, s controlspec.Spec) schema.SingleNestedAttribute {
	t.Helper()
	a, ok := buildRuleAttributes(s)["criteria"]
	if !ok {
		t.Fatalf("%s has no criteria attribute", s.TypeName)
	}
	nested, ok := a.(schema.SingleNestedAttribute)
	if !ok {
		t.Fatalf("criteria is %T, want SingleNestedAttribute", a)
	}
	return nested
}

// TestEveryControlsCriteriaCarriesADefault guards against "Provider produced
// inconsistent result after apply: .rules[0].criteria.profile_scope: was null,
// but now cty.StringVal(\"ALL\")".
//
// A profileScope with no ServerDefault would plan an omitted criteria block as
// null while the API returns "ALL". Every control carries the default, and
// criteriaFromAPI normalises the omitted case back to it, so both directions
// agree.
func TestEveryControlsCriteriaCarriesADefault(t *testing.T) {
	for _, spec := range controlspec.All {
		if len(spec.Criteria) == 0 || spec.CriteriaRequired {
			continue
		}
		t.Run(spec.TypeName, func(t *testing.T) {
			if criteriaAttribute(t, spec).Default == nil {
				t.Error("criteria has no default, so an omitted block plans null")
			}
		})
	}
}

// TestSingleCriteriaAllCarryAServerDefault guards the premise the criteria
// default rests on: an optional single-valued criterion the provider cannot
// predict would plan null where the API may return a value, and nothing else
// would catch it before the apply. A required one is exempt: it is never
// omitted.
func TestSingleCriteriaAllCarryAServerDefault(t *testing.T) {
	for _, spec := range controlspec.All {
		for _, c := range spec.Criteria {
			if c.Single && c.ServerDefault == "" && !c.Required {
				t.Errorf("%s.%s is single-valued with no ServerDefault: an omitted "+
					"criteria block will plan null and the apply may return a value",
					spec.TypeName, c.Name)
			}
		}
	}
}

func TestRequiredCriteriaIsStillRequired(t *testing.T) {
	for _, spec := range []controlspec.Spec{
		controlspec.ClipboardBlocking, controlspec.AccountConditionEnforcement,
	} {
		crit := criteriaAttribute(t, spec)
		if !crit.Required {
			t.Errorf("%s criteria must stay required: the API rejects a rule without it",
				spec.TypeName)
		}
		if crit.Default != nil {
			t.Errorf("%s: a required attribute must not carry a default", spec.TypeName)
		}
	}
}

// TestRequiredCriterionIsARequiredAttribute covers both shapes a required
// criterion takes: a plain string for a single-valued one, and a nested
// object for the rest. Either way Terraform itself reports it missing.
func TestRequiredCriterionIsARequiredAttribute(t *testing.T) {
	attrs := criteriaAttribute(t, controlspec.AccountConditionEnforcement).Attributes
	for name, required := range map[string]bool{
		"domain_scope":  true,
		"app_types":     true,
		"login_domains": false,
		"profile_scope": false,
	} {
		a, ok := attrs[name]
		if !ok {
			t.Errorf("no criterion %s", name)
			continue
		}
		if a.IsRequired() != required || a.IsOptional() == required {
			t.Errorf("%s: required = %v, optional = %v; want required = %v",
				name, a.IsRequired(), a.IsOptional(), required)
		}
	}
}

func TestSchemaStaysValidForEveryControl(t *testing.T) {
	// Optional+Computed+PlanModifiers is easy to get subtly wrong; the
	// framework's own check catches it without needing Terraform.
	ctx := context.Background()
	for _, spec := range controlspec.All {
		t.Run(spec.TypeName, func(t *testing.T) {
			if diags := buildSchema(spec).ValidateImplementation(ctx); diags.HasError() {
				t.Errorf("invalid schema: %v", diags)
			}
		})
	}
}

func TestDerivedPatternEnum(t *testing.T) {
	// Each name exercises the derivation differently: mixed case, digits,
	// parentheses, hyphens, dots, runs of punctuation and spaces, and
	// punctuation at the end.
	for _, tc := range []struct{ name, want string }{
		{"Example Identifiers (email)", "CUSTOM_EXAMPLE_IDENTIFIERS_EMAIL"},
		{"Example Cloud (all regions) - Access Key ID - long-term",
			"CUSTOM_EXAMPLE_CLOUD_ALL_REGIONS_ACCESS_KEY_ID_LONG_TERM"},
		{"Example AI (Model 2) - API key (id.secret)",
			"CUSTOM_EXAMPLE_AI_MODEL_2_API_KEY_ID_SECRET"},
		{"Generic (multi-provider) - compatible sk key",
			"CUSTOM_GENERIC_MULTI_PROVIDER_COMPATIBLE_SK_KEY"},
		{"Example vendor - API key (direct via proxy)",
			"CUSTOM_EXAMPLE_VENDOR_API_KEY_DIRECT_VIA_PROXY"},
		// The renamed pattern the validateGlobals tests below use.
		{"Renamed example pattern (email)",
			"CUSTOM_RENAMED_EXAMPLE_PATTERN_EMAIL"},
	} {
		if got := derivedPatternEnum(tc.name); got != tc.want {
			t.Errorf("derivedPatternEnum(%q) = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// contentPatterns builds a clipboard `globals` object holding one custom
// content pattern.
func contentPatterns(t *testing.T, name, enum string) types.Object {
	t.Helper()
	spec := controlspec.ClipboardBlocking
	objType := globalsObjectType(spec)

	listType := objType.AttrTypes["custom_content_patterns"].(types.ListType)
	elemType := listType.ElemType.(types.ObjectType)

	elem := types.ObjectValueMust(elemType.AttrTypes, map[string]attr.Value{
		"name":  types.StringValue(name),
		"enum":  types.StringValue(enum),
		"regex": types.StringValue("x"),
	})

	vals := map[string]attr.Value{}
	for n, typ := range objType.AttrTypes {
		switch tt := typ.(type) {
		case types.ListType:
			vals[n] = types.ListValueMust(tt.ElemType, []attr.Value{elem})
		case types.SetType:
			vals[n] = types.SetValueMust(tt.ElemType, nil)
		default:
			vals[n] = types.StringNull()
		}
	}
	return types.ObjectValueMust(objType.AttrTypes, vals)
}

func TestValidateGlobalsCatchesAnEnumThatDoesNotMatchItsName(t *testing.T) {
	// The failure this prevents is a 400 at apply, after review and merge.
	diags := validateGlobals(controlspec.ClipboardBlocking,
		contentPatterns(t, "Renamed example pattern (email)",
			"CUSTOM_EXAMPLE_PATTERN_EMAIL"))

	if !diags.HasError() {
		t.Fatal("a stale enum was accepted")
	}
	d := diags.Errors()[0]
	if d.Summary() != "Pattern enum does not match its name" {
		t.Errorf("summary = %q", d.Summary())
	}
	// The message has to give the value to use, or it is not actionable.
	if want := "CUSTOM_RENAMED_EXAMPLE_PATTERN_EMAIL"; !strings.Contains(d.Detail(), want) {
		t.Errorf("detail does not name the correct enum %q: %s", want, d.Detail())
	}
}

func TestValidateGlobalsAcceptsAConsistentPattern(t *testing.T) {
	if diags := validateGlobals(controlspec.ClipboardBlocking,
		contentPatterns(t, "Example pattern (email)",
			"CUSTOM_EXAMPLE_PATTERN_EMAIL")); diags.HasError() {
		t.Errorf("a consistent pattern was rejected: %v", diags.Errors())
	}
}

func TestValidateGlobalsAllowsAnOmittedEnum(t *testing.T) {
	// The API's own advice is "omit enum to have it derived automatically".
	if diags := validateGlobals(controlspec.ClipboardBlocking,
		contentPatterns(t, "Anything at all", "")); diags.HasError() {
		t.Errorf("an omitted enum was rejected: %v", diags.Errors())
	}
}

// TestOmittedSingleCriterionReadsBackAsItsDefault covers the console-created
// rule: the API returns no profileScope at all, and state must still say "ALL"
// so that configuration omitting the criteria block plans empty.
func TestOmittedSingleCriterionReadsBackAsItsDefault(t *testing.T) {
	spec := controlspec.MaliciousBrowserExtensionDetection
	res := testResolver(t, &employeeStub{employees: testEmployees})

	// criteria {} — exactly what a console-created rule comes back as.
	got, diags := criteriaFromAPI(context.Background(), spec, res,
		map[string]pushapi.Condition{}, nil, "Block: All employees")
	if diags.HasError() {
		t.Fatalf("criteriaFromAPI: %v", diags.Errors())
	}

	ps := got.(types.Object).Attributes()["profile_scope"].(types.String)
	if ps.IsNull() || ps.ValueString() != "ALL" {
		t.Errorf("profile_scope = %v, want \"ALL\": absent is documented as meaning ALL", ps)
	}

	// And it must equal what an omitted criteria block plans to, or the two
	// disagree and the rule replans forever.
	want := defaultCriteria(spec).Attributes()["profile_scope"].(types.String)
	if !ps.Equal(want) {
		t.Errorf("read %v but the schema default plans %v", ps, want)
	}
}

// TestExplicitSingleCriterionSurvivesTheNormalisation makes sure the default is
// only a fallback, not an override.
func TestExplicitSingleCriterionSurvivesTheNormalisation(t *testing.T) {
	spec := controlspec.MaliciousBrowserExtensionDetection
	res := testResolver(t, &employeeStub{employees: testEmployees})

	got, diags := criteriaFromAPI(context.Background(), spec, res,
		map[string]pushapi.Condition{"profileScope": {Matches: []string{"COMPANY_DOMAIN"}}},
		nil, "a rule")
	if diags.HasError() {
		t.Fatalf("criteriaFromAPI: %v", diags.Errors())
	}
	if v := got.(types.Object).Attributes()["profile_scope"].(types.String).ValueString(); v != "COMPANY_DOMAIN" {
		t.Errorf("profile_scope = %q, want COMPANY_DOMAIN", v)
	}
}

// TestSingleCriterionWithSeveralValuesKeepsTheFirst pins what happens to a
// single-valued criterion that comes back holding more than one value: state
// can only hold one, so it keeps the first and says so, rather than failing
// the refresh or dropping the rest without a word.
func TestSingleCriterionWithSeveralValuesKeepsTheFirst(t *testing.T) {
	spec := controlspec.MaliciousBrowserExtensionDetection
	res := testResolver(t, &employeeStub{employees: testEmployees})

	got, diags := criteriaFromAPI(context.Background(), spec, res,
		map[string]pushapi.Condition{"profileScope": {Matches: []string{"COMPANY_DOMAIN", "NON_COMPANY_DOMAIN"}}},
		nil, "a rule")
	if diags.HasError() {
		t.Fatalf("criteriaFromAPI: %v", diags.Errors())
	}
	if v := got.(types.Object).Attributes()["profile_scope"].(types.String).ValueString(); v != "COMPANY_DOMAIN" {
		t.Errorf("profile_scope = %q, want COMPANY_DOMAIN", v)
	}
	warnings := diags.Warnings()
	if len(warnings) != 1 || warnings[0].Summary() != "Criterion holds more than one value" {
		t.Fatalf("warnings = %v, want one saying the criterion holds more than one value", warnings)
	}
	for _, want := range []string{"criteria.profile_scope", "NON_COMPANY_DOMAIN", `"a rule"`} {
		if !strings.Contains(warnings[0].Detail(), want) {
			t.Errorf("warning detail %q does not mention %s", warnings[0].Detail(), want)
		}
	}
}
