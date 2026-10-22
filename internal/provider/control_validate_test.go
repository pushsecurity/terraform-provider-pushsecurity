package provider

import (
	"context"
	"slices"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/provider/controlspec"
)

// TestCriterionValueValidatorSeverity checks the validator passes a value's
// problem through at the right severity: an error fails the plan, a warning
// only reports.
func TestCriterionValueValidatorSeverity(t *testing.T) {
	urls, ok := controlspec.FileDownloadBlocking.Criterion("url_patterns")
	if !ok {
		t.Fatal("file_download_blocking has no url_patterns")
	}
	v := criterionValueValidator{urls}

	for _, tc := range []struct {
		in       string
		severity diag.Severity // 0 for no diagnostic
	}{
		{"*://*.anydesk.com/*", 0},
		{"*://*.anydesk.com", diag.SeverityError},
		{"*://example.com:443/*", diag.SeverityWarning},
	} {
		t.Run(tc.in, func(t *testing.T) {
			at := path.Root("rules").AtListIndex(0).AtName("criteria").AtName("url_patterns").
				AtName("matches").AtSetValue(types.StringValue(tc.in))
			resp := &validator.StringResponse{}
			v.ValidateString(context.Background(), validator.StringRequest{
				Path: at, ConfigValue: types.StringValue(tc.in),
			}, resp)

			if tc.severity == 0 {
				if len(resp.Diagnostics) != 0 {
					t.Fatalf("diagnostics = %v, want none", resp.Diagnostics)
				}
				return
			}
			if len(resp.Diagnostics) != 1 {
				t.Fatalf("diagnostics = %v, want one", resp.Diagnostics)
			}
			d := resp.Diagnostics[0]
			if d.Severity() != tc.severity {
				t.Errorf("severity = %v, want %v", d.Severity(), tc.severity)
			}
			if wp, ok := d.(diag.DiagnosticWithPath); !ok || !wp.Path().Equal(at) {
				t.Errorf("diagnostic is not on the value's path %s: %v", at, d)
			}
		})
	}

	// Unknown values are left alone: they have no value to check until apply.
	resp := &validator.StringResponse{}
	v.ValidateString(context.Background(), validator.StringRequest{
		Path: path.Root("x"), ConfigValue: types.StringUnknown(),
	}, resp)
	if len(resp.Diagnostics) != 0 {
		t.Errorf("an unknown value produced %v", resp.Diagnostics)
	}
}

// TestRuleTextIsCheckedOnEveryRuleTextField checks the schema puts the text
// check on every rule text field of every control and of custom detections,
// and not on the control-wide settings, which the API stores as written.
func TestRuleTextIsCheckedOnEveryRuleTextField(t *testing.T) {
	hasTextCheck := func(a schema.Attribute) bool {
		sa, ok := a.(schema.StringAttribute)
		if !ok {
			return false
		}
		for _, v := range sa.Validators {
			if _, ok := v.(ruleTextValidator); ok {
				return true
			}
		}
		return false
	}

	for _, s := range append(controlspec.All, controlspec.CustomDetectionRules) {
		attrs := buildRuleAttributes(s)
		for _, f := range s.Fields {
			if got, want := hasTextCheck(attrs[f.Name]), f.IsText(); got != want {
				t.Errorf("%s.%s: text check = %v, want %v", s.TypeName, f.Name, got, want)
			}
		}
		if hasTextCheck(attrs["name"]) {
			t.Errorf("%s: the API stores the rule name as written, so it must not be checked", s.TypeName)
		}
		if len(s.Globals) == 0 {
			continue
		}
		for _, g := range buildGlobalAttributes(s) {
			list, ok := g.(schema.ListNestedAttribute)
			if !ok {
				continue
			}
			for name, a := range list.NestedObject.Attributes {
				if hasTextCheck(a) {
					t.Errorf("%s globals attribute %s has the rule text check", s.TypeName, name)
				}
			}
		}
	}
}

func TestRuleTextValidator(t *testing.T) {
	title, _ := controlspec.AppBanner.Field("title")
	subtext, _ := controlspec.AppBanner.Field("subtext")
	for _, tc := range []struct {
		field   controlspec.Field
		in      types.String
		wantErr bool
	}{
		{title, types.StringValue("Terms & Conditions"), true},
		{title, types.StringValue("Terms and Conditions"), false},
		{subtext, types.StringValue("Terms & Conditions"), false},
		{subtext, types.StringValue("JAVASCRIPT"), true},
		{title, types.StringUnknown(), false},
		{title, types.StringNull(), false},
	} {
		resp := &validator.StringResponse{}
		ruleTextValidator{tc.field}.ValidateString(context.Background(), validator.StringRequest{
			Path: path.Root("rules").AtListIndex(0).AtName(tc.field.Name), ConfigValue: tc.in,
		}, resp)
		if resp.Diagnostics.HasError() != tc.wantErr {
			t.Errorf("%s %s: diagnostics = %v, want error = %v", tc.field.Name, tc.in, resp.Diagnostics, tc.wantErr)
		}
	}
}

// TestObjectRuleValuesIsFalse checks a boolean that is not yet known counts as
// neither true nor false, so a constraint on it waits for apply.
func TestObjectRuleValuesIsFalse(t *testing.T) {
	r := objectRuleValues{map[string]attr.Value{
		"no":      types.BoolValue(false),
		"yes":     types.BoolValue(true),
		"unknown": types.BoolUnknown(),
		"null":    types.BoolNull(),
	}}
	for field, want := range map[string]bool{"no": true, "yes": false, "unknown": false, "null": false, "absent": false} {
		if got := r.IsFalse(field); got != want {
			t.Errorf("IsFalse(%q) = %v, want %v", field, got, want)
		}
	}
}

// TestValidateRulesSkipsWhatIsNotYetKnown checks a constraint on a value that
// is not known until apply, such as one taken from another resource, waits for
// it instead of failing the plan. Each case is a clipboard blocking rule, the
// control with the most kinds of constraint; the known cases alongside show
// the same rules do fail once the value is there to check.
func TestValidateRulesSkipsWhatIsNotYetKnown(t *testing.T) {
	spec := controlspec.ClipboardBlocking
	ctx := context.Background()
	ruleType := ruleObjectType(spec)
	critType := criteriaObjectType(spec)

	unknownOf := func(typ attr.Type) attr.Value {
		v, err := typ.ValueFromTerraform(ctx, tftypes.NewValue(typ.TerraformType(ctx), tftypes.UnknownValue))
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	nullOf := func(typ attr.Type) attr.Value {
		v, err := typ.ValueFromTerraform(ctx, tftypes.NewValue(typ.TerraformType(ctx), nil))
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	matching := func(name, value string) attr.Value {
		inner := critType.AttrTypes[name].(types.ObjectType).AttrTypes
		return types.ObjectValueMust(inner, map[string]attr.Value{
			"matches": types.SetValueMust(types.StringType, []attr.Value{types.StringValue(value)}),
		})
	}
	// criteria builds the criteria object: every criterion null but those
	// given.
	criteria := func(set map[string]attr.Value) attr.Value {
		vals := make(map[string]attr.Value, len(critType.AttrTypes))
		for name, typ := range critType.AttrTypes {
			vals[name] = nullOf(typ)
		}
		for name, v := range set {
			vals[name] = v
		}
		return types.ObjectValueMust(critType.AttrTypes, vals)
	}
	urls := map[string]attr.Value{"url_patterns": matching("url_patterns", "*://example.com/*")}
	// rule builds a COPY rule without content capture: every other attribute
	// null but those given.
	rule := func(set map[string]attr.Value) types.List {
		vals := make(map[string]attr.Value, len(ruleType.AttrTypes))
		for name, typ := range ruleType.AttrTypes {
			vals[name] = nullOf(typ)
		}
		vals["operation"] = types.StringValue("COPY")
		vals["content_capture"] = types.BoolValue(false)
		for name, v := range set {
			vals[name] = v
		}
		return types.ListValueMust(ruleType, []attr.Value{types.ObjectValueMust(ruleType.AttrTypes, vals)})
	}
	str := types.StringValue
	block := func(set map[string]attr.Value) map[string]attr.Value {
		set["mode"], set["title"], set["subtext"] = str("BLOCK"), str("Blocked"), str("Not here.")
		return set
	}

	for _, tc := range []struct {
		name  string
		rules types.List
		// want is the attributes errors must be reported on, under rules[0].
		want []string
	}{
		{
			// Neither whether the rule matches on regex patterns nor whether it
			// matches on anything at all can be told yet.
			name:  "criteria unknown",
			rules: rule(block(map[string]attr.Value{"criteria": unknownOf(critType)})),
		},
		{
			name:  "criteria known",
			rules: rule(block(map[string]attr.Value{"criteria": criteria(urls)})),
			want:  []string{"acknowledge_button_text"},
		},
		{
			name: "criteria known but empty",
			rules: rule(block(map[string]attr.Value{
				"criteria": criteria(nil), "acknowledge_button_text": str("OK"),
			})),
			want: []string{"criteria"},
		},
		{
			name: "regex patterns unknown",
			rules: rule(block(map[string]attr.Value{"criteria": criteria(map[string]attr.Value{
				"url_patterns":   urls["url_patterns"],
				"regex_patterns": unknownOf(critType.AttrTypes["regex_patterns"]),
			})})),
		},
		{
			// A MONITOR rule takes no title, but an unknown one may yet be
			// null.
			name: "title unknown outside the modes that take it",
			rules: rule(map[string]attr.Value{
				"mode": str("MONITOR"), "title": unknownOf(types.StringType), "criteria": criteria(urls),
			}),
		},
		{
			name: "title known outside the modes that take it",
			rules: rule(map[string]attr.Value{
				"mode": str("MONITOR"), "title": str("Copied"), "criteria": criteria(urls),
			}),
			want: []string{"title"},
		},
		{
			name: "mask_pii unknown without content capture",
			rules: rule(map[string]attr.Value{
				"mode": str("MONITOR"), "mask_pii": unknownOf(types.BoolType), "criteria": criteria(urls),
			}),
		},
		{
			name: "mask_pii known without content capture",
			rules: rule(map[string]attr.Value{
				"mode": str("MONITOR"), "mask_pii": types.BoolValue(false), "criteria": criteria(urls),
			}),
			want: []string{"mask_pii"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			for _, d := range validateRules(spec, tc.rules) {
				wp, ok := d.(diag.DiagnosticWithPath)
				if !ok {
					t.Fatalf("diagnostic without a path: %v", d)
				}
				steps := wp.Path().Steps()
				if len(steps) < 3 {
					t.Fatalf("diagnostic at %s, want it under rules[0]", wp.Path())
				}
				got = append(got, steps[2].String())
			}
			slices.Sort(got)
			if !slices.Equal(got, tc.want) {
				t.Errorf("errors on %v, want %v", got, tc.want)
			}
		})
	}
}
