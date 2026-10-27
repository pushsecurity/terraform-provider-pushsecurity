package provider

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/provider/controlspec"
)

// validateRules adapts Terraform values to the constraint interface and turns
// violations into diagnostics. The rules themselves live in controlspec so
// that this and CheckStored give identical answers.
//
// Checking during plan matters because the API has no dry-run endpoint:
// anything not caught here is only discovered when the apply returns a 400, by
// which point the change has been reviewed and merged.
func validateRules(s controlspec.Spec, rules types.List) diag.Diagnostics {
	var diags diag.Diagnostics

	for i, e := range rules.Elements() {
		obj, ok := e.(types.Object)
		if !ok || obj.IsNull() || obj.IsUnknown() {
			continue
		}

		rulePath := path.Root("rules").AtListIndex(i)
		for _, v := range s.CheckRule(objectRuleValues{obj.Attributes()}) {
			// A violation with neither a field nor a criterion is about the
			// rule's criteria as a whole, which is the only rule-level
			// constraint there is.
			at := rulePath.AtName("criteria")
			switch {
			case v.Field != "":
				at = rulePath.AtName(v.Field)
			case v.Criterion != "":
				at = at.AtName(v.Criterion)
			}
			diags.AddAttributeError(at, v.Summary, v.Detail)
		}
	}

	return diags
}

type objectRuleValues struct {
	attrs map[string]attr.Value
}

// CheckRule finds Unknowns by a type assertion, so nothing else would notice
// if these methods stopped matching it.
var _ controlspec.Unknowns = objectRuleValues{}

func (o objectRuleValues) Mode() string { return stringOrEmpty(o.attrs["mode"]) }

func (o objectRuleValues) IsSet(field string) bool { return valueIsSet(o.attrs[field]) }

func (o objectRuleValues) IsTrue(field string) bool { return boolOrFalse(o.attrs[field]) }

func (o objectRuleValues) IsFalse(field string) bool {
	bv, ok := o.attrs[field].(types.Bool)
	return ok && !bv.IsNull() && !bv.IsUnknown() && !bv.ValueBool()
}

func (o objectRuleValues) HasCriterion(name string) bool {
	crit, ok := o.attrs["criteria"].(types.Object)
	if !ok || crit.IsNull() || crit.IsUnknown() {
		return false
	}
	return valueIsSet(crit.Attributes()[name])
}

func (o objectRuleValues) CriterionValue(name string) string {
	crit, ok := o.attrs["criteria"].(types.Object)
	if !ok || crit.IsNull() || crit.IsUnknown() {
		return ""
	}
	return stringOrEmpty(crit.Attributes()[name])
}

// FieldUnknown and CriterionUnknown let CheckRule skip a constraint on a value
// that is not known until apply, such as one taken from another resource.
// Treating it as either set or absent would fail some plans for nothing.
func (o objectRuleValues) FieldUnknown(field string) bool {
	v := o.attrs[field]
	return v != nil && v.IsUnknown()
}

func (o objectRuleValues) CriterionUnknown(name string) bool {
	crit, ok := o.attrs["criteria"].(types.Object)
	if !ok || crit.IsNull() {
		return false
	}
	if crit.IsUnknown() {
		return true
	}
	v := crit.Attributes()[name]
	return v != nil && v.IsUnknown()
}

// valueIsSet reports whether an attribute has a usable value. A value not yet
// known has none; CheckRule does not ask about one, since it skips the
// constraints that depend on it.
func valueIsSet(v attr.Value) bool {
	if v == nil || v.IsNull() || v.IsUnknown() {
		return false
	}
	// An empty string is not a value. That is the provider's rule, not the
	// API's: see controlspec.RuleValues.
	if sv, ok := v.(types.String); ok {
		return sv.ValueString() != ""
	}
	return true
}

// criterionValueValidator checks one value of a criterion's matches against
// what will happen to it: the API rejects it at apply, rewrites it so the
// read-back differs, or stores it and it never matches. The rules live in
// controlspec, beside the cross-field ones; see Criterion.CheckValue.
type criterionValueValidator struct {
	criterion controlspec.Criterion
}

func (criterionValueValidator) Description(context.Context) string {
	return "must be a value the Push API stores as written and that can match"
}

func (v criterionValueValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v criterionValueValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	p := v.criterion.CheckValue(req.ConfigValue.ValueString())
	switch {
	case p == nil:
	case p.Warning:
		resp.Diagnostics.AddAttributeWarning(req.Path, p.Summary, p.Detail)
	default:
		resp.Diagnostics.AddAttributeError(req.Path, p.Summary, p.Detail)
	}
}

// employeeMatchesNotEmptyValidator rejects an employee criterion that names
// nobody, as the API does, saying what to write instead. It is the plan-time
// half of the warning a read raises for a rule that names only employees the
// tenant no longer holds.
type employeeMatchesNotEmptyValidator struct{}

func (employeeMatchesNotEmptyValidator) Description(context.Context) string {
	return "must name at least one employee"
}

func (v employeeMatchesNotEmptyValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (employeeMatchesNotEmptyValidator) ValidateSet(_ context.Context, req validator.SetRequest, resp *validator.SetResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() || len(req.ConfigValue.Elements()) > 0 {
		return
	}
	resp.Diagnostics.AddAttributeError(req.Path, "Employee criterion names nobody",
		"An employee criterion needs at least one employee email address.\n\n"+
			"Configuration generated from a rule that names only employees the tenant no "+
			"longer holds looks like this. That rule applies to nobody, and to keep it that "+
			"way, set `enabled = false` and remove `employee_ids`: a disabled rule applies to "+
			"nobody too. To apply it to people instead, list their addresses here. Or remove "+
			"the rule.\n\n"+
			"Do not remove `employee_ids` and leave the rule enabled: a rule without an "+
			"employee criterion applies to every employee. With `action = \"EXCLUDE\"`, "+
			"though, removing `employee_ids` is right: excluding nobody is what a rule without "+
			"one does.")
}

// ruleTextValidator checks a rule text field against what the API does with
// text on write: HTML-escape it, so that it reads back changed, or refuse it
// outright. The rules live in controlspec; see Field.CheckText.
type ruleTextValidator struct {
	field controlspec.Field
}

func (ruleTextValidator) Description(context.Context) string {
	return "must be text the Push API stores as written"
}

func (v ruleTextValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v ruleTextValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if p := v.field.CheckText(req.ConfigValue.ValueString()); p != nil {
		resp.Diagnostics.AddAttributeError(req.Path, p.Summary, p.Detail)
	}
}

// noWhitespaceValidator rejects a value holding any whitespace, as the API
// does for an excluded extension's identifier.
type noWhitespaceValidator struct{}

func (noWhitespaceValidator) Description(context.Context) string {
	return "must not contain whitespace"
}

func (v noWhitespaceValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (noWhitespaceValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if strings.IndexFunc(req.ConfigValue.ValueString(), unicode.IsSpace) >= 0 {
		resp.Diagnostics.AddAttributeError(req.Path, "Value must not contain whitespace",
			fmt.Sprintf("The Push API rejects %q because it contains whitespace. An extension "+
				"ID never does, so check for a stray space or line break.",
				req.ConfigValue.ValueString()))
	}
}

// validateKeysUnique enforces the one invariant the key mechanism depends on.
// Duplicate keys make identity ambiguous, which is the problem keys exist to
// solve.
func validateKeysUnique(rules types.List) diag.Diagnostics {
	var diags diag.Diagnostics

	seen := make(map[string]int, len(rules.Elements()))
	for i, e := range rules.Elements() {
		obj, ok := e.(types.Object)
		if !ok || obj.IsNull() || obj.IsUnknown() {
			continue
		}
		key := stringOrEmpty(obj.Attributes()["key"])
		if key == "" {
			continue
		}
		if first, dup := seen[key]; dup {
			diags.AddAttributeError(
				path.Root("rules").AtListIndex(i).AtName("key"),
				"Duplicate rule key",
				fmt.Sprintf("`key` must be unique within a control, but %q is also used by "+
					"rules[%d]. Keys are how the provider tracks which rule is which across "+
					"reorders; duplicates make that ambiguous.", key, first),
			)
			continue
		}
		seen[key] = i
	}

	return diags
}

// derivedPatternEnum reproduces how the API derives a custom content pattern's
// `enum` from its `name`: upper-cased, every run of non-alphanumerics collapsed
// to one underscore, trimmed, and prefixed with CUSTOM_.
var nonAlphanumeric = regexp.MustCompile(`[^A-Z0-9]+`)

func derivedPatternEnum(name string) string {
	return "CUSTOM_" + strings.Trim(nonAlphanumeric.ReplaceAllString(strings.ToUpper(name), "_"), "_")
}

// validateGlobals checks the control-wide settings that the API validates on
// write but the schema cannot express.
//
// Only one such setting exists: a clipboard custom content pattern's `enum` is
// derived from its `name`, so setting the two inconsistently is a 400 at apply,
// which is exactly the class of failure validateRules exists to prevent. It is
// easy to hit: renaming a pattern without touching its enum is a one-line edit
// that looks harmless, and the rules referencing the old enum have to change
// too.
func validateGlobals(s controlspec.Spec, globals types.Object) diag.Diagnostics {
	var diags diag.Diagnostics
	if globals.IsNull() || globals.IsUnknown() {
		return diags
	}

	for _, g := range s.Globals {
		if g.Type != controlspec.GlobalObjectList || !hasField(g, "enum") {
			continue
		}
		list, ok := globals.Attributes()[g.Name].(types.List)
		if !ok || list.IsNull() || list.IsUnknown() {
			continue
		}

		for i, e := range list.Elements() {
			obj, ok := e.(types.Object)
			if !ok || obj.IsNull() || obj.IsUnknown() {
				continue
			}
			attrs := obj.Attributes()
			name, enum := stringOrEmpty(attrs["name"]), stringOrEmpty(attrs["enum"])
			// An absent enum is the documented way to have it derived.
			if name == "" || enum == "" {
				continue
			}
			if want := derivedPatternEnum(name); enum != want {
				diags.AddAttributeError(
					path.Root("globals").AtName(g.Name).AtListIndex(i).AtName("enum"),
					"Pattern enum does not match its name",
					fmt.Sprintf("The API derives a pattern's enum from its name, so %q must "+
						"have the enum %q, not %q.\n\nEither correct the enum — and every "+
						"criterion that references the old one — or omit it and let the API "+
						"derive it.", name, want, enum),
				)
			}
		}
	}

	return diags
}

func hasField(g controlspec.Global, name string) bool {
	for _, f := range g.Attributes {
		if f.Name == name {
			return true
		}
	}
	return false
}
