package provider

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/provider/controlspec"
	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/pushapi"
)

// planRule is one rule as it appears in configuration: the API payload plus the
// practitioner's key, which is provider-side only and never sent.
//
// Emails records the addresses the employee criterion held before they were
// resolved to identifiers. State keeps the addresses, not the identifiers, so
// the write path has to remember which was which — see emailsByID.
type planRule struct {
	Key    string
	Emails []string
	Rule   pushapi.Rule
}

// rulesFromPlan resolves employee email addresses to identifiers, because the
// payload is not valid until it carries them. Rule identifiers are not
// resolved here; carryIDs does that against prior state.
func rulesFromPlan(ctx context.Context, s controlspec.Spec, res *employeeResolver, list types.List) ([]planRule, diag.Diagnostics) {
	var diags diag.Diagnostics
	if list.IsNull() || list.IsUnknown() {
		return nil, diags
	}

	elems := list.Elements()
	out := make([]planRule, 0, len(elems))

	for i, e := range elems {
		obj, ok := e.(types.Object)
		if !ok {
			diags.AddAttributeError(path.Root("rules").AtListIndex(i),
				"Unexpected rule value", "Expected an object; this is a bug in the provider.")
			continue
		}
		attrs := obj.Attributes()

		pr := planRule{
			Key: stringOrEmpty(attrs["key"]),
			Rule: pushapi.Rule{
				Name:    stringOrEmpty(attrs["name"]),
				Enabled: boolOrFalse(attrs["enabled"]),
				Mode:    stringOrEmpty(attrs["mode"]),
				Fields:  map[string]any{},
			},
		}

		for _, f := range s.Fields {
			v, d := fieldToAPI(ctx, f, attrs[f.Name])
			diags.Append(d...)
			// A null attribute is left out of the payload entirely. Several
			// controls require a field to be absent outside particular modes,
			// so absent and null are not interchangeable.
			if v != nil {
				pr.Rule.Fields[f.APIName] = v
			}
		}

		if len(s.Criteria) > 0 {
			crit, emails, d := criteriaToAPI(ctx, s, res, attrs["criteria"], i)
			diags.Append(d...)
			pr.Rule.Criteria = crit
			pr.Emails = emails
		}

		out = append(out, pr)
	}

	return out, diags
}

func fieldToAPI(ctx context.Context, f controlspec.Field, v attr.Value) (any, diag.Diagnostics) {
	var diags diag.Diagnostics
	if v == nil || v.IsNull() || v.IsUnknown() {
		return nil, diags
	}

	switch f.Type {
	case controlspec.TypeBool:
		b, ok := v.(types.Bool)
		if !ok {
			return nil, diags
		}
		return b.ValueBool(), diags

	case controlspec.TypeEnumSet:
		set, ok := v.(types.Set)
		if !ok {
			return nil, diags
		}
		var vals []string
		diags.Append(set.ElementsAs(ctx, &vals, false)...)
		return vals, diags

	default:
		sv, ok := v.(types.String)
		if !ok {
			return nil, diags
		}
		return sv.ValueString(), diags
	}
}

// criteriaToAPI returns, alongside the conditions, the employee email
// addresses it resolved, in the order the resolved identifiers were written.
func criteriaToAPI(ctx context.Context, s controlspec.Spec, res *employeeResolver, v attr.Value, ruleIndex int) (map[string]pushapi.Condition, []string, diag.Diagnostics) {
	var diags diag.Diagnostics
	// An absent criteria block means no restriction. The client sends an empty
	// object, which the API accepts everywhere.
	out := map[string]pushapi.Condition{}
	var emails []string

	obj, ok := v.(types.Object)
	if !ok || obj.IsNull() || obj.IsUnknown() {
		return out, emails, diags
	}
	attrs := obj.Attributes()

	for _, c := range s.Criteria {
		cv := attrs[c.Name]
		if cv == nil || cv.IsNull() || cv.IsUnknown() {
			continue
		}

		if c.Single {
			sv, ok := cv.(types.String)
			if !ok {
				continue
			}
			// One-element array on the wire, plain string in configuration.
			out[c.APIName] = pushapi.Condition{Matches: []string{sv.ValueString()}}
			continue
		}

		cobj, ok := cv.(types.Object)
		if !ok {
			continue
		}
		cattrs := cobj.Attributes()

		matchesPath := path.Root("rules").AtListIndex(ruleIndex).
			AtName("criteria").AtName(c.Name).AtName("matches")

		matches := stringCollection(cattrs["matches"])
		if len(matches) == 0 {
			diags.AddAttributeError(
				matchesPath,
				"Empty matches list",
				"A condition needs at least one value to match. Remove the condition instead.",
			)
			continue
		}

		if c.ResolvesEmails() {
			resolved, d := resolveEmails(ctx, res, matches, matchesPath)
			diags.Append(d...)
			if d.HasError() {
				continue
			}
			// Keep the addresses as written: they, not the identifiers, are
			// what goes back into state.
			emails = append(emails, matches...)
			matches = resolved
		}

		cond := pushapi.Condition{Matches: matches}
		if c.Excludable {
			// Only sent where the API permits it; include-only conditions
			// reject the field, and the schema does not offer it there.
			cond.Action = stringOrEmpty(cattrs["action"])
		}
		out[c.APIName] = cond
	}

	return out, emails, diags
}

// resolveEmails attaches a failure to the attribute rather than returning it
// bare, so a typo names the rule and the address that caused it. It runs
// during plan for a change and at apply for the write itself; either way it
// fails before the API is asked to store anything.
func resolveEmails(ctx context.Context, res *employeeResolver, emails []string, at path.Path) ([]string, diag.Diagnostics) {
	var diags diag.Diagnostics

	if res == nil {
		diags.AddAttributeError(at, "Provider not configured",
			"The Push API client is unavailable, so employee email addresses cannot be "+
				"resolved. This is a bug in the provider.")
		return nil, diags
	}

	out := make([]string, 0, len(emails))
	for _, email := range emails {
		id, err := res.IDForEmail(ctx, email)
		if err != nil {
			var (
				missing   errNoSuchEmployee
				ambiguous errAmbiguousEmployee
			)
			switch {
			case errors.As(err, &missing):
				diags.AddAttributeError(at, "No such employee",
					fmt.Sprintf("No employee has the email address %q. Check the address, or "+
						"use the pushsecurity_employees data source to list what the tenant holds.\n\n"+
						"An employee who has left the organisation is removed from the tenant, "+
						"so a rule naming them has to be updated or dropped.", email))
			case errors.As(err, &ambiguous):
				diags.AddAttributeError(at, "Ambiguous employee lookup",
					fmt.Sprintf("%d employees have the email address %q, so it cannot identify "+
						"one person.", ambiguous.Count, email))
			default:
				diags.AddAttributeError(at, "Could not look up employee",
					fmt.Sprintf("Resolving %q failed: %v", email, err))
			}
			continue
		}
		out = append(out, id)
	}

	return out, diags
}

// emailsFromIDs turns the identifiers the API stores back into the email
// addresses configuration is written in, so that a refresh of an unchanged
// rule produces an unchanged set and plans empty.
//
// An identifier the tenant no longer holds — an offboarded employee still
// named by a rule — cannot be turned back into an address. Failing the refresh
// would leave no way to see or repair the rule, and dropping the value would
// widen, without a warning, a control that was meant to exclude someone. So
// the address the rule was last written with is kept and a warning is raised.
// After an import there is no such address to keep, and the warning says so.
func emailsFromIDs(ctx context.Context, res *employeeResolver, ids, priorEmails []string, controlName, ruleName string) ([]string, diag.Diagnostics) {
	var diags diag.Diagnostics
	if len(ids) == 0 {
		return nil, diags
	}

	if res == nil {
		// Nothing can be resolved without a client. Prior state is the best
		// available answer; identifiers would not even validate.
		return priorEmails, diags
	}

	resolved := make([]string, 0, len(ids))
	var unresolved []string
	for _, id := range ids {
		email, ok, err := res.EmailForID(ctx, id)
		if err != nil {
			diags.AddWarning("Could not read the employee list",
				fmt.Sprintf("The %s rule %q matches employees by identifier, which the "+
					"provider translates back into email addresses. Listing the tenant's "+
					"employees failed: %v\n\nState keeps the addresses it already held, so "+
					"this refresh may be stale.", controlName, ruleName, err))
			return priorEmails, diags
		}
		if !ok {
			unresolved = append(unresolved, id)
			continue
		}
		resolved = append(resolved, email)
	}

	if len(unresolved) == 0 {
		return resolved, diags
	}

	// Which configured addresses have stopped resolving? Those are the
	// offboarded people, and they account for the identifiers that came back
	// unresolvable. Recovering them this way keeps a console-side addition to
	// the same rule visible instead of masking it with prior state wholesale.
	var gone []string
	for _, email := range priorEmails {
		if _, err := res.IDForEmail(ctx, email); err != nil {
			var missing errNoSuchEmployee
			if errors.As(err, &missing) {
				gone = append(gone, email)
			}
		}
	}

	detail := fmt.Sprintf("The %s rule %q matches %d employee identifier(s) that the tenant "+
		"no longer holds: %s.\n\nThis is what an offboarded employee still named by a rule "+
		"looks like. ", controlName, ruleName, len(unresolved), strings.Join(unresolved, ", "))

	switch {
	case len(gone) == len(unresolved):
		detail += fmt.Sprintf("State keeps the address(es) the rule was written with (%s) so "+
			"that the plan stays empty and the rule is not widened. Remove them "+
			"from the configuration when the rule should no longer name them.",
			strings.Join(gone, ", "))
	case len(gone) > 0:
		detail += fmt.Sprintf("Only %d of them can be matched to an address in the "+
			"configuration (%s); the rest are kept out of state, so the next apply would "+
			"drop them. Review the rule.", len(gone), strings.Join(gone, ", "))
	default:
		detail += "None of them can be matched to an address in the configuration, which is " +
			"normal directly after an import. They are left out of state, so the next apply " +
			"would drop them from the rule. Review the rule before applying."
	}

	diags.AddWarning("Rule names an employee the tenant no longer holds", detail)
	return append(resolved, gone...), diags
}

// rulesToState builds the state value for the rules the API returned.
//
// keyByID maps a server identifier back to the practitioner's key so that keys
// survive a refresh. Identifiers absent from the map produce a null key, which
// is what happens after an import.
//
// emailsByID does the same for the employee criterion: it holds the addresses
// the rule was last written with, so that an identifier the tenant no longer
// resolves does not drop out of state. Absent, as after an import, the
// addresses are recovered by enumerating the tenant.
func rulesToState(ctx context.Context, s controlspec.Spec, res *employeeResolver, rules []pushapi.Rule, keyByID map[string]string, emailsByID map[string][]string) (types.List, diag.Diagnostics) {
	var diags diag.Diagnostics
	objType := ruleObjectType(s)

	elems := make([]attr.Value, 0, len(rules))
	for _, r := range rules {
		vals := map[string]attr.Value{
			"id":      types.StringValue(r.ID),
			"name":    types.StringValue(r.Name),
			"enabled": types.BoolValue(r.Enabled),
			"mode":    types.StringValue(r.Mode),
			"key":     types.StringNull(),
		}
		if k, ok := keyByID[r.ID]; ok && k != "" {
			vals["key"] = types.StringValue(k)
		}

		for _, f := range s.Fields {
			v, d := fieldFromAPI(f, r.Fields[f.APIName])
			diags.Append(d...)
			vals[f.Name] = v
		}

		if len(s.Criteria) > 0 {
			c, d := criteriaFromAPI(ctx, s, res, r.Criteria, emailsByID[r.ID], r.Name)
			diags.Append(d...)
			vals["criteria"] = c
		}

		obj, d := types.ObjectValue(objType.AttrTypes, vals)
		diags.Append(d...)
		elems = append(elems, obj)
	}

	list, d := types.ListValue(objType, elems)
	diags.Append(d...)
	return list, diags
}

func fieldFromAPI(f controlspec.Field, raw any) (attr.Value, diag.Diagnostics) {
	var diags diag.Diagnostics

	switch f.Type {
	case controlspec.TypeBool:
		b, ok := raw.(bool)
		if !ok {
			return types.BoolNull(), diags
		}
		return types.BoolValue(b), diags

	case controlspec.TypeEnumSet:
		items, ok := raw.([]any)
		if !ok {
			return types.SetNull(types.StringType), diags
		}
		vals := make([]attr.Value, 0, len(items))
		for _, it := range items {
			if sv, ok := it.(string); ok {
				vals = append(vals, types.StringValue(sv))
			}
		}
		set, d := types.SetValue(types.StringType, vals)
		diags.Append(d...)
		return set, diags

	default:
		sv, ok := raw.(string)
		if !ok {
			// Absent on the wire becomes null in state, never "", so that
			// state says what the API returned: most controls store an empty
			// string as sent, and read it back as one.
			return types.StringNull(), diags
		}
		return types.StringValue(sv), diags
	}
}

// criteriaFromAPI takes the addresses the employee criterion was last written
// with, and the rule's name for any warning it raises.
func criteriaFromAPI(ctx context.Context, s controlspec.Spec, res *employeeResolver, crit map[string]pushapi.Condition, priorEmails []string, ruleName string) (attr.Value, diag.Diagnostics) {
	var diags diag.Diagnostics
	t := criteriaObjectType(s)
	vals := make(map[string]attr.Value, len(t.AttrTypes))

	for _, c := range s.Criteria {
		cond, present := crit[c.APIName]

		if c.Single {
			if !present || len(cond.Matches) == 0 {
				// Absent means the criterion's documented default, not "unset".
				// profileScope is specified as "If omitted, defaults to ALL",
				// and most controls inject it on write so it is never absent
				// anyway — but maliciousBrowserExtensionDetection leaves it off
				// rules created in the console. Reading that back as null would
				// contradict the schema default and make an adopted rule either
				// replan forever or fail the apply that settles it.
				if c.ServerDefault != "" {
					vals[c.Name] = types.StringValue(c.ServerDefault)
					continue
				}
				vals[c.Name] = types.StringNull()
				continue
			}
			vals[c.Name] = types.StringValue(cond.Matches[0])
			if len(cond.Matches) > 1 {
				// Configuration holds this criterion as one value, so state
				// can hold no more. Keeping the first is the least surprising
				// choice, but it narrows what is written back, so say so.
				diags.AddWarning("Criterion holds more than one value",
					fmt.Sprintf("The %s rule %q matches `criteria.%s` on %d values (%s), but "+
						"the provider holds this criterion as a single value. State keeps the "+
						"first, %q, and the next apply that writes the rule sends only that one.",
						s.TypeName, ruleName, c.Name, len(cond.Matches),
						strings.Join(cond.Matches, ", "), cond.Matches[0]))
			}
			continue
		}

		innerType := t.AttrTypes[c.Name].(types.ObjectType).AttrTypes
		if !present {
			vals[c.Name] = types.ObjectNull(innerType)
			continue
		}

		raw := cond.Matches
		if c.ResolvesEmails() {
			resolved, d := emailsFromIDs(ctx, res, raw, priorEmails, s.TypeName, ruleName)
			diags.Append(d...)
			raw = resolved
		}

		matches := make([]attr.Value, 0, len(raw))
		for _, m := range raw {
			matches = append(matches, types.StringValue(m))
		}
		set, d := types.SetValue(types.StringType, matches)
		diags.Append(d...)

		inner := map[string]attr.Value{"matches": set}
		if c.Excludable {
			action := cond.Action
			if action == "" {
				// The server echoes INCLUDE when it was omitted, but be
				// defensive: the schema default is INCLUDE either way.
				action = actionInclude
			}
			inner["action"] = types.StringValue(action)
		}

		obj, d := types.ObjectValue(innerType, inner)
		diags.Append(d...)
		vals[c.Name] = obj
	}

	obj, d := types.ObjectValue(t.AttrTypes, vals)
	diags.Append(d...)
	return obj, diags
}

func globalsFromPlan(ctx context.Context, s controlspec.Spec, v attr.Value) (map[string]any, diag.Diagnostics) {
	var diags diag.Diagnostics
	out := map[string]any{}

	obj, ok := v.(types.Object)
	if !ok || obj.IsNull() || obj.IsUnknown() {
		return out, diags
	}
	attrs := obj.Attributes()

	for _, g := range s.Globals {
		gv := attrs[g.Name]
		if gv == nil || gv.IsNull() || gv.IsUnknown() {
			continue
		}

		switch g.Type {
		case controlspec.GlobalObjectList:
			list, ok := gv.(types.List)
			if !ok {
				continue
			}
			items := make([]map[string]any, 0, len(list.Elements()))
			for _, e := range list.Elements() {
				eobj, ok := e.(types.Object)
				if !ok {
					continue
				}
				item := map[string]any{}
				for _, f := range g.Attributes {
					fv, d := fieldToAPI(ctx, f, eobj.Attributes()[f.Name])
					diags.Append(d...)
					if fv != nil {
						item[f.APIName] = fv
					}
				}
				items = append(items, item)
			}
			out[g.APIName] = items

		default:
			vals := stringCollection(gv)
			if vals == nil {
				vals = []string{}
			}
			out[g.APIName] = vals
		}
	}

	return out, diags
}

func globalsToState(s controlspec.Spec, globals map[string]any) (attr.Value, diag.Diagnostics) {
	var diags diag.Diagnostics
	t := globalsObjectType(s)
	vals := make(map[string]attr.Value, len(t.AttrTypes))

	for _, g := range s.Globals {
		raw, present := globals[g.APIName]

		switch g.Type {
		case controlspec.GlobalObjectList:
			listType := t.AttrTypes[g.Name].(types.ListType)
			objType := listType.ElemType.(types.ObjectType)
			items, ok := raw.([]any)
			if !present || !ok {
				vals[g.Name] = types.ListValueMust(objType, []attr.Value{})
				continue
			}
			elems := make([]attr.Value, 0, len(items))
			for _, it := range items {
				m, ok := it.(map[string]any)
				if !ok {
					continue
				}
				inner := make(map[string]attr.Value, len(g.Attributes))
				for _, f := range g.Attributes {
					fv, d := fieldFromAPI(f, m[f.APIName])
					diags.Append(d...)
					inner[f.Name] = fv
				}
				obj, d := types.ObjectValue(objType.AttrTypes, inner)
				diags.Append(d...)
				elems = append(elems, obj)
			}
			list, d := types.ListValue(objType, elems)
			diags.Append(d...)
			vals[g.Name] = list

		default:
			items, ok := raw.([]any)
			if !present || !ok {
				vals[g.Name] = emptyStringSet()
				continue
			}
			elems := make([]attr.Value, 0, len(items))
			for _, it := range items {
				if sv, ok := it.(string); ok {
					elems = append(elems, types.StringValue(sv))
				}
			}
			set, d := types.SetValue(types.StringType, elems)
			diags.Append(d...)
			vals[g.Name] = set
		}
	}

	obj, d := types.ObjectValue(t.AttrTypes, vals)
	diags.Append(d...)
	return obj, diags
}

func stringOrEmpty(v attr.Value) string {
	sv, ok := v.(types.String)
	if !ok || sv.IsNull() || sv.IsUnknown() {
		return ""
	}
	return sv.ValueString()
}

func boolOrFalse(v attr.Value) bool {
	bv, ok := v.(types.Bool)
	if !ok || bv.IsNull() || bv.IsUnknown() {
		return false
	}
	return bv.ValueBool()
}

// stringCollection reads a set or list of strings. Match values and the
// string-valued globals are sets — the server does not preserve their order —
// but the helper accepts either so it can be reused if that changes.
func stringCollection(v attr.Value) []string {
	var elems []attr.Value
	switch c := v.(type) {
	case types.Set:
		if c.IsNull() || c.IsUnknown() {
			return nil
		}
		elems = c.Elements()
	case types.List:
		if c.IsNull() || c.IsUnknown() {
			return nil
		}
		elems = c.Elements()
	default:
		return nil
	}

	out := make([]string, 0, len(elems))
	for _, e := range elems {
		sv, ok := e.(types.String)
		if !ok || sv.IsNull() || sv.IsUnknown() {
			continue
		}
		out = append(out, sv.ValueString())
	}
	return out
}
