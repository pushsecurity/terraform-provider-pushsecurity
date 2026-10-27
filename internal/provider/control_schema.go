package provider

import (
	"fmt"
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/objectdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/provider/controlspec"
)

// The actions an excludable condition takes. actionInclude is the server's
// default.
const (
	actionInclude = "INCLUDE"
	actionExclude = "EXCLUDE"
)

func buildSchema(s controlspec.Spec) schema.Schema {
	attrs := map[string]schema.Attribute{
		"rules": schema.ListNestedAttribute{
			Required: true,
			MarkdownDescription: "The control's rules, in evaluation order: the first rule that " +
				"matches wins, so the order of this list is part of your configuration.\n\n" +
				"This list is the **complete** set of rules for the control. An apply deletes " +
				"any rule that is not here, including rules created in the console.\n\n" +
				fmt.Sprintf("At most %d rules.", controlspec.MaxRules),
			Validators: []validator.List{
				listvalidator.SizeAtMost(controlspec.MaxRules),
			},
			NestedObject: schema.NestedAttributeObject{
				Attributes: buildRuleAttributes(s),
			},
		},
	}

	if len(s.Globals) > 0 {
		attrs["globals"] = schema.SingleNestedAttribute{
			Optional: true,
			Computed: true,
			// As with criteria: the server returns globals it was not sent
			// (ignoredHosts comes back as an empty list), so an omitted block
			// must plan to that rather than to null.
			Default:             objectdefault.StaticValue(defaultGlobals(s)),
			MarkdownDescription: "Control-wide settings that apply across every rule.",
			Attributes:          buildGlobalAttributes(s),
		}
	}

	return schema.Schema{
		MarkdownDescription: s.Description + "\n\n" +
			"~> This resource owns the whole `" + s.APIName + "` configuration. The API " +
			"replaces the entire document on every write, so this control is either managed " +
			"by Terraform or managed in the console — not both. Import the existing " +
			"configuration before your first apply.\n\n" +
			"Destroying this resource does not remove the control, which cannot be removed. " +
			"It writes an empty configuration: no rules, and default control-wide settings.",
		Attributes: attrs,
	}
}

func buildRuleAttributes(s controlspec.Spec) map[string]schema.Attribute {
	attrs := map[string]schema.Attribute{
		"key": schema.StringAttribute{
			Optional: true,
			MarkdownDescription: "A stable identifier for this rule, chosen by you and unique " +
				"within the control. It is never sent to the API; the provider uses it to " +
				"remember which server-side rule this configuration block corresponds to.\n\n" +
				"~> Set this on every rule. Rule names are not unique — the console generates " +
				"names from a template, so duplicates are common — and without `key` the " +
				"provider has to match rules by position. Reordering positionally matched " +
				"rules keeps the server-side rule identifiers but moves them onto different " +
				"rules. Nothing in Push refers to a rule identifier, so the tenant behaves " +
				"the same either way; set a key if your own tooling reads the identifiers " +
				"the API returns.",
			Validators: []validator.String{
				stringvalidator.LengthAtLeast(1),
			},
		},
		"id": schema.StringAttribute{
			Computed:            true,
			MarkdownDescription: "The rule's server-assigned identifier.",
			// Deliberately no UseStateForUnknown. That plan modifier copies the
			// prior state value at the same *list index*, but a rule's
			// identifier belongs to the rule, not to its position. Inserting a
			// rule would make the plan promise index 0 the identifier of what
			// is now index 1, and the apply — which resolves identifiers by
			// key — would return something else, failing with "Provider
			// produced inconsistent result after apply".
			//
			// The cost is that identifiers show as "(known after apply)"
			// whenever the rules list changes. That is honest: which rule holds
			// which identifier genuinely is not known until the key mapping is
			// applied.
		},
		"name": schema.StringAttribute{
			Required: true,
			MarkdownDescription: "A short name to help you recognise the rule. Not required to " +
				fmt.Sprintf("be unique. At most %d characters.", controlspec.MaxRuleNameLength),
			Validators: []validator.String{
				stringvalidator.LengthAtMost(controlspec.MaxRuleNameLength),
			},
		},
		"enabled": schema.BoolAttribute{
			Required:            true,
			MarkdownDescription: "Whether the rule is active.",
		},
		"mode": schema.StringAttribute{
			Required: true,
			MarkdownDescription: "What happens when the rule matches. One of " +
				controlspec.Backticked(s.Modes) + ".",
			Validators: []validator.String{
				stringvalidator.OneOf(s.Modes...),
			},
		},
	}

	for _, f := range s.Fields {
		attrs[f.Name] = buildRuleFieldAttribute(f)
	}

	if len(s.Criteria) > 0 {
		crit := schema.SingleNestedAttribute{
			MarkdownDescription: "Restricts the rule to apply only under these conditions.",
			Attributes:          buildCriteriaAttributes(s),
		}
		if s.CriteriaRequired {
			crit.Required = true
		} else {
			crit.MarkdownDescription += " A rule with no criteria applies to everyone."
			// Optional and computed, with an explicit default. The server
			// returns criteria it was never sent — profileScope comes back as
			// ["ALL"] on a rule written without it, even one sent with
			// criteria {} — so an omitted block must plan to what the server
			// will return rather than to null. Planning null and reading back
			// a value fails the apply.
			//
			// This only works because the value is predictable. Where the API
			// omits a criterion it documents a default for, criteriaFromAPI
			// normalises it back to that default on read, so state and this
			// default agree either way.
			crit.Optional = true
			crit.Computed = true
			crit.Default = objectdefault.StaticValue(defaultCriteria(s))
		}
		attrs["criteria"] = crit
	}

	return attrs
}

// buildRuleFieldAttribute adds what applies to a rule's text and not to the
// control-wide settings: the API escapes or rejects some rule text on write.
func buildRuleFieldAttribute(f controlspec.Field) schema.Attribute {
	a := buildFieldAttribute(f)
	sa, ok := a.(schema.StringAttribute)
	if !ok || !f.IsText() {
		return a
	}
	sa.Validators = append(sa.Validators, ruleTextValidator{f})
	if f.Type == controlspec.TypeString && f.StoredEscaped() {
		sa.MarkdownDescription += " Must not contain `&`, `<` or `>`, which the API stores " +
			"HTML-escaped."
	}
	return sa
}

func buildFieldAttribute(f controlspec.Field) schema.Attribute {
	desc := f.Description

	switch f.Type {
	case controlspec.TypeBool:
		a := schema.BoolAttribute{
			Required:            f.Required,
			Optional:            !f.Required,
			MarkdownDescription: desc,
		}
		if b, ok := f.ServerDefault.(bool); ok {
			a.Computed = true
			a.Default = booldefault.StaticBool(b)
			a.MarkdownDescription += fmt.Sprintf(" Defaults to `%t`.", b)
		}
		return a

	case controlspec.TypeEnum:
		a := schema.StringAttribute{
			Required:            f.Required,
			Optional:            !f.Required,
			MarkdownDescription: desc + " One of " + controlspec.Backticked(f.Enum) + ".",
			Validators: []validator.String{
				stringvalidator.OneOf(f.Enum...),
			},
		}
		if sv, ok := f.ServerDefault.(string); ok {
			// The server substitutes this when the field is absent, so an
			// omitted field must plan to it rather than to null.
			a.Computed = true
			a.Default = stringdefault.StaticString(sv)
			a.MarkdownDescription += " Defaults to `" + sv + "`."
		}
		return a

	case controlspec.TypeEnumSet:
		return schema.SetAttribute{
			ElementType:         types.StringType,
			Required:            f.Required,
			Optional:            !f.Required,
			MarkdownDescription: desc + " Any of " + controlspec.Backticked(f.Enum) + ".",
			Validators: []validator.Set{
				setvalidator.ValueStringsAre(stringvalidator.OneOf(f.Enum...)),
				setvalidator.SizeAtLeast(1),
			},
		}

	default: // controlspec.TypeString
		var vs []validator.String
		switch {
		case f.MinLength > 0 && f.MaxLength > 0:
			vs = append(vs, stringvalidator.LengthBetween(f.MinLength, f.MaxLength))
			desc += fmt.Sprintf(" Between %d and %d characters.", f.MinLength, f.MaxLength)
		case f.MaxLength > 0:
			vs = append(vs, stringvalidator.LengthAtMost(f.MaxLength))
			desc += fmt.Sprintf(" At most %d characters.", f.MaxLength)
		case f.MinLength > 0:
			vs = append(vs, stringvalidator.LengthAtLeast(f.MinLength))
			desc += fmt.Sprintf(" At least %d characters.", f.MinLength)
		}
		if f.NoWhitespace {
			vs = append(vs, noWhitespaceValidator{})
			desc += " Must not contain whitespace."
		}
		return schema.StringAttribute{
			Required:            f.Required,
			Optional:            !f.Required,
			Computed:            f.Computed,
			MarkdownDescription: desc,
			Validators:          vs,
		}
	}
}

func buildCriteriaAttributes(s controlspec.Spec) map[string]schema.Attribute {
	attrs := make(map[string]schema.Attribute, len(s.Criteria))

	for _, c := range s.Criteria {
		// A single-valued criterion is a one-element array on the wire,
		// flattened to a plain string here.
		if c.Single {
			a := schema.StringAttribute{
				Required:            c.Required,
				Optional:            !c.Required,
				MarkdownDescription: c.Description,
			}
			if len(c.Enum) > 0 {
				a.MarkdownDescription += " One of " + controlspec.Backticked(c.Enum) + "."
				a.Validators = []validator.String{stringvalidator.OneOf(c.Enum...)}
			}
			if c.ServerDefault != "" {
				// The server returns this criterion on a rule written without
				// it, and criteriaFromAPI reads an omitted one as this default,
				// so state always holds a value even when configuration omits
				// it.
				a.Computed = true
				a.Default = stringdefault.StaticString(c.ServerDefault)
				a.MarkdownDescription += " Defaults to `" + c.ServerDefault + "`."
			}
			attrs[c.Name] = a
			continue
		}

		// A set, not a list. Match order carries no meaning, and the server
		// does not always preserve it: appCategories comes back sorted
		// numerically, so a list would show a diff on every plan.
		matchesDesc := fmt.Sprintf("Between 1 and %d values to match.", c.MatchesLimit())
		if c.MatchesLimit() == 1 {
			matchesDesc = "Exactly one value to match."
		}
		matchesValidators := []validator.Set{
			// The API requires at least one value, and caps the count; either
			// way it is a 400.
			setvalidator.SizeBetween(1, c.MatchesLimit()),
		}
		if c.ResolvesEmails() {
			// An empty employee list is what configuration generated from a
			// rule naming only departed employees holds, and the obvious fix,
			// removing the criterion, widens the rule to everyone. Say so
			// where the plan fails, which may be well after the warning.
			matchesValidators = []validator.Set{
				setvalidator.SizeAtMost(c.MatchesLimit()),
				employeeMatchesNotEmptyValidator{},
			}
		}
		if len(c.Enum) > 0 {
			matchesDesc += " Any of " + controlspec.Backticked(c.Enum) + "."
			matchesValidators = append(matchesValidators,
				setvalidator.ValueStringsAre(stringvalidator.OneOf(c.Enum...)))
		}
		if c.Values != controlspec.PlainValues {
			matchesValidators = append(matchesValidators,
				setvalidator.ValueStringsAre(criterionValueValidator{c}))
		}
		if c.ResolvesEmails() {
			matchesDesc = fmt.Sprintf("Between 1 and %d employee email addresses. ",
				c.MatchesLimit()) + "Each is resolved to an " +
				"employee identifier during plan, so an address the tenant does not hold " +
				"fails before anything is written."
			// A UUID here is the mistake worth catching by shape: it is the
			// identifier the API itself carries, and resolving it as an
			// address would fail with a confusing "no such employee" instead
			// of saying what is wrong.
			matchesValidators = append(matchesValidators,
				setvalidator.ValueStringsAre(stringvalidator.RegexMatches(
					regexp.MustCompile(`^[^@\s]+@[^@\s]+$`),
					"must be an employee email address, not an employee identifier",
				)))
		}
		inner := map[string]schema.Attribute{
			"matches": schema.SetAttribute{
				ElementType:         types.StringType,
				Required:            true,
				MarkdownDescription: matchesDesc,
				Validators:          matchesValidators,
			},
		}

		if c.Excludable {
			inner["action"] = schema.StringAttribute{
				Optional: true,
				Computed: true,
				Default:  stringdefault.StaticString(actionInclude),
				MarkdownDescription: "Whether to apply the rule to the matched values " +
					"(`INCLUDE`) or to everything except them (`EXCLUDE`). Defaults to " +
					"`INCLUDE`.",
				Validators: []validator.String{
					stringvalidator.OneOf(actionInclude, actionExclude),
				},
			}
		}

		attrs[c.Name] = schema.SingleNestedAttribute{
			Required:            c.Required,
			Optional:            !c.Required,
			MarkdownDescription: c.Description,
			Attributes:          inner,
		}
	}

	return attrs
}

func buildGlobalAttributes(s controlspec.Spec) map[string]schema.Attribute {
	attrs := make(map[string]schema.Attribute, len(s.Globals))

	for _, g := range s.Globals {
		switch g.Type {
		case controlspec.GlobalObjectList:
			inner := make(map[string]schema.Attribute, len(g.Attributes))
			for _, f := range g.Attributes {
				inner[f.Name] = buildFieldAttribute(f)
			}
			a := schema.ListNestedAttribute{
				Optional:            true,
				Computed:            true,
				Default:             listdefault.StaticValue(emptyObjectList(g)),
				MarkdownDescription: g.Description,
				NestedObject:        schema.NestedAttributeObject{Attributes: inner},
			}
			if g.MaxItems > 0 {
				a.Validators = []validator.List{listvalidator.SizeAtMost(g.MaxItems)}
				a.MarkdownDescription += fmt.Sprintf(" At most %d entries.", g.MaxItems)
			}
			attrs[g.Name] = a

		default: // controlspec.GlobalStringList
			// A set: the server sorts ignoredHosts, so a list would diff on
			// every plan.
			a := schema.SetAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Computed:    true,
				// The server returns an empty collection rather than omitting
				// the key.
				Default:             setdefault.StaticValue(emptyStringSet()),
				MarkdownDescription: g.Description,
			}
			if g.MaxItems > 0 {
				a.Validators = []validator.Set{setvalidator.SizeAtMost(g.MaxItems)}
				a.MarkdownDescription += fmt.Sprintf(" At most %d entries.", g.MaxItems)
			}
			attrs[g.Name] = a
		}
	}

	return attrs
}

// ruleObjectType is needed to build rule values when reading from the API.
func ruleObjectType(s controlspec.Spec) types.ObjectType {
	attrTypes := map[string]attr.Type{
		"key":     types.StringType,
		"id":      types.StringType,
		"name":    types.StringType,
		"enabled": types.BoolType,
		"mode":    types.StringType,
	}

	for _, f := range s.Fields {
		switch f.Type {
		case controlspec.TypeBool:
			attrTypes[f.Name] = types.BoolType
		case controlspec.TypeEnumSet:
			attrTypes[f.Name] = types.SetType{ElemType: types.StringType}
		default:
			attrTypes[f.Name] = types.StringType
		}
	}

	if len(s.Criteria) > 0 {
		attrTypes["criteria"] = criteriaObjectType(s)
	}

	return types.ObjectType{AttrTypes: attrTypes}
}

func criteriaObjectType(s controlspec.Spec) types.ObjectType {
	attrTypes := make(map[string]attr.Type, len(s.Criteria))
	for _, c := range s.Criteria {
		if c.Single {
			attrTypes[c.Name] = types.StringType
			continue
		}
		inner := map[string]attr.Type{"matches": types.SetType{ElemType: types.StringType}}
		if c.Excludable {
			inner["action"] = types.StringType
		}
		attrTypes[c.Name] = types.ObjectType{AttrTypes: inner}
	}
	return types.ObjectType{AttrTypes: attrTypes}
}

func globalsObjectType(s controlspec.Spec) types.ObjectType {
	attrTypes := make(map[string]attr.Type, len(s.Globals))
	for _, g := range s.Globals {
		switch g.Type {
		case controlspec.GlobalObjectList:
			attrTypes[g.Name] = types.ListType{ElemType: globalObjectType(g)}
		default:
			attrTypes[g.Name] = types.SetType{ElemType: types.StringType}
		}
	}
	return types.ObjectType{AttrTypes: attrTypes}
}

// defaultCriteria builds the criteria object the server produces for a rule
// whose criteria were omitted: every criterion null except those the server
// injects a value for.
func defaultCriteria(s controlspec.Spec) types.Object {
	t := criteriaObjectType(s)
	vals := make(map[string]attr.Value, len(t.AttrTypes))
	for _, c := range s.Criteria {
		switch {
		case c.Single && c.ServerDefault != "":
			vals[c.Name] = types.StringValue(c.ServerDefault)
		case c.Single:
			// Flattened to a plain string, so its null is a string null. The
			// Single check has to come before the object cast below, not after:
			// a single-valued criterion with no ServerDefault has a string type
			// in the schema and cannot be asserted to an ObjectType at all.
			vals[c.Name] = types.StringNull()
		default:
			vals[c.Name] = types.ObjectNull(t.AttrTypes[c.Name].(types.ObjectType).AttrTypes)
		}
	}
	return types.ObjectValueMust(t.AttrTypes, vals)
}

// defaultGlobals builds the globals object the server produces when globals
// were omitted: an empty list for each setting.
func defaultGlobals(s controlspec.Spec) types.Object {
	t := globalsObjectType(s)
	vals := make(map[string]attr.Value, len(t.AttrTypes))
	for _, g := range s.Globals {
		switch g.Type {
		case controlspec.GlobalObjectList:
			vals[g.Name] = emptyObjectList(g)
		default:
			vals[g.Name] = emptyStringSet()
		}
	}
	return types.ObjectValueMust(t.AttrTypes, vals)
}

func emptyStringSet() types.Set {
	return types.SetValueMust(types.StringType, []attr.Value{})
}

func emptyObjectList(g controlspec.Global) types.List {
	return types.ListValueMust(globalObjectType(g), []attr.Value{})
}

// globalObjectType is the type of one entry of a GlobalObjectList setting.
func globalObjectType(g controlspec.Global) types.ObjectType {
	inner := make(map[string]attr.Type, len(g.Attributes))
	for _, f := range g.Attributes {
		switch f.Type {
		case controlspec.TypeBool:
			inner[f.Name] = types.BoolType
		default:
			inner[f.Name] = types.StringType
		}
	}
	return types.ObjectType{AttrTypes: inner}
}
