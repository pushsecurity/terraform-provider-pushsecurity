package controlspec

import (
	"fmt"
	"slices"
	"strings"
)

// RuleValues is the minimum a constraint needs to know about a rule.
//
// It exists so that the cross-field rules have exactly one implementation.
// They are evaluated during `terraform plan` against Terraform values, and by
// CheckStored against what the API returns, and those two answers must agree:
// the point of checking stored configuration is to predict what the plan will
// say.
type RuleValues interface {
	Mode() string
	// IsSet reports whether a field has a usable value. An empty string is not
	// a value. That is the provider's rule rather than the API's, which stores
	// an empty string on most controls: an empty heading or button label is
	// never what was meant, so a field a mode requires must hold text.
	IsSet(field string) bool
	IsTrue(field string) bool
	// IsFalse reports whether a boolean field is known to be false. Absent or
	// not yet known is neither true nor false.
	IsFalse(field string) bool
	HasCriterion(name string) bool
	// CriterionValue returns the value of a single-valued criterion, or ""
	// when it is absent or not yet known.
	CriterionValue(name string) string
}

// Unknowns is implemented by a RuleValues whose values may not be known yet,
// as during a plan, where a value can depend on another resource. A
// constraint that depends on a value not yet known is not checked: whichever
// way it went would be a guess, and a wrong guess fails the plan for nothing.
//
// What the API returns is always known, so CheckStored has no need of it.
type Unknowns interface {
	// FieldUnknown reports whether a field's value is not yet known.
	FieldUnknown(field string) bool
	// CriterionUnknown reports whether a criterion's value is not yet known,
	// which it is not while the criteria as a whole are unknown either.
	CriterionUnknown(name string) bool
}

// Violation is one cross-field rule a rule breaks.
type Violation struct {
	// Field is the attribute at fault, or "" when the rule as a whole or a
	// criterion is.
	Field string
	// Criterion is the criterion at fault, when one is.
	Criterion string
	// Summary is a one-line statement of the problem.
	Summary string
	// Detail explains what the API requires and what to do.
	Detail string
}

// CheckRule returns every constraint violation in a rule.
//
// Constraints whose mode is not yet known are skipped rather than guessed at:
// during a plan the mode may be unknown until apply. So is a constraint on any
// other value not yet known, where v reports them; see Unknowns.
func (s Spec) CheckRule(v RuleValues) []Violation {
	mode := v.Mode()
	if mode == "" {
		return nil
	}

	var out []Violation
	for _, c := range s.Constraints {
		if dependsOnUnknown(c, v) {
			continue
		}
		if got := checkOne(s, c, mode, v); got != nil {
			out = append(out, *got)
		}
	}
	return out
}

// dependsOnUnknown reports whether a constraint reads a value v does not know
// yet.
func dependsOnUnknown(c Constraint, v RuleValues) bool {
	u, ok := v.(Unknowns)
	if !ok {
		return false
	}
	if c.Field != "" && u.FieldUnknown(c.Field) {
		return true
	}
	if c.Criterion != "" && u.CriterionUnknown(c.Criterion) {
		return true
	}
	for _, name := range c.Others {
		if u.CriterionUnknown(name) {
			return true
		}
	}
	if c.Other == "" {
		return false
	}
	switch c.Kind {
	case RequiredWhenCriterionSet, RequiredWhenCriterionAbsent, CriterionRequiredForValues:
		return u.CriterionUnknown(c.Other)
	default:
		return u.FieldUnknown(c.Other)
	}
}

func checkOne(s Spec, c Constraint, mode string, v RuleValues) *Violation {
	switch c.Kind {
	case RequiredForModes:
		if !slices.Contains(c.Modes, mode) || v.IsSet(c.Field) {
			return nil
		}
		detail := fmt.Sprintf("The Push API requires `%s` when `mode` is %s. Set it", c.Field, mode)
		var others []string
		for _, m := range s.Modes {
			if !slices.Contains(c.Modes, m) {
				others = append(others, m)
			}
		}
		if len(others) > 0 {
			detail += fmt.Sprintf(", or use a mode that does not require it (%s)", Backticked(others))
		}
		return &Violation{
			Field:   c.Field,
			Summary: fmt.Sprintf("`%s` is required for mode %s", c.Field, mode),
			Detail:  detail + ".",
		}

	case ForbiddenForModes:
		if !slices.Contains(c.Modes, mode) || !v.IsSet(c.Field) {
			return nil
		}
		return &Violation{
			Field:   c.Field,
			Summary: fmt.Sprintf("`%s` must not be set for mode %s", c.Field, mode),
			Detail:  fmt.Sprintf("The Push API rejects `%s` when `mode` is %s. Remove it.", c.Field, mode),
		}

	case DiscardedForModes:
		if !slices.Contains(c.Modes, mode) || !v.IsSet(c.Field) {
			return nil
		}
		return &Violation{
			Field:   c.Field,
			Summary: fmt.Sprintf("`%s` must not be set for mode %s", c.Field, mode),
			Detail: fmt.Sprintf("The Push API accepts `%s` when `mode` is %s and then drops it, "+
				"so the value would not survive the apply and Terraform would report an "+
				"inconsistent result. Remove it.", c.Field, mode),
		}

	case ForbiddenTrueForModes:
		if !slices.Contains(c.Modes, mode) || !v.IsTrue(c.Field) {
			return nil
		}
		return &Violation{
			Field:   c.Field,
			Summary: fmt.Sprintf("`%s` cannot be true for mode %s", c.Field, mode),
			Detail: fmt.Sprintf("The Push API forces `%s` to false when `mode` is %s, so a "+
				"true value is returned as false. Set it to false or omit it.",
				c.Field, mode),
		}

	case RequiredWhenFieldTrue:
		if !v.IsTrue(c.Other) || v.IsSet(c.Field) {
			return nil
		}
		return &Violation{
			Field:   c.Field,
			Summary: fmt.Sprintf("`%s` is required when `%s` is true", c.Field, c.Other),
			Detail:  fmt.Sprintf("The Push API requires `%s` whenever `%s` is true.", c.Field, c.Other),
		}

	case ForbiddenWhenFieldFalse:
		inMode := len(c.Modes) == 0 || slices.Contains(c.Modes, mode)
		if !inMode || !v.IsFalse(c.Other) || !v.IsSet(c.Field) {
			return nil
		}
		return &Violation{
			Field:   c.Field,
			Summary: fmt.Sprintf("`%s` must not be set when `%s` is false", c.Field, c.Other),
			Detail: fmt.Sprintf("The Push API rejects `%s` on a %s rule whose `%s` is false. "+
				"Remove it, or set `%s` to true.", c.Field, mode, c.Other, c.Other),
		}

	case DiscardedWhenFieldFalse:
		if !v.IsFalse(c.Other) || !v.IsSet(c.Field) {
			return nil
		}
		return &Violation{
			Field:   c.Field,
			Summary: fmt.Sprintf("`%s` must not be set when `%s` is false", c.Field, c.Other),
			Detail: fmt.Sprintf("The Push API accepts `%s` when `%s` is false and then drops "+
				"it, so the value would not survive the apply and Terraform would report an "+
				"inconsistent result. Remove it.", c.Field, c.Other),
		}

	case RequiredWhenCriterionSet:
		set := v.HasCriterion(c.Other)
		inMode := len(c.Modes) == 0 || slices.Contains(c.Modes, mode)
		switch {
		case set && inMode && !v.IsSet(c.Field):
			return &Violation{
				Field:   c.Field,
				Summary: fmt.Sprintf("`%s` is required when `criteria.%s` is set", c.Field, c.Other),
				Detail: fmt.Sprintf("The Push API requires `%s` for a %s rule that matches "+
					"`criteria.%s`.", c.Field, mode, c.Other),
			}
		case !set && v.IsSet(c.Field):
			return &Violation{
				Field:   c.Field,
				Summary: fmt.Sprintf("`%s` must not be set without `criteria.%s`", c.Field, c.Other),
				Detail: fmt.Sprintf("The Push API rejects `%s` on a rule that does not match "+
					"`criteria.%s`.", c.Field, c.Other),
			}
		}
		return nil

	case RequiredWhenCriterionAbsent:
		absent := !v.HasCriterion(c.Other)
		inMode := len(c.Modes) == 0 || slices.Contains(c.Modes, mode)
		switch {
		case absent && inMode && !v.IsSet(c.Field):
			return &Violation{
				Field:   c.Field,
				Summary: fmt.Sprintf("`%s` is required when `criteria.%s` is not set", c.Field, c.Other),
				Detail: fmt.Sprintf("The Push API requires `%s` for a %s rule that does not "+
					"match `criteria.%s`.", c.Field, mode, c.Other),
			}
		case (!absent || !inMode) && v.IsSet(c.Field):
			return &Violation{
				Field:   c.Field,
				Summary: fmt.Sprintf("`%s` must not be set here", c.Field),
				Detail: fmt.Sprintf("The Push API only accepts `%s` on a rule whose mode is %s "+
					"and which does not match `criteria.%s`. Remove it.",
					c.Field, Backticked(c.Modes), c.Other),
			}
		}
		return nil

	case AtLeastOneCriterion:
		for _, name := range c.Others {
			if v.HasCriterion(name) {
				return nil
			}
		}
		return &Violation{
			Summary: "At least one of " + Backticked(c.Others) + " is required",
			Detail: fmt.Sprintf("The Push API requires every %s rule to match on at least one "+
				"of %s.", s.TypeName, Backticked(c.Others)),
		}

	case CriterionRequiredForValues:
		other := v.CriterionValue(c.Other)
		if other == "" {
			return nil
		}
		set := v.HasCriterion(c.Criterion)
		switch required := slices.Contains(c.Values, other); {
		case required && !set:
			return &Violation{
				Criterion: c.Criterion,
				Summary: fmt.Sprintf("`criteria.%s` is required when `criteria.%s` is %s",
					c.Criterion, c.Other, other),
				Detail: fmt.Sprintf("The Push API requires `criteria.%s` on a rule whose "+
					"`criteria.%s` is %s. Set it, or choose another `%s`.",
					c.Criterion, c.Other, other, c.Other),
			}
		case !required && set:
			return &Violation{
				Criterion: c.Criterion,
				Summary: fmt.Sprintf("`criteria.%s` must not be set when `criteria.%s` is %s",
					c.Criterion, c.Other, other),
				Detail: fmt.Sprintf("The Push API only accepts `criteria.%s` on a rule whose "+
					"`criteria.%s` is %s. Remove it, or change `%s`.",
					c.Criterion, c.Other, Backticked(c.Values), c.Other),
			}
		}
		return nil
	}

	return nil
}

// Backticked writes values as Markdown code spans in an English list, as
// diagnostics and attribute descriptions name them: `a`, `b` or `c`.
func Backticked(vals []string) string {
	out := make([]string, len(vals))
	for i, v := range vals {
		out[i] = "`" + v + "`"
	}
	switch len(out) {
	case 0:
		return ""
	case 1:
		return out[0]
	}
	return strings.Join(out[:len(out)-1], ", ") + " or " + out[len(out)-1]
}
