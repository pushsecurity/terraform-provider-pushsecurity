package controlspec

import (
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/pushapi"
)

// StoredViolation is configuration the API will not accept back: GET is more
// permissive than PUT, so a tenant can hold rules that cannot be rewritten.
// It is also a criterion value or rule text that the provider rejects, or
// warns about, during plan, and a list longer than the API accepts.
type StoredViolation struct {
	// RuleIndex is -1 for a problem with the resource as a whole, such as too
	// many rules.
	RuleIndex int
	RuleName  string
	Mode      string
	// Criterion or Field, with Value, name the value at fault, for a problem
	// with one criterion value or one rule field rather than with the rule as
	// a whole. Value is empty where the problem is the number of values.
	Criterion string
	Field     string
	Value     string
	Summary   string
	// Warning marks a value that plans, with a warning, rather than failing.
	Warning bool
}

// Pathless reports whether a violation is a URL pattern with no path. The API
// adds `/*` to those on write, but returns one already stored without a path
// as it is.
func (v StoredViolation) Pathless() bool {
	rest, ok := strings.CutPrefix(v.Value, "*://")
	return v.Criterion == "url_patterns" && ok && !strings.ContainsAny(rest, "/?#")
}

// CheckStored evaluates configuration as the API returns it against the same
// cross-field constraints, text checks, criterion value checks and size limits
// the provider applies during plan. It predicts what the first plan of an
// adopted tenant will say, before any configuration exists.
func CheckStored(s Spec, rules []pushapi.Rule, globals map[string]any) []StoredViolation {
	return append(checkSizes(s, len(rules), globals), checkRules(s, rules)...)
}

// CheckStoredBlockedURLs reports a blocked URL list longer than the API
// accepts.
func CheckStoredBlockedURLs(n int) []StoredViolation {
	if n <= MaxBlockedURLs {
		return nil
	}
	return []StoredViolation{{
		RuleIndex: -1,
		Summary:   fmt.Sprintf("%d patterns, more than the %d the API accepts", n, MaxBlockedURLs),
	}}
}

// HasGlobals reports whether any of a control's control-wide lists has
// entries. A control with no rules but with globals still has configuration
// to adopt.
func HasGlobals(s Spec, globals map[string]any) bool {
	for _, g := range s.Globals {
		if items, _ := globals[g.APIName].([]any); len(items) > 0 {
			return true
		}
	}
	return false
}

// checkSizes reports a control or detection holding more rules, or more
// entries in a control-wide list, than the API accepts. The provider checks
// the same limits during plan.
func checkSizes(s Spec, rules int, globals map[string]any) []StoredViolation {
	var out []StoredViolation
	if rules > MaxRules {
		out = append(out, StoredViolation{
			RuleIndex: -1,
			Summary:   fmt.Sprintf("%d rules, more than the %d the API accepts", rules, MaxRules),
		})
	}
	for _, g := range s.Globals {
		items, _ := globals[g.APIName].([]any)
		if g.MaxItems > 0 && len(items) > g.MaxItems {
			out = append(out, StoredViolation{
				RuleIndex: -1,
				Summary: fmt.Sprintf("globals.%s has %d entries, more than the %d the API accepts",
					g.Name, len(items), g.MaxItems),
			})
		}
	}
	return out
}

// checkRules evaluates the same cross-field constraints, text checks,
// criterion value checks and size limits the provider applies during plan, so
// the result predicts what a plan will say rather than approximating it.
func checkRules(s Spec, rules []pushapi.Rule) []StoredViolation {
	var out []StoredViolation
	for i, r := range rules {
		for _, v := range s.CheckRule(apiRuleValues{r}) {
			out = append(out, StoredViolation{
				RuleIndex: i,
				RuleName:  r.Name,
				Mode:      r.Mode,
				Summary:   v.Summary,
			})
		}
		if n := utf8.RuneCountInString(r.Name); n > MaxRuleNameLength {
			out = append(out, StoredViolation{
				RuleIndex: i,
				RuleName:  r.Name,
				Mode:      r.Mode,
				Summary: fmt.Sprintf("Name is %d characters, more than the %d the API accepts",
					n, MaxRuleNameLength),
			})
		}
		// What the API stored for these fields is what it escaped on write,
		// so this is where a title holding `&amp;` turns up.
		for _, f := range s.Fields {
			text, ok := r.Fields[f.APIName].(string)
			if !ok {
				continue
			}
			if p := f.CheckText(text); p != nil {
				out = append(out, StoredViolation{
					RuleIndex: i,
					RuleName:  r.Name,
					Mode:      r.Mode,
					Field:     f.Name,
					Value:     text,
					Summary:   p.Summary,
				})
			}
		}
		for _, c := range s.Criteria {
			// A stored rule can lack a criterion the API requires on write,
			// and the configuration generated from it then fails plan.
			if c.Required && len(r.Criteria[c.APIName].Matches) == 0 {
				out = append(out, StoredViolation{
					RuleIndex: i,
					RuleName:  r.Name,
					Mode:      r.Mode,
					Summary:   fmt.Sprintf("`criteria.%s` is missing, which the API requires", c.Name),
				})
			}
			if n := len(r.Criteria[c.APIName].Matches); !c.Single && n > c.MatchesLimit() {
				out = append(out, StoredViolation{
					RuleIndex: i,
					RuleName:  r.Name,
					Mode:      r.Mode,
					Criterion: c.Name,
					Summary: fmt.Sprintf("%d values, more than the %d the API accepts",
						n, c.MatchesLimit()),
				})
			}
		}
		// The criteria come off the wire keyed by API name, so the spec maps
		// them back to the criterion that knows how to check them. Walking the
		// spec rather than the map keeps the result in a stable order.
		for _, c := range s.Criteria {
			// A closed set the API extends can hold a value newer than the
			// provider's copy of it.
			for _, m := range r.Criteria[c.APIName].Matches {
				if len(c.Enum) > 0 && !slices.Contains(c.Enum, m) {
					out = append(out, StoredViolation{
						RuleIndex: i,
						RuleName:  r.Name,
						Mode:      r.Mode,
						Criterion: c.Name,
						Value:     m,
						Summary:   "Not one of the values this version of the provider accepts",
					})
				}
			}
			if c.Values == PlainValues {
				continue
			}
			for _, m := range r.Criteria[c.APIName].Matches {
				p := c.CheckValue(m)
				if p == nil {
					continue
				}
				out = append(out, StoredViolation{
					RuleIndex: i,
					RuleName:  r.Name,
					Mode:      r.Mode,
					Criterion: c.Name,
					Value:     m,
					Summary:   p.Summary,
					Warning:   p.Warning,
				})
			}
		}
	}
	return out
}

// apiRuleValues is a rule as the API returns it, seen the way the
// constraints see a rule.
type apiRuleValues struct{ rule pushapi.Rule }

func (a apiRuleValues) Mode() string { return a.rule.Mode }

func (a apiRuleValues) IsSet(field string) bool {
	v, present := a.rule.Fields[apiName(field)]
	if !present || v == nil {
		return false
	}
	if s, ok := v.(string); ok {
		return s != ""
	}
	if items, ok := v.([]any); ok {
		return len(items) > 0
	}
	return true
}

func (a apiRuleValues) IsTrue(field string) bool {
	b, _ := a.rule.Fields[apiName(field)].(bool)
	return b
}

func (a apiRuleValues) IsFalse(field string) bool {
	b, ok := a.rule.Fields[apiName(field)].(bool)
	return ok && !b
}

func (a apiRuleValues) HasCriterion(name string) bool {
	c, present := a.rule.Criteria[apiName(name)]
	return present && len(c.Matches) > 0
}

func (a apiRuleValues) CriterionValue(name string) string {
	c := a.rule.Criteria[apiName(name)]
	if len(c.Matches) != 1 {
		return ""
	}
	return c.Matches[0]
}

// apiName converts a Terraform attribute name back to the API's camelCase.
// Constraints are written in terms of attribute names, but the data here came
// off the wire.
func apiName(attr string) string {
	parts := strings.Split(attr, "_")
	for i := 1; i < len(parts); i++ {
		if parts[i] == "" {
			continue
		}
		parts[i] = strings.ToUpper(parts[i][:1]) + parts[i][1:]
	}
	return strings.Join(parts, "")
}
