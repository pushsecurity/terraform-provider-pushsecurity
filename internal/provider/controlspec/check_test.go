package controlspec

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"testing"
)

// fakeRule is the least a constraint needs: a mode, the fields that are set,
// and the criteria that are present. A field named in fields is set and, if it
// is a boolean, true; one named in falses is set and false. A single-valued
// criterion named in values is present with that value.
type fakeRule struct {
	mode     string
	fields   map[string]bool
	falses   map[string]bool
	criteria map[string]bool
	values   map[string]string
}

func (f fakeRule) Mode() string                      { return f.mode }
func (f fakeRule) IsSet(field string) bool           { return f.fields[field] || f.falses[field] }
func (f fakeRule) IsTrue(field string) bool          { return f.fields[field] }
func (f fakeRule) IsFalse(field string) bool         { return f.falses[field] }
func (f fakeRule) HasCriterion(name string) bool     { return f.criteria[name] || f.values[name] != "" }
func (f fakeRule) CriterionValue(name string) string { return f.values[name] }

func rule(mode string, fields ...string) fakeRule {
	r := fakeRule{mode: mode, fields: map[string]bool{}, falses: map[string]bool{},
		criteria: map[string]bool{}, values: map[string]string{}}
	for _, f := range fields {
		r.fields[f] = true
	}
	return r
}

func (f fakeRule) withFalse(fields ...string) fakeRule {
	for _, name := range fields {
		f.falses[name] = true
	}
	return f
}

func (f fakeRule) with(criteria ...string) fakeRule {
	for _, c := range criteria {
		f.criteria[c] = true
	}
	return f
}

func (f fakeRule) withValue(criterion, value string) fakeRule {
	f.values[criterion] = value
	return f
}

// TestMessageFieldsOutsideMessageModes covers the gap where a rule in a mode
// that shows no message still carries one: the plan passed, and the apply
// failed. Each case is a rule the API enforces on write.
func TestMessageFieldsOutsideMessageModes(t *testing.T) {
	for _, tc := range []struct {
		name string
		spec Spec
		rule fakeRule
		// want is the field the violation must name, or "" for none.
		want, wantText string
	}{
		{"download MONITOR title", FileDownloadBlocking, rule("MONITOR", "title"), "title", "rejects"},
		{"download OFF subtext", FileDownloadBlocking, rule("OFF", "subtext"), "subtext", "rejects"},
		{"download BLOCK message", FileDownloadBlocking, rule("BLOCK", "title", "subtext"), "", ""},
		{"upload MONITOR subtext", FileUploadBlocking, rule("MONITOR", "subtext"), "subtext", "rejects"},
		{"upload OFF title", FileUploadBlocking, rule("OFF", "title"), "title", "rejects"},
		{"mfa OFF title", MfaEnforcement, rule("OFF", "title"), "title", "rejects"},
		{"mfa OFF button_text", MfaEnforcement, rule("OFF", "button_text"), "button_text", "rejects"},
		{"mfa OFF bare", MfaEnforcement, rule("OFF"), "", ""},
		{
			"clipboard MONITOR copy_redacted with regex patterns", ClipboardBlocking,
			rule("MONITOR", "copy_redacted_button_text").with("regex_patterns"),
			"copy_redacted_button_text", "rejects",
		},
		{"custom detection OFF severity", CustomDetectionRules, rule("OFF", "severity"), "severity", "rejects"},
		{"custom detection MONITOR title", CustomDetectionRules, rule("MONITOR", "severity", "title"), "title", "rejects"},
		{"custom detection BLOCK button_text", CustomDetectionRules,
			rule("BLOCK", "severity", "title", "subtext", "button_text"), "button_text", "rejects"},
		{"custom detection MONITOR", CustomDetectionRules, rule("MONITOR", "severity"), "", ""},

		// The API takes these and drops them, so the read-back differs.
		{"extension blocking ENABLE title", BrowserExtensionBlocking, rule("ENABLE", "title"), "title", "drops it"},
		{"extension blocking OFF subtext", BrowserExtensionBlocking, rule("OFF", "subtext"), "subtext", "drops it"},
		{"banner DO_NOT_SHOW title", AppBanner, rule("DO_NOT_SHOW", "title"), "title", "drops it"},
		{"URL banner DO_NOT_SHOW display_frequency", AppBannerURLPattern,
			rule("DO_NOT_SHOW", "display_frequency"), "display_frequency", "drops it"},
		{"banner DO_NOT_SHOW bare", AppBanner, rule("DO_NOT_SHOW"), "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.spec.CheckRule(tc.rule)
			if tc.want == "" {
				if len(got) != 0 {
					t.Errorf("violations = %+v, want none", got)
				}
				return
			}
			for _, v := range got {
				if v.Field == tc.want && strings.Contains(v.Detail, tc.wantText) {
					return
				}
			}
			t.Errorf("violations = %+v, want one on %q saying %q", got, tc.want, tc.wantText)
		})
	}
}

// TestConstraintsOnABooleanBeingFalse covers the two rules that depend on a
// boolean being false rather than true. Absent or unknown is neither, so a
// plan whose boolean is not yet known is not refused.
func TestConstraintsOnABooleanBeingFalse(t *testing.T) {
	for _, tc := range []struct {
		name string
		spec Spec
		rule fakeRule
		// want is the field the violation must name, or "" for none.
		want, wantText string
	}{
		// The API stores maskPii only when contentCapture is true, so the
		// value would read back null.
		{"clipboard mask_pii without capture", ClipboardBlocking,
			rule("MONITOR", "mask_pii").withFalse("content_capture").with("url_patterns"),
			"mask_pii", "drops it"},
		{"clipboard mask_pii false without capture", ClipboardBlocking,
			rule("MONITOR").withFalse("content_capture", "mask_pii").with("url_patterns"),
			"mask_pii", "drops it"},
		{"clipboard mask_pii with capture", ClipboardBlocking,
			rule("MONITOR", "content_capture", "mask_pii").with("url_patterns"), "", ""},
		{"clipboard no mask_pii without capture", ClipboardBlocking,
			rule("MONITOR").withFalse("content_capture").with("url_patterns"), "", ""},
		{"clipboard mask_pii with capture unknown", ClipboardBlocking,
			rule("MONITOR", "mask_pii").with("url_patterns"), "", ""},

		// A BLOCK banner takes button_text only when a reason may be given.
		{"banner BLOCK button_text without reasons", AppBanner,
			rule("BLOCK", "title", "subtext", "button_text").withFalse("allow_reason_submission"),
			"button_text", "rejects"},
		{"URL banner BLOCK button_text without reasons", AppBannerURLPattern,
			rule("BLOCK", "title", "subtext", "button_text").withFalse("allow_reason_submission"),
			"button_text", "rejects"},
		{"banner BLOCK without reasons", AppBanner,
			rule("BLOCK", "title", "subtext").withFalse("allow_reason_submission"), "", ""},
		{"banner BLOCK button_text with reasons", AppBanner,
			rule("BLOCK", "title", "subtext", "button_text", "allow_reason_submission"), "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.spec.CheckRule(tc.rule)
			if tc.want == "" {
				if len(got) != 0 {
					t.Errorf("violations = %+v, want none", got)
				}
				return
			}
			for _, v := range got {
				if v.Field == tc.want && strings.Contains(v.Detail, tc.wantText) {
					return
				}
			}
			t.Errorf("violations = %+v, want one on %q saying %q", got, tc.want, tc.wantText)
		})
	}
}

// TestForbiddenWhenFieldFalseKeepsToItsModes pins the mode scoping: outside
// BLOCK, a banner's button_text is governed by the mode rules alone.
func TestForbiddenWhenFieldFalseKeepsToItsModes(t *testing.T) {
	got := AppBanner.CheckRule(
		rule("ACKNOWLEDGE", "title", "subtext", "button_text").withFalse("allow_reason_submission"))
	for _, v := range got {
		if v.Field == "button_text" {
			t.Errorf("unexpected violation on button_text in ACKNOWLEDGE: %+v", v)
		}
	}
	// allow_reason_submission itself is still forbidden outside BLOCK.
	if len(got) != 1 || got[0].Field != "allow_reason_submission" {
		t.Errorf("violations = %+v, want only allow_reason_submission", got)
	}
}

// TestCriterionRequiredForAValue covers account condition enforcement's login
// domains, which the API demands when the domain scope is SPECIFIC_DOMAINS and
// rejects for any other scope. With the scope absent or not yet known there is
// nothing to check against.
func TestCriterionRequiredForAValue(t *testing.T) {
	for _, tc := range []struct {
		name string
		rule fakeRule
		// wantText is what the one violation on login_domains must say, or ""
		// for none.
		wantText string
	}{
		{"specific domains with login domains",
			rule("MONITOR").withValue("domain_scope", "SPECIFIC_DOMAINS").with("login_domains"), ""},
		{"specific domains without login domains",
			rule("MONITOR").withValue("domain_scope", "SPECIFIC_DOMAINS"), "requires"},
		{"company domains with login domains",
			rule("MONITOR").withValue("domain_scope", "COMPANY_DOMAINS").with("login_domains"),
			"only accepts"},
		{"non-company domains with login domains",
			rule("MONITOR").withValue("domain_scope", "NON_COMPANY_DOMAINS").with("login_domains"),
			"only accepts"},
		{"company domains alone", rule("MONITOR").withValue("domain_scope", "COMPANY_DOMAINS"), ""},
		{"scope unknown with login domains", rule("MONITOR").with("login_domains"), ""},
		{"scope unknown alone", rule("MONITOR"), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := AccountConditionEnforcement.CheckRule(tc.rule)
			if tc.wantText == "" {
				if len(got) != 0 {
					t.Errorf("violations = %+v, want none", got)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("violations = %+v, want one", got)
			}
			v := got[0]
			if v.Criterion != "login_domains" || v.Field != "" {
				t.Errorf("violation is on field %q, criterion %q; want criterion login_domains",
					v.Field, v.Criterion)
			}
			if !strings.Contains(v.Detail, tc.wantText) {
				t.Errorf("detail = %q, want it to say %q", v.Detail, tc.wantText)
			}
		})
	}
}

// TestAccountConditionEnforcementMessageFields covers the four text fields
// against the modes: WARN takes all four, BLOCK all but the continue button,
// and OFF and MONITOR none.
func TestAccountConditionEnforcementMessageFields(t *testing.T) {
	scoped := func(r fakeRule) fakeRule { return r.withValue("domain_scope", "COMPANY_DOMAINS") }
	all := []string{"title", "subtext", "terminate_button_text", "continue_button_text"}

	for _, tc := range []struct {
		name string
		rule fakeRule
		// want is the fields that must be reported, in any order.
		want []string
	}{
		{"WARN complete", scoped(rule("WARN", all...)), nil},
		{"WARN without continue", scoped(rule("WARN", all[:3]...)), []string{"continue_button_text"}},
		{"BLOCK complete", scoped(rule("BLOCK", all[:3]...)), nil},
		{"BLOCK with continue", scoped(rule("BLOCK", all...)), []string{"continue_button_text"}},
		{"BLOCK without terminate", scoped(rule("BLOCK", "title", "subtext")),
			[]string{"terminate_button_text"}},
		{"MONITOR bare", scoped(rule("MONITOR")), nil},
		{"MONITOR with everything", scoped(rule("MONITOR", all...)), all},
		{"OFF with a title", scoped(rule("OFF", "title")), []string{"title"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			for _, v := range AccountConditionEnforcement.CheckRule(tc.rule) {
				got = append(got, v.Field)
			}
			if strings.Join(sorted(got), ",") != strings.Join(sorted(tc.want), ",") {
				t.Errorf("violations on %v, want %v", got, tc.want)
			}
		})
	}
}

func sorted(vals []string) []string {
	out := append([]string(nil), vals...)
	sort.Strings(out)
	return out
}

// TestViolationDetail pins the advice each kind of constraint gives, since a
// test that only checks which field is named lets wrong advice through.
func TestViolationDetail(t *testing.T) {
	modes := []string{"OFF", "MONITOR", "WARN", "BLOCK"}
	for _, tc := range []struct {
		name       string
		constraint Constraint
		rule       fakeRule
		want       string
	}{
		{
			"required for modes names the modes that do not require it",
			Constraint{Kind: RequiredForModes, Field: "title", Modes: []string{"WARN", "BLOCK"}},
			rule("BLOCK"),
			"The Push API requires `title` when `mode` is BLOCK. Set it, or use a mode that " +
				"does not require it (`OFF` or `MONITOR`).",
		},
		{
			"required for every mode offers no other mode",
			Constraint{Kind: RequiredForModes, Field: "title", Modes: modes},
			rule("OFF"),
			"The Push API requires `title` when `mode` is OFF. Set it.",
		},
		{
			"forbidden for modes",
			Constraint{Kind: ForbiddenForModes, Field: "title", Modes: []string{"OFF"}},
			rule("OFF", "title"),
			"The Push API rejects `title` when `mode` is OFF. Remove it.",
		},
		{
			"forbidden true for modes",
			Constraint{Kind: ForbiddenTrueForModes, Field: "flag", Modes: []string{"OFF"}},
			rule("OFF", "flag"),
			"The Push API forces `flag` to false when `mode` is OFF, so a true value is " +
				"returned as false. Set it to false or omit it.",
		},
		{
			"required when field true",
			Constraint{Kind: RequiredWhenFieldTrue, Field: "text", Other: "flag"},
			rule("OFF", "flag"),
			"The Push API requires `text` whenever `flag` is true.",
		},
		{
			"forbidden when field false",
			Constraint{Kind: ForbiddenWhenFieldFalse, Field: "text", Other: "flag"},
			rule("BLOCK", "text").withFalse("flag"),
			"The Push API rejects `text` on a BLOCK rule whose `flag` is false. Remove it, or " +
				"set `flag` to true.",
		},
		{
			"required when criterion set",
			Constraint{Kind: RequiredWhenCriterionSet, Field: "text", Other: "hosts"},
			rule("BLOCK").with("hosts"),
			"The Push API requires `text` for a BLOCK rule that matches `criteria.hosts`.",
		},
		{
			"forbidden without the criterion",
			Constraint{Kind: RequiredWhenCriterionSet, Field: "text", Other: "hosts"},
			rule("BLOCK", "text"),
			"The Push API rejects `text` on a rule that does not match `criteria.hosts`.",
		},
		{
			"required when criterion absent",
			Constraint{Kind: RequiredWhenCriterionAbsent, Field: "text", Other: "hosts", Modes: []string{"BLOCK"}},
			rule("BLOCK"),
			"The Push API requires `text` for a BLOCK rule that does not match `criteria.hosts`.",
		},
		{
			"forbidden with the criterion",
			Constraint{Kind: RequiredWhenCriterionAbsent, Field: "text", Other: "hosts", Modes: []string{"BLOCK"}},
			rule("BLOCK", "text").with("hosts"),
			"The Push API only accepts `text` on a rule whose mode is `BLOCK` and which does " +
				"not match `criteria.hosts`. Remove it.",
		},
		{
			"at least one criterion",
			Constraint{Kind: AtLeastOneCriterion, Others: []string{"hosts", "urls"}},
			rule("BLOCK"),
			"The Push API requires every test_control rule to match on at least one of " +
				"`hosts` or `urls`.",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := Spec{TypeName: "test_control", Modes: modes, Constraints: []Constraint{tc.constraint}}
			got := spec.CheckRule(tc.rule)
			if len(got) != 1 {
				t.Fatalf("violations = %+v, want one", got)
			}
			if got[0].Detail != tc.want {
				t.Errorf("detail =\n  %s\nwant\n  %s", got[0].Detail, tc.want)
			}
		})
	}
}

// TestConstraintsOnTheControlsThatUseThem checks the conditional kinds of
// constraint against the controls that declare them, where TestViolationDetail
// uses a constraint made up for the purpose: each case is the full list of
// violations, advice included, so a constraint that fires on the wrong rule
// fails as surely as one that does not fire.
func TestConstraintsOnTheControlsThatUseThem(t *testing.T) {
	const (
		ackRequired = "The Push API requires `acknowledge_button_text` for a BLOCK rule that does " +
			"not match `criteria.regex_patterns`."
		ackForbidden = "The Push API only accepts `acknowledge_button_text` on a rule whose mode " +
			"is `BLOCK` and which does not match `criteria.regex_patterns`. Remove it."
		redactedRequired = "The Push API requires `copy_redacted_button_text` for a %s rule that " +
			"matches `criteria.regex_patterns`."
		redactedForbidden = "The Push API rejects `copy_redacted_button_text` on a rule that does " +
			"not match `criteria.regex_patterns`."
	)
	message := []string{"title", "subtext"}
	with := func(fields ...string) []string { return append(append([]string(nil), message...), fields...) }

	for _, tc := range []struct {
		name string
		spec Spec
		rule fakeRule
		// want is each violation as its field, or "" for the rule as a whole,
		// and its detail.
		want [][2]string
	}{
		// RequiredWhenCriterionAbsent: a clipboard BLOCK rule without regex
		// patterns has a button to dismiss the banner, and no other rule does.
		{"clipboard BLOCK on URLs with acknowledge", ClipboardBlocking,
			rule("BLOCK", with("acknowledge_button_text")...).with("url_patterns"), nil},
		{"clipboard BLOCK on URLs without acknowledge", ClipboardBlocking,
			rule("BLOCK", message...).with("url_patterns"),
			[][2]string{{"acknowledge_button_text", ackRequired}}},
		{"clipboard WARN with acknowledge", ClipboardBlocking,
			rule("WARN", with("copy_original_button_text", "acknowledge_button_text")...).with("url_patterns"),
			[][2]string{{"acknowledge_button_text", ackForbidden}}},

		// RequiredWhenCriterionSet: one with regex patterns has a button to
		// copy the content redacted, in the modes that show a banner.
		{"clipboard BLOCK on regex patterns", ClipboardBlocking,
			rule("BLOCK", with("copy_redacted_button_text")...).with("regex_patterns"), nil},
		{"clipboard BLOCK on regex patterns with acknowledge", ClipboardBlocking,
			rule("BLOCK", with("acknowledge_button_text")...).with("regex_patterns"),
			[][2]string{
				{"copy_redacted_button_text", fmt.Sprintf(redactedRequired, "BLOCK")},
				{"acknowledge_button_text", ackForbidden},
			}},
		{"clipboard WARN on regex patterns without copy_redacted", ClipboardBlocking,
			rule("WARN", with("copy_original_button_text")...).with("regex_patterns"),
			[][2]string{{"copy_redacted_button_text", fmt.Sprintf(redactedRequired, "WARN")}}},
		{"clipboard MONITOR on regex patterns", ClipboardBlocking,
			rule("MONITOR").with("regex_patterns"), nil},
		{"clipboard BLOCK on URLs with copy_redacted", ClipboardBlocking,
			rule("BLOCK", with("acknowledge_button_text", "copy_redacted_button_text")...).with("url_patterns"),
			[][2]string{{"copy_redacted_button_text", redactedForbidden}}},

		// AtLeastOneCriterion.
		{"clipboard on employee groups alone", ClipboardBlocking,
			rule("MONITOR").with("employee_groups"),
			[][2]string{{"", "The Push API requires every clipboard_blocking rule to match on at " +
				"least one of `url_patterns` or `regex_patterns`."}}},
		{"clipboard on both", ClipboardBlocking,
			rule("MONITOR").with("url_patterns", "regex_patterns"), nil},

		// RequiredWhenFieldTrue.
		{"clipboard capture without mask_pii", ClipboardBlocking,
			rule("MONITOR", "content_capture").with("url_patterns"),
			[][2]string{{"mask_pii", "The Push API requires `mask_pii` whenever `content_capture` is true."}}},
		{"banner BLOCK with reasons and no button", AppBanner,
			rule("BLOCK", with("allow_reason_submission")...),
			[][2]string{{"button_text", "The Push API requires `button_text` whenever " +
				"`allow_reason_submission` is true."}}},

		// ForbiddenTrueForModes.
		{"custom detection OFF on internal hosts", CustomDetectionRules,
			rule("OFF", "detect_on_internal_hosts"),
			[][2]string{{"detect_on_internal_hosts", "The Push API forces `detect_on_internal_hosts` " +
				"to false when `mode` is OFF, so a true value is returned as false. Set it to false " +
				"or omit it."}}},
		{"custom detection OFF not on internal hosts", CustomDetectionRules,
			rule("OFF").withFalse("detect_on_internal_hosts"), nil},
		{"custom detection MONITOR on internal hosts", CustomDetectionRules,
			rule("MONITOR", "severity", "detect_on_internal_hosts"), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got [][2]string
			for _, v := range tc.spec.CheckRule(tc.rule) {
				got = append(got, [2]string{v.Field, v.Detail})
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("violations =\n  %q\nwant\n  %q", got, tc.want)
			}
		})
	}
}

// unknownRule is a fakeRule some of whose values are not yet known, as during
// a plan. Whatever fakeRule says of them is ignored.
type unknownRule struct {
	fakeRule
	fields, criteria map[string]bool
}

func (u unknownRule) FieldUnknown(field string) bool    { return u.fields[field] }
func (u unknownRule) CriterionUnknown(name string) bool { return u.criteria[name] }

func unknown(r fakeRule, fields, criteria []string) unknownRule {
	u := unknownRule{fakeRule: r, fields: map[string]bool{}, criteria: map[string]bool{}}
	for _, f := range fields {
		u.fields[f] = true
	}
	for _, c := range criteria {
		u.criteria[c] = true
	}
	return u
}

// TestConstraintsWaitForUnknownValues checks a constraint that reads a value
// not yet known is skipped, whichever way the value would have gone, and that
// the constraints that do not read it are still checked.
func TestConstraintsWaitForUnknownValues(t *testing.T) {
	message := []string{"title", "subtext"}
	for _, tc := range []struct {
		name string
		spec Spec
		rule unknownRule
		// want is the fields violations must name, in order; "" is the rule
		// as a whole.
		want []string
	}{
		// Unknown criteria might hold regex patterns, URL patterns, both or
		// neither, so neither button nor the one-criterion rule can be judged.
		{"clipboard BLOCK with every criterion unknown", ClipboardBlocking,
			unknown(rule("BLOCK", message...), nil, []string{"url_patterns", "regex_patterns"}), nil},
		{"clipboard BLOCK with regex patterns unknown", ClipboardBlocking,
			unknown(rule("BLOCK", "title", "subtext", "acknowledge_button_text").with("url_patterns"),
				nil, []string{"regex_patterns"}), nil},
		// A constraint that does not read the criteria is still checked.
		{"clipboard BLOCK with criteria unknown and no title", ClipboardBlocking,
			unknown(rule("BLOCK", "subtext"), nil, []string{"url_patterns", "regex_patterns"}),
			[]string{"title"}},
		{"clipboard MONITOR with the title unknown", ClipboardBlocking,
			unknown(rule("MONITOR", "title").with("url_patterns"), []string{"title"}, nil), nil},
		{"clipboard mask_pii unknown without capture", ClipboardBlocking,
			unknown(rule("MONITOR", "mask_pii").withFalse("content_capture").with("url_patterns"),
				[]string{"mask_pii"}, nil), nil},
		{"clipboard capture unknown without mask_pii", ClipboardBlocking,
			unknown(rule("MONITOR", "content_capture").with("url_patterns"),
				[]string{"content_capture"}, nil), nil},
		{"login domains unknown for specific domains", AccountConditionEnforcement,
			unknown(rule("MONITOR").withValue("domain_scope", "SPECIFIC_DOMAINS"),
				nil, []string{"login_domains"}), nil},
		{"domain scope unknown with login domains", AccountConditionEnforcement,
			unknown(rule("MONITOR").with("login_domains"), nil, []string{"domain_scope"}), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			for _, v := range tc.spec.CheckRule(tc.rule) {
				got = append(got, v.Field)
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("violations on %q, want %q", got, tc.want)
			}
		})
	}
}
