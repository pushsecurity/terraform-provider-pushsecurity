package controlspec

import (
	"fmt"
	"strings"
	"testing"

	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/pushapi"
)

// TestCheckRulesFindsUnwritableConfiguration uses two app banner rules, mode
// INFORM, each with a title and no subtext. The API returns such rules on read
// and refuses to write them back with
//
//	rules[0]._schema: title and subtext are required for all modes except DO_NOT_SHOW
//
// Predicting that before the first apply is what these checks are for.
func TestCheckRulesFindsUnwritableConfiguration(t *testing.T) {
	rules := []pushapi.Rule{
		{
			ID: "8d06a924", Name: "Inform: All employees on selected apps",
			Enabled: false, Mode: "INFORM",
			Fields:   map[string]any{"title": "TESTTOTLE"},
			Criteria: map[string]pushapi.Condition{"appTypes": {Matches: []string{"DROPBOX"}}},
		},
		{
			ID: "6f330ec6", Name: "Inform: All employees on selected apps",
			Enabled: true, Mode: "INFORM",
			Fields:   map[string]any{"title": "TESTTOTLE ad £qasd"},
			Criteria: map[string]pushapi.Condition{"appTypes": {Matches: []string{"OKTA"}}},
		},
	}

	got := checkRules(AppBanner, rules)
	if len(got) != 2 {
		t.Fatalf("got %d violations, want 2 (one missing subtext per rule): %+v", len(got), got)
	}
	for i, v := range got {
		if v.RuleIndex != i {
			t.Errorf("violation %d has RuleIndex %d", i, v.RuleIndex)
		}
		if !strings.Contains(v.Summary, "subtext") {
			t.Errorf("violation %d = %q, want it to name subtext", i, v.Summary)
		}
		if v.Mode != "INFORM" {
			t.Errorf("violation %d mode = %q", i, v.Mode)
		}
	}
}

func TestCheckRulesAcceptsValidConfiguration(t *testing.T) {
	rules := []pushapi.Rule{{
		Name: "ok", Enabled: true, Mode: "INFORM",
		Fields: map[string]any{"title": "t", "subtext": "s"},
	}}
	if got := checkRules(AppBanner, rules); len(got) != 0 {
		t.Errorf("got %d violations, want none: %+v", len(got), got)
	}
}

// TestCheckRulesMatchesTheProviderOnCriteriaConstraints covers the clipboard
// control, whose constraints depend on criteria as well as mode.
func TestCheckRulesClipboardCriteriaConstraints(t *testing.T) {
	// A BLOCK rule matching regex patterns needs copyRedactedButtonText.
	missing := []pushapi.Rule{{
		Name: "r", Enabled: true, Mode: "BLOCK",
		Fields: map[string]any{
			"operation": "COPY", "contentCapture": false,
			"title": "t", "subtext": "s",
		},
		Criteria: map[string]pushapi.Condition{
			"regexPatterns": {Matches: []string{"CUSTOM_X"}},
		},
	}}
	got := checkRules(ClipboardBlocking, missing)
	if len(got) != 1 || !strings.Contains(got[0].Summary, "copy_redacted_button_text") {
		t.Errorf("violations = %+v, want one naming copy_redacted_button_text", got)
	}

	// Supplying it satisfies the constraint.
	ok := missing
	ok[0].Fields["copyRedactedButtonText"] = "Copy redacted"
	if got := checkRules(ClipboardBlocking, ok); len(got) != 0 {
		t.Errorf("got %d violations, want none: %+v", len(got), got)
	}
}

func TestCheckRulesCustomDetectionSeverity(t *testing.T) {
	// severity is required for every mode except OFF.
	got := checkRules(CustomDetectionRules, []pushapi.Rule{
		{Name: "r", Enabled: true, Mode: "MONITOR"},
	})
	if len(got) != 1 || !strings.Contains(got[0].Summary, "severity") {
		t.Errorf("violations = %+v, want one naming severity", got)
	}

	if got := checkRules(CustomDetectionRules, []pushapi.Rule{
		{Name: "r", Enabled: false, Mode: "OFF"},
	}); len(got) != 0 {
		t.Errorf("an OFF rule needs no severity, got %+v", got)
	}
}

// TestCheckRulesCriterionValues covers values a tenant can hold that the
// provider rejects or warns about during plan. Each rule is otherwise valid,
// so the value is the only thing reported. What the report says about it is
// whatever the provider says, so the wording is not checked here.
func TestCheckRulesCriterionValues(t *testing.T) {
	for _, tc := range []struct {
		name      string
		spec      Spec
		fields    map[string]any
		criterion string // the wire name
		value     string
		warning   bool
	}{
		{
			// Stored without a path, so the API returns it without one.
			name: "download pattern with no path", spec: FileDownloadBlocking,
			criterion: "urlPatterns", value: "*://*.anydesk.com",
		},
		{
			// A pattern with a query string is not supported.
			name: "clipboard pattern with a query", spec: ClipboardBlocking,
			fields:    map[string]any{"operation": "COPY", "contentCapture": false},
			criterion: "urlPatterns", value: "*://docs.example.com/document?usp=sharing",
		},
		{
			// An inline flag group, which is not supported.
			name: "file name pattern with (?i)", spec: FileDownloadBlocking,
			criterion: "fileNamePatterns", value: "(?i)anydesk",
		},
		{
			// Works, but matches every port.
			name: "upload pattern with :443", spec: FileUploadBlocking,
			criterion: "urlPatterns", value: "*://example.com:443/*",
			warning: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// A value the criterion accepts, to sit beside the one at fault.
			good := map[string]string{
				"urlPatterns":      "*://*.example.com/*",
				"fileNamePatterns": "^[Aa]ny[Dd]esk.*\\.exe$",
			}[tc.criterion]
			rules := []pushapi.Rule{{
				Name: "r", Enabled: true, Mode: "MONITOR", Fields: tc.fields,
				Criteria: map[string]pushapi.Condition{
					// Only the second value is at fault, so the reported value
					// must be the right one.
					tc.criterion: {Matches: []string{good, tc.value}},
					// Group names are plain values, so nothing checks this one.
					"employeeGroups": {Matches: []string{"(?i)Finance"}},
				},
			}}
			got := checkRules(tc.spec, rules)
			if len(got) != 1 {
				t.Fatalf("got %d violations, want 1: %+v", len(got), got)
			}
			v := got[0]
			c, _ := tc.spec.Criterion(v.Criterion)
			if c.APIName != tc.criterion || v.Value != tc.value {
				t.Errorf("reported %s %q, want the criterion with API name %s and value %q",
					v.Criterion, v.Value, tc.criterion, tc.value)
			}
			if want := c.CheckValue(tc.value).Summary; v.Summary != want {
				t.Errorf("summary = %q, want the provider's %q", v.Summary, want)
			}
			if v.Warning != tc.warning {
				t.Errorf("warning = %v, want %v", v.Warning, tc.warning)
			}
			if v.RuleIndex != 0 || v.RuleName != "r" || v.Mode != "MONITOR" {
				t.Errorf("violation names rules[%d] %q (mode %s), want rules[0] \"r\" (mode MONITOR)",
					v.RuleIndex, v.RuleName, v.Mode)
			}
		})
	}
}

func TestStoredViolationPathless(t *testing.T) {
	for _, tc := range []struct {
		criterion, value string
		want             bool
	}{
		{"url_patterns", "*://*.anydesk.com", true},
		{"url_patterns", "*://example.com*", true},
		{"url_patterns", "*://example.com:8443", true},
		{"url_patterns", "*://*.anydesk.com/*", false},
		{"url_patterns", "*://example.com?q=1", false},
		{"url_patterns", "example.com", false},
		{"file_name_patterns", "*://anydesk", false},
	} {
		if got := (StoredViolation{Criterion: tc.criterion, Value: tc.value}).Pathless(); got != tc.want {
			t.Errorf("Pathless(%s %q) = %v, want %v", tc.criterion, tc.value, got, tc.want)
		}
	}
}

func TestAPIName(t *testing.T) {
	// Constraints are written in Terraform attribute names, but the data being
	// checked came off the wire in camelCase.
	for _, tc := range []struct{ in, want string }{
		{"title", "title"},
		{"button_text", "buttonText"},
		{"copy_redacted_button_text", "copyRedactedButtonText"},
		{"detect_on_internal_hosts", "detectOnInternalHosts"},
		{"employee_groups", "employeeGroups"},
		{"mask_pii", "maskPii"},
	} {
		t.Run(tc.in, func(t *testing.T) {
			if got := apiName(tc.in); got != tc.want {
				t.Errorf("apiName(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestAPIRuleValues(t *testing.T) {
	r := apiRuleValues{pushapi.Rule{
		Mode: "WARN",
		Fields: map[string]any{
			"title":                 "t",
			"subtext":               "",
			"detectOnInternalHosts": true,
			"contentCapture":        false,
			"applicableFindings":    []any{},
			"buttonText":            nil,
		},
		Criteria: map[string]pushapi.Condition{
			"employeeGroups": {Matches: []string{"Finance"}},
			"urlPatterns":    {Matches: nil},
		},
	}}

	if !r.IsSet("title") {
		t.Error("title should be set")
	}
	// An empty string is not a value, by the provider's rule.
	if r.IsSet("subtext") {
		t.Error("an empty string must not count as set")
	}
	if r.IsSet("button_text") {
		t.Error("a null field must not count as set")
	}
	if r.IsSet("applicable_findings") {
		t.Error("an empty list must not count as set")
	}
	if !r.IsTrue("detect_on_internal_hosts") {
		t.Error("detect_on_internal_hosts should be true")
	}
	if !r.IsFalse("content_capture") || r.IsTrue("content_capture") {
		t.Error("content_capture should be false")
	}
	// Absent is neither true nor false.
	if r.IsFalse("mask_pii") || r.IsFalse("detect_on_internal_hosts") {
		t.Error("only a boolean that is present and false is false")
	}
	if !r.HasCriterion("employee_groups") {
		t.Error("employee_groups should be present")
	}
	// A criterion with no matches is not a restriction.
	if r.HasCriterion("url_patterns") {
		t.Error("a criterion with no matches must not count as present")
	}
	if r.HasCriterion("file_extensions") {
		t.Error("an absent criterion must not count as present")
	}
	if got := r.CriterionValue("employee_groups"); got != "Finance" {
		t.Errorf("CriterionValue(employee_groups) = %q, want Finance", got)
	}
	if got := r.CriterionValue("url_patterns"); got != "" {
		t.Errorf("CriterionValue of a criterion with no matches = %q, want empty", got)
	}
}

// TestCheckRulesAccountConditionEnforcement covers what a tenant can hold that
// the first plan of account condition enforcement rejects: a rule without one
// of the two criteria the API requires, login domains that do not fit the
// domain scope, and an app newer than the provider's list of them.
func TestCheckRulesAccountConditionEnforcement(t *testing.T) {
	valid := func() map[string]pushapi.Condition {
		return map[string]pushapi.Condition{
			"appTypes":     {Matches: []string{"OPENAI_CHATGPT"}},
			"domainScope":  {Matches: []string{"SPECIFIC_DOMAINS"}},
			"loginDomains": {Matches: []string{"example.com"}, Action: "INCLUDE"},
			"profileScope": {Matches: []string{"ALL"}},
		}
	}

	for _, tc := range []struct {
		name   string
		change func(map[string]pushapi.Condition)
		// want is a fragment of the one violation's summary, or "" for none.
		want, criterion, value string
	}{
		{name: "valid", change: func(map[string]pushapi.Condition) {}},
		{
			name:   "no app types",
			change: func(c map[string]pushapi.Condition) { delete(c, "appTypes") },
			want:   "`criteria.app_types` is missing",
		},
		{
			// Without a scope there is nothing to hold the login domains
			// against, so only the missing scope is reported.
			name:   "no domain scope",
			change: func(c map[string]pushapi.Condition) { delete(c, "domainScope") },
			want:   "`criteria.domain_scope` is missing",
		},
		{
			name:   "specific domains without login domains",
			change: func(c map[string]pushapi.Condition) { delete(c, "loginDomains") },
			want:   "`criteria.login_domains` is required",
		},
		{
			name: "login domains with company domains",
			change: func(c map[string]pushapi.Condition) {
				c["domainScope"] = pushapi.Condition{Matches: []string{"COMPANY_DOMAINS"}}
			},
			want: "`criteria.login_domains` must not be set",
		},
		{
			name: "an app newer than the provider",
			change: func(c map[string]pushapi.Condition) {
				c["appTypes"] = pushapi.Condition{Matches: []string{"OPENAI_CHATGPT", "SOME_NEW_APP"}}
			},
			want: "Not one of the values", criterion: "app_types", value: "SOME_NEW_APP",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			crit := valid()
			tc.change(crit)
			got := checkRules(AccountConditionEnforcement, []pushapi.Rule{{
				Name: "r", Enabled: true, Mode: "MONITOR", Criteria: crit,
			}})
			if tc.want == "" {
				if len(got) != 0 {
					t.Errorf("violations = %+v, want none", got)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("violations = %+v, want one", got)
			}
			v := got[0]
			if !strings.Contains(v.Summary, tc.want) {
				t.Errorf("summary = %q, want it to contain %q", v.Summary, tc.want)
			}
			if v.Criterion != tc.criterion || v.Value != tc.value {
				t.Errorf("violation names %s %q, want %s %q", v.Criterion, v.Value, tc.criterion, tc.value)
			}
		})
	}
}

// TestCheckRulesMaskPiiWithoutCapture is a rule the console can write: the
// API stores it without maskPii, so it reports nothing to fix.
func TestCheckRulesMaskPiiWithoutCapture(t *testing.T) {
	rules := []pushapi.Rule{{
		Name: "Copy", Enabled: true, Mode: "MONITOR",
		Fields:   map[string]any{"operation": "COPY", "contentCapture": false},
		Criteria: map[string]pushapi.Condition{"urlPatterns": {Matches: []string{"*://example.com/*"}}},
	}}
	if got := checkRules(ClipboardBlocking, rules); len(got) != 0 {
		t.Errorf("got %+v, want nothing", got)
	}
	rules[0].Fields["maskPii"] = true
	if got := checkRules(ClipboardBlocking, rules); len(got) != 1 ||
		!strings.Contains(got[0].Summary, "mask_pii") {
		t.Errorf("got %+v, want mask_pii reported", got)
	}
}

func TestCheckRulesSizes(t *testing.T) {
	extensions := make([]string, 201)
	for i := range extensions {
		extensions[i] = fmt.Sprintf(".x%d", i)
	}
	rules := []pushapi.Rule{{
		Name: strings.Repeat("n", 251), Enabled: true, Mode: "MONITOR",
		Criteria: map[string]pushapi.Condition{
			"fileExtensions": {Matches: extensions},
			"employeeGroups": {Matches: extensions[:50]},
		},
	}}
	got := checkRules(FileDownloadBlocking, rules)
	if len(got) != 2 {
		t.Fatalf("got %+v, want the name and file_extensions", got)
	}
	if !strings.Contains(got[0].Summary, "251 characters") {
		t.Errorf("first violation = %+v, want the name", got[0])
	}
	if got[1].Criterion != "file_extensions" || got[1].Value != "" ||
		!strings.Contains(got[1].Summary, "201 values, more than the 200") {
		t.Errorf("second violation = %+v, want file_extensions over its limit", got[1])
	}
}

// TestCheckRulesText checks that the rule text the plan will reject is
// flagged. Text the API has stored holds its escaped form, which is what an
// adopted configuration would carry.
func TestCheckRulesText(t *testing.T) {
	rules := []pushapi.Rule{{
		Name: "Banner", Enabled: true, Mode: "ACKNOWLEDGE",
		Fields: map[string]any{
			"title":      "Terms &amp; Conditions",
			"subtext":    "Read the terms & conditions",
			"buttonText": "I agree",
		},
	}}
	got := checkRules(AppBanner, rules)
	if len(got) != 1 {
		t.Fatalf("got %d violations, want 1 (the title): %+v", len(got), got)
	}
	if v := got[0]; v.Field != "title" || v.Value != "Terms &amp; Conditions" {
		t.Errorf("reported %s %q, want title", v.Field, v.Value)
	}
}

func TestCheckSizes(t *testing.T) {
	hosts := make([]any, 101)
	for i := range hosts {
		hosts[i] = "example.com"
	}
	got := checkSizes(PhishingToolDetection, 51, map[string]any{"ignoredHosts": hosts})
	if len(got) != 2 {
		t.Fatalf("got %+v, want too many rules and too many ignored hosts", got)
	}
	for i, want := range []string{"51 rules", "globals.ignored_hosts has 101 entries"} {
		if got[i].RuleIndex != -1 || !strings.Contains(got[i].Summary, want) {
			t.Errorf("violation %d = %+v, want a resource-wide %q", i, got[i], want)
		}
	}
	if got := checkSizes(PhishingToolDetection, 50, map[string]any{"ignoredHosts": hosts[:100]}); len(got) != 0 {
		t.Errorf("at the limits: got %+v, want nothing", got)
	}
}
