package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/provider/controlspec"
	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/pushapi"
)

// TestCheckRulesFindsUnwritableConfiguration uses two app banner rules, mode
// INFORM, each with a title and no subtext. The API returns such rules on read
// and refuses to write them back with
//
//	rules[0]._schema: title and subtext are required for all modes except DO_NOT_SHOW
//
// Predicting that before the first apply is the reason this tool exists.
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

	got := checkRules(controlspec.AppBanner, rules)
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
	if got := checkRules(controlspec.AppBanner, rules); len(got) != 0 {
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
	got := checkRules(controlspec.ClipboardBlocking, missing)
	if len(got) != 1 || !strings.Contains(got[0].Summary, "copy_redacted_button_text") {
		t.Errorf("violations = %+v, want one naming copy_redacted_button_text", got)
	}

	// Supplying it satisfies the constraint.
	ok := missing
	ok[0].Fields["copyRedactedButtonText"] = "Copy redacted"
	if got := checkRules(controlspec.ClipboardBlocking, ok); len(got) != 0 {
		t.Errorf("got %d violations, want none: %+v", len(got), got)
	}
}

func TestCheckRulesCustomDetectionSeverity(t *testing.T) {
	// severity is required for every mode except OFF.
	got := checkRules(controlspec.CustomDetectionRules, []pushapi.Rule{
		{Name: "r", Enabled: true, Mode: "MONITOR"},
	})
	if len(got) != 1 || !strings.Contains(got[0].Summary, "severity") {
		t.Errorf("violations = %+v, want one naming severity", got)
	}

	if got := checkRules(controlspec.CustomDetectionRules, []pushapi.Rule{
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
		spec      controlspec.Spec
		fields    map[string]any
		criterion string // the wire name
		value     string
		warning   bool
	}{
		{
			// Stored without a path, so the API returns it without one.
			name: "download pattern with no path", spec: controlspec.FileDownloadBlocking,
			criterion: "urlPatterns", value: "*://*.anydesk.com",
		},
		{
			// A pattern with a query string is not supported.
			name: "clipboard pattern with a query", spec: controlspec.ClipboardBlocking,
			fields:    map[string]any{"operation": "COPY", "contentCapture": false},
			criterion: "urlPatterns", value: "*://docs.example.com/document?usp=sharing",
		},
		{
			// An inline flag group, which is not supported.
			name: "file name pattern with (?i)", spec: controlspec.FileDownloadBlocking,
			criterion: "fileNamePatterns", value: "(?i)anydesk",
		},
		{
			// Works, but matches every port.
			name: "upload pattern with :443", spec: controlspec.FileUploadBlocking,
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

// TestWriteViolationsCriterionValues checks the report separates what fails
// the first plan from what it only warns about, and explains the patterns
// with no path that tenants commonly hold.
func TestWriteViolationsCriterionValues(t *testing.T) {
	rules := func(urlPatterns ...string) []pushapi.Rule {
		return []pushapi.Rule{{
			Name: "Block remote access tools", Enabled: true, Mode: "MONITOR",
			Criteria: map[string]pushapi.Condition{"urlPatterns": {Matches: urlPatterns}},
		}}
	}
	download := controlspec.FileDownloadBlocking
	upload := controlspec.FileUploadBlocking
	tenant := &tenantSurvey{Controls: []control{
		{Spec: download, Rules: 1, Violations: checkRules(download, rules("*://*.anydesk.com"))},
		{Spec: upload, Rules: 1, Violations: checkRules(upload, rules("*://example.com:443/*"))},
	}}

	var b strings.Builder
	writeViolations(&b, tenant)
	report := b.String()

	errorsAt := strings.Index(report, "will not pass validation")
	warningsAt := strings.Index(report, "will plan with a warning")
	if errorsAt < 0 || warningsAt < errorsAt {
		t.Fatalf("want an errors section followed by a warnings section:\n%s", report)
	}
	errs, warns := report[errorsAt:warningsAt], report[warningsAt:]

	for _, want := range []string{
		"The API adds /* to a pattern written without a path",
		"pushsecurity_file_download_blocking",
		`rules[0] "Block remote access tools" (mode MONITOR), url_patterns "*://*.anydesk.com": `,
	} {
		if !strings.Contains(errs, want) {
			t.Errorf("errors section lacks %q:\n%s", want, errs)
		}
	}
	if strings.Contains(errs, "pushsecurity_file_upload_blocking") {
		t.Errorf("a warning is listed among the errors:\n%s", errs)
	}

	if want := `url_patterns "*://example.com:443/*": `; !strings.Contains(warns, want) {
		t.Errorf("warnings section lacks %q:\n%s", want, warns)
	}
	if strings.Contains(warns, "pushsecurity_file_download_blocking") {
		t.Errorf("an error is listed among the warnings:\n%s", warns)
	}

	// A warning alone does not stop the first apply, and a value that is not
	// a path-less URL pattern does not need the explanation of those.
	tenant.Controls = tenant.Controls[1:]
	b.Reset()
	writeViolations(&b, tenant)
	report = b.String()
	if !strings.Contains(report, "nothing needs fixing before the\nfirst apply") {
		t.Errorf("with only warnings, the report should say nothing needs fixing:\n%s", report)
	}
	if !strings.Contains(report, "will plan with a warning") {
		t.Errorf("the warning went missing:\n%s", report)
	}
	if strings.Contains(report, "written without a path") {
		t.Errorf("explains path-less patterns when there are none:\n%s", report)
	}
}

func TestPathless(t *testing.T) {
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
		if got := pathless(ruleViolation{Criterion: tc.criterion, Value: tc.value}); got != tc.want {
			t.Errorf("pathless(%s %q) = %v, want %v", tc.criterion, tc.value, got, tc.want)
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
			got := checkRules(controlspec.AccountConditionEnforcement, []pushapi.Rule{{
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

func TestSlugify(t *testing.T) {
	for _, tc := range []struct{ in, file, ident string }{
		{"Torrent website visit", "torrent-website-visit", "torrent_website_visit"},
		{"OAuth consent abuse", "oauth-consent-abuse", "oauth_consent_abuse"},
		{"  Padded  Name  ", "padded-name", "padded_name"},
		{"Already_underscored", "already-underscored", "already_underscored"},
		// A Terraform resource label may not start with a digit.
		{"2FA bypass", "2fa-bypass", "d_2fa_bypass"},
		{"???", "detection", "detection"},
	} {
		t.Run(tc.in, func(t *testing.T) {
			if got := slugify(tc.in); got != tc.file {
				t.Errorf("slugify(%q) = %q, want %q", tc.in, got, tc.file)
			}
			if got := identifier(slugify(tc.in)); got != tc.ident {
				t.Errorf("identifier(slugify(%q)) = %q, want %q", tc.in, got, tc.ident)
			}
		})
	}
}

// TestCheckRulesText checks the report flags the rule text the plan will
// reject. Text the API has stored holds its escaped form, which is what an
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
	got := checkRules(controlspec.AppBanner, rules)
	if len(got) != 1 {
		t.Fatalf("got %d violations, want 1 (the title): %+v", len(got), got)
	}
	if v := got[0]; v.Field != "title" || v.Value != "Terms &amp; Conditions" {
		t.Errorf("reported %s %q, want title", v.Field, v.Value)
	}

	tenant := &tenantSurvey{Controls: []control{
		{Spec: controlspec.AppBanner, Rules: 1, Violations: got},
	}}
	var b strings.Builder
	writeViolations(&b, tenant)
	for _, want := range []string{
		"Message text is checked too",
		`rules[0] "Banner" (mode ACKNOWLEDGE), title "Terms &amp; Conditions": Text must not contain &`,
	} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("report lacks %q:\n%s", want, b.String())
		}
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
	if got := checkRules(controlspec.ClipboardBlocking, rules); len(got) != 0 {
		t.Errorf("got %+v, want nothing", got)
	}
	rules[0].Fields["maskPii"] = true
	if got := checkRules(controlspec.ClipboardBlocking, rules); len(got) != 1 ||
		!strings.Contains(got[0].Summary, "mask_pii") {
		t.Errorf("got %+v, want mask_pii reported", got)
	}
}

func TestCheckSizes(t *testing.T) {
	hosts := make([]any, 101)
	for i := range hosts {
		hosts[i] = "example.com"
	}
	got := checkSizes(controlspec.PhishingToolDetection, 51, map[string]any{"ignoredHosts": hosts})
	if len(got) != 2 {
		t.Fatalf("got %+v, want too many rules and too many ignored hosts", got)
	}
	for i, want := range []string{"51 rules", "globals.ignored_hosts has 101 entries"} {
		if got[i].RuleIndex != -1 || !strings.Contains(got[i].Summary, want) {
			t.Errorf("violation %d = %+v, want a resource-wide %q", i, got[i], want)
		}
	}
	if got := checkSizes(controlspec.PhishingToolDetection, 50, map[string]any{"ignoredHosts": hosts[:100]}); len(got) != 0 {
		t.Errorf("at the limits: got %+v, want nothing", got)
	}

	tenant := &tenantSurvey{Controls: []control{
		{Spec: controlspec.PhishingToolDetection, Rules: 51, Violations: got},
	}}
	tenant.Controls[0].Violations = checkSizes(controlspec.PhishingToolDetection, 51, nil)
	var b strings.Builder
	writeViolations(&b, tenant)
	if want := "   pushsecurity_phishing_tool_detection\n     51 rules, more than the 50 the API accepts\n"; !strings.Contains(b.String(), want) {
		t.Errorf("report lacks %q:\n%s", want, b.String())
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
	got := checkRules(controlspec.FileDownloadBlocking, rules)
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

// TestSurveyReadsAccountConditionEnforcement runs the survey against a fake API
// whose only configuration is one account condition enforcement rule: the
// control is read from its own endpoint, gets an import block, and has its
// rule checked like every other control's.
func TestSurveyReadsAccountConditionEnforcement(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/controls/accountConditionEnforcement/configuration":
			// SPECIFIC_DOMAINS without the login domains it needs.
			_, _ = io.WriteString(w, `{"globals": {}, "rules": [{
				"id": "r1", "name": "Personal logins", "enabled": true, "mode": "MONITOR",
				"criteria": {
					"appTypes": {"matches": ["OPENAI_CHATGPT"]},
					"domainScope": {"matches": ["SPECIFIC_DOMAINS"]},
					"profileScope": {"matches": ["ALL"]}
				}
			}]}`)
		case "/v1/controls/customDetections", "/v1/controls/blockedUrls":
			_, _ = io.WriteString(w, `{"result": []}`)
		default:
			_, _ = io.WriteString(w, `{"globals": {}, "rules": []}`)
		}
	}))
	t.Cleanup(srv.Close)

	client, err := pushapi.New(srv.URL, "test-key")
	if err != nil {
		t.Fatal(err)
	}
	opts := options{outDir: t.TempDir(), detectionsDir: "detections", skipEmpty: true}
	got, err := survey(context.Background(), client, opts)
	if err != nil {
		t.Fatal(err)
	}

	if len(got.Controls) != 1 {
		t.Fatalf("surveyed %d controls with rules, want 1: %+v", len(got.Controls), got.Controls)
	}
	c := got.Controls[0]
	if c.Spec.ResourceName() != "pushsecurity_account_condition_enforcement" || c.Rules != 1 {
		t.Errorf("surveyed %s with %d rules, want pushsecurity_account_condition_enforcement with 1",
			c.Spec.ResourceName(), c.Rules)
	}
	if len(c.Violations) != 1 || !strings.Contains(c.Violations[0].Summary, "criteria.login_domains") {
		t.Errorf("violations = %+v, want one naming criteria.login_domains", c.Violations)
	}

	if err := write(got, opts); err != nil {
		t.Fatal(err)
	}
	imports, err := os.ReadFile(filepath.Join(opts.outDir, "imports.tf"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(imports), "to       = pushsecurity_account_condition_enforcement.this") {
		t.Errorf("imports.tf has no import block for the control:\n%s", imports)
	}
}

// TestWriteGivesCollidingDetectionsTheirOwnFiles: names that slugify alike
// still get a file and an import label each, so neither detection's logic
// overwrites the other's.
func TestWriteGivesCollidingDetectionsTheirOwnFiles(t *testing.T) {
	tenant := &tenantSurvey{Detections: []detection{
		{EventType: "CUSTOM_ONE", Name: "Foo Bar", Logic: "one"},
		{EventType: "CUSTOM_TWO", Name: "Foo-Bar", Logic: "two"},
		{EventType: "CUSTOM_THREE", Name: "???", Logic: "three"},
		{EventType: "CUSTOM_FOUR", Name: "!!!", Logic: "four"},
		// Labels collide too: "2fa" becomes d_2fa, as "D 2FA" does.
		{EventType: "CUSTOM_FIVE", Name: "D 2FA", Logic: "five"},
		{EventType: "CUSTOM_SIX", Name: "2FA", Logic: "six"},
	}}
	opts := options{outDir: t.TempDir(), detectionsDir: "detections"}
	if err := write(tenant, opts); err != nil {
		t.Fatal(err)
	}

	files := map[string]bool{}
	labels := map[string]bool{}
	for _, d := range tenant.Detections {
		if files[d.LogicFile] {
			t.Errorf("%s shares the file %s", d.EventType, d.LogicFile)
		}
		files[d.LogicFile] = true
		if labels[d.Label] {
			t.Errorf("%s shares the label %s", d.EventType, d.Label)
		}
		labels[d.Label] = true

		got, err := os.ReadFile(filepath.Join(opts.outDir, d.LogicFile))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != d.Logic {
			t.Errorf("%s holds %q, want %s's logic %q", d.LogicFile, got, d.EventType, d.Logic)
		}
	}

	imports, err := os.ReadFile(filepath.Join(opts.outDir, "imports.tf"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"pushsecurity_custom_detection.foo_bar\n", "pushsecurity_custom_detection.foo_bar_2\n",
		"pushsecurity_custom_detection.detection\n", "pushsecurity_custom_detection.detection_2\n",
		"pushsecurity_custom_detection.d_2fa\n", "pushsecurity_custom_detection.d_2fa_2\n"} {
		if !strings.Contains(string(imports), want) {
			t.Errorf("imports.tf has no %q:\n%s", strings.TrimSpace(want), imports)
		}
	}
}

// TestSurveySkipEmptyKeepsControlsWithGlobals: a control with no rules but
// with control-wide settings still has configuration to adopt, so
// -skip-empty keeps it. One with neither is skipped.
func TestSurveySkipEmptyKeepsControlsWithGlobals(t *testing.T) {
	spec := findGlobalsSpec(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case spec.Path():
			_, _ = fmt.Fprintf(w, `{"globals": {%q: [%s]}, "rules": []}`,
				spec.Globals[0].APIName, globalItem(spec.Globals[0]))
		case "/v1/controls/customDetections", "/v1/controls/blockedUrls":
			_, _ = io.WriteString(w, `{"result": []}`)
		default:
			_, _ = io.WriteString(w, `{"globals": {}, "rules": []}`)
		}
	}))
	t.Cleanup(srv.Close)

	client, err := pushapi.New(srv.URL, "test-key")
	if err != nil {
		t.Fatal(err)
	}
	opts := options{outDir: t.TempDir(), detectionsDir: "detections", skipEmpty: true}
	got, err := survey(context.Background(), client, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Controls) != 1 || got.Controls[0].Spec.APIName != spec.APIName {
		t.Errorf("surveyed %+v, want only %s", got.Controls, spec.APIName)
	}
}

// findGlobalsSpec returns a control with control-wide settings.
func findGlobalsSpec(t *testing.T) controlspec.Spec {
	t.Helper()
	for _, s := range controlspec.All {
		if len(s.Globals) > 0 {
			return s
		}
	}
	t.Fatal("no control has globals")
	return controlspec.Spec{}
}

// globalItem is one JSON entry for a control-wide list.
func globalItem(g controlspec.Global) string {
	if g.Type == controlspec.GlobalObjectList {
		return `{}`
	}
	return `"example.com"`
}

// fakeTenant serves a tenant whose controls are all empty, with one custom
// detection and two blocked URLs.
func fakeTenant(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/controls/customDetections":
			_, _ = io.WriteString(w, `{"result": [{"detectionEventType": "CUSTOM_MY_DETECTION", "detectionEventName": "My detection"}]}`)
		case "/v1/controls/customDetections/CUSTOM_MY_DETECTION":
			_, _ = io.WriteString(w, `{"detectionEventType": "CUSTOM_MY_DETECTION", "detectionEventName": "My detection",
				"detectionLogic": "metadata:\n  name: x\n", "rules": []}`)
		case "/v1/controls/blockedUrls":
			_, _ = io.WriteString(w, `{"result": ["*://a.example.com/*", "*://b.example.com/*"]}`)
		default:
			_, _ = io.WriteString(w, `{"globals": {}, "rules": []}`)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestRunRequiresAPIKey(t *testing.T) {
	t.Setenv(envAPIKey, "")
	out := t.TempDir()
	err := run([]string{"-out", out}, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), envAPIKey) {
		t.Fatalf("err = %v, want one naming %s", err, envAPIKey)
	}
	if _, err := os.Stat(filepath.Join(out, "imports.tf")); !os.IsNotExist(err) {
		t.Errorf("imports.tf was written without a key: %v", err)
	}
}

func TestRunRejectsPositionalArguments(t *testing.T) {
	// Parsing stops at "extra", so without the check -skip-empty=false would be
	// dropped and the run would go ahead without it. The key is unset to show
	// the arguments are refused before anything else is looked at.
	t.Setenv(envAPIKey, "")
	var stderr bytes.Buffer
	err := run([]string{"-out", t.TempDir(), "extra", "-skip-empty=false"}, io.Discard, &stderr)
	if err == nil || !strings.Contains(err.Error(), `unexpected argument "extra"`) {
		t.Fatalf("err = %v, want one naming the argument", err)
	}
	if !strings.Contains(stderr.String(), "-detections-dir") {
		t.Errorf("usage not printed:\n%s", stderr.String())
	}
}

// TestRunWritesEverything runs the whole tool against fakeTenant with every
// flag set: -skip-empty=false keeps the empty controls, and -detections-dir
// moves the detection logic.
func TestRunWritesEverything(t *testing.T) {
	srv := fakeTenant(t)
	t.Setenv(envAPIKey, "test-key")
	t.Setenv(envBaseURL, srv.URL)
	out := t.TempDir()

	var stdout, stderr bytes.Buffer
	args := []string{"-out", out, "-detections-dir", "logic", "-skip-empty=false"}
	if err := run(args, &stdout, &stderr); err != nil {
		t.Fatalf("run: %v\n%s", err, stderr.String())
	}

	logic, err := os.ReadFile(filepath.Join(out, "logic", "my-detection.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(logic) != "metadata:\n  name: x\n" {
		t.Errorf("logic file holds %q, want the logic byte for byte", logic)
	}

	imports, err := os.ReadFile(filepath.Join(out, "imports.tf"))
	if err != nil {
		t.Fatal(err)
	}
	// Every control, empty or not, plus the detection and the blocked URLs.
	if got, want := strings.Count(string(imports), "import {"), len(controlspec.All)+2; got != want {
		t.Errorf("imports.tf has %d import blocks, want %d:\n%s", got, want, imports)
	}
	for _, want := range []string{
		"to       = pushsecurity_custom_detection.my_detection\n",
		`id       = "CUSTOM_MY_DETECTION"`,
		"logic extracted to logic/my-detection.yaml",
		"to       = pushsecurity_blocked_urls.this\n",
	} {
		if !strings.Contains(string(imports), want) {
			t.Errorf("imports.tf has no %q:\n%s", want, imports)
		}
	}

	for _, want := range []string{
		"Wrote " + filepath.Join(out, "imports.tf") + "\n",
		fmt.Sprintf("%d control(s) with configuration, 0 rule(s) in total:", len(controlspec.All)),
		"CUSTOM_MY_DETECTION",
		"logic -> logic/my-detection.yaml",
		"2 blocked URL(s).",
		"nothing needs fixing before the\nfirst apply",
		"Next steps:",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("report has no %q:\n%s", want, stdout.String())
		}
	}
}

func TestWriteImports(t *testing.T) {
	tenant := &tenantSurvey{
		Controls: []control{{Spec: controlspec.AppBanner, Rules: 3}},
		Detections: []detection{{
			EventType: "CUSTOM_X", Name: "X", Rules: 1,
			LogicFile: "detections/x.yaml", Label: "x",
		}},
	}
	var b bytes.Buffer
	if err := writeImports(&b, tenant); err != nil {
		t.Fatal(err)
	}
	got := b.String()
	for _, want := range []string{
		"# 3 rule(s)\nimport {\n  to       = " + controlspec.AppBanner.ResourceName() +
			".this\n  provider = pushsecurity\n  id       = \"default\"\n}\n",
		"# \"X\", 1 rule(s); logic extracted to detections/x.yaml\nimport {\n  to       = pushsecurity_custom_detection.x\n" +
			"  provider = pushsecurity\n  id       = \"CUSTOM_X\"\n}\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("imports.tf has no\n%s\nin\n%s", want, got)
		}
	}
	// No blocked URLs, so nothing to import for them.
	if strings.Contains(got, "pushsecurity_blocked_urls") {
		t.Errorf("imports.tf imports blocked URLs the tenant does not have:\n%s", got)
	}
}

func TestReportWithNothingToAdopt(t *testing.T) {
	var b bytes.Buffer
	if err := report(&b, &tenantSurvey{}, options{outDir: "out"}); err != nil {
		t.Fatal(err)
	}
	got := b.String()
	for _, want := range []string{"0 control(s) with configuration, 0 rule(s) in total:\n  (none)\n", "Next steps:"} {
		if !strings.Contains(got, want) {
			t.Errorf("report has no %q:\n%s", want, got)
		}
	}
	for _, unwanted := range []string{"custom detection(s)", "blocked URL(s)"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("report mentions %q for a tenant without any:\n%s", unwanted, got)
		}
	}
}

func TestSurveyReportsRefusedCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"message": "Unauthorized"}`)
	}))
	t.Cleanup(srv.Close)
	client, err := pushapi.New(srv.URL, "test-key")
	if err != nil {
		t.Fatal(err)
	}

	_, err = survey(context.Background(), client, options{skipEmpty: true})
	if !pushapi.Unauthorized(err) {
		t.Fatalf("err = %v, want the 401", err)
	}
	if want := "reading " + controlspec.All[0].APIName + ":"; !strings.Contains(err.Error(), want) {
		t.Errorf("err = %v, want it to say what was being read", err)
	}
}

func TestSurveyReportsMissingDetection(t *testing.T) {
	// The index names a detection that cannot then be read.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/controls/customDetections":
			_, _ = io.WriteString(w, `{"result": [{"detectionEventType": "CUSTOM_GONE", "detectionEventName": "Gone"}]}`)
		case "/v1/controls/customDetections/CUSTOM_GONE":
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"message": "Not Found"}`)
		default:
			_, _ = io.WriteString(w, `{"globals": {}, "rules": []}`)
		}
	}))
	t.Cleanup(srv.Close)
	client, err := pushapi.New(srv.URL, "test-key")
	if err != nil {
		t.Fatal(err)
	}

	_, err = survey(context.Background(), client, options{skipEmpty: true})
	if !pushapi.NotFound(err) {
		t.Fatalf("err = %v, want the 404", err)
	}
	if !strings.Contains(err.Error(), "reading custom detection CUSTOM_GONE:") {
		t.Errorf("err = %v, want it to name the detection", err)
	}
}
