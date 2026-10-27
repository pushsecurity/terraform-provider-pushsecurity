package provider

import (
	"fmt"
	"iter"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/list"

	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/provider/controlspec"
)

// The list resources are what terraform query finds existing configuration
// with, which is how a tenant is adopted: with -generate-config-out, Terraform
// writes a resource block and an import block for each result.
//
// A warning on a result is how a list resource talks to the person running the
// query. Terraform attributes it to the list block, not to the result, and
// folds warnings that share a summary into one. So every warning on a result
// is named after the result it is about; otherwise two detections that both
// warn would show as one warning, about neither in particular.

// nameWarnings prefixes the summary of each warning with name. Errors are
// left alone: the first one ends the query, so there is never a second to
// tell it apart from.
func nameWarnings(name string, diags diag.Diagnostics) diag.Diagnostics {
	out := make(diag.Diagnostics, 0, len(diags))
	for _, d := range diags {
		if d.Severity() != diag.SeverityWarning {
			out = append(out, d)
			continue
		}
		out.AddWarning(name+": "+d.Summary(), d.Detail())
	}
	return out
}

// storedWarnings reports what the first plan of an adopted resource will say
// about the configuration the tenant holds: one warning for what will fail
// plan, and one for what will plan with a warning. Both are warnings here,
// because an error on a result would end the whole query.
func storedWarnings(name string, violations []controlspec.StoredViolation) diag.Diagnostics {
	var diags diag.Diagnostics
	var errs, warns []controlspec.StoredViolation
	for _, v := range violations {
		if v.Warning {
			warns = append(warns, v)
		} else {
			errs = append(errs, v)
		}
	}

	if len(errs) > 0 {
		var b strings.Builder
		b.WriteString("The tenant holds configuration that this provider's checks during plan, " +
			"or the API's own on write, refuse. The configuration generated from it fails plan " +
			"until it is fixed:\n\n")
		writeViolations(&b, errs)
		var notes []string
		if anyViolation(errs, func(v controlspec.StoredViolation) bool { return v.Criterion != "" && v.Value != "" }) {
			notes = append(notes, "terraform plan says why each criterion value is rejected and "+
				"what to write instead.")
		}
		if anyViolation(errs, controlspec.StoredViolation.Pathless) {
			notes = append(notes, "The API adds /* to a URL pattern written without a path, but "+
				"returns a pattern already stored without one as it is, so each of them needs /* "+
				"added. That can change what a rule matches, so check what each one does before "+
				"you apply.")
		}
		if anyViolation(errs, func(v controlspec.StoredViolation) bool { return v.Field != "" }) {
			notes = append(notes, "The API stores &, < and > in a title or button label "+
				"HTML-escaped, so text adopted from the tenant holds &amp; where & was typed. These "+
				"characters are not supported there. Reword it.")
		}
		for _, n := range notes {
			b.WriteString("\n" + n + "\n")
		}
		diags.AddWarning(name+": configuration the first plan will reject", strings.TrimSpace(b.String()))
	}

	if len(warns) > 0 {
		var b strings.Builder
		b.WriteString("Terraform accepts these values, but they do not match the way they read. " +
			"terraform plan explains each one:\n\n")
		writeViolations(&b, warns)
		diags.AddWarning(name+": configuration that plans with a warning", strings.TrimSpace(b.String()))
	}

	return diags
}

// writeViolations lists violations one to a line, each naming the rule and
// the value at fault.
func writeViolations(b *strings.Builder, violations []controlspec.StoredViolation) {
	for _, v := range violations {
		if v.RuleIndex < 0 {
			fmt.Fprintf(b, "  - %s\n", v.Summary)
			continue
		}
		fmt.Fprintf(b, "  - rules[%d] %q (mode %s)", v.RuleIndex, v.RuleName, v.Mode)
		switch at := v.Criterion + v.Field; {
		case at != "" && v.Value != "":
			fmt.Fprintf(b, ", %s %q", at, v.Value)
		case at != "":
			fmt.Fprintf(b, ", %s", at)
		}
		fmt.Fprintf(b, ": %s\n", v.Summary)
	}
}

func anyViolation(violations []controlspec.StoredViolation, match func(controlspec.StoredViolation) bool) bool {
	for _, v := range violations {
		if match(v) {
			return true
		}
	}
	return false
}

// listResult is a stream holding one result.
func listResult(result list.ListResult) iter.Seq[list.ListResult] {
	return func(push func(list.ListResult) bool) { push(result) }
}

// notConfigured is the stream a list resource answers with before the
// provider is configured: one error, which ends the query.
func notConfigured() iter.Seq[list.ListResult] {
	var diags diag.Diagnostics
	diags.AddError("Provider not configured", "The Push API client is unavailable.")
	return list.ListResultsStreamDiagnostics(diags)
}

// counted is n things, in words: "1 rule", "3 rules".
func counted(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}
