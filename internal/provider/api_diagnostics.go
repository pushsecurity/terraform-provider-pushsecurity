package provider

import (
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"

	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/pushapi"
)

// attributeForFieldError maps an API validation error onto the configuration
// attribute that caused it.
//
// Anchoring everything to `rules` is tempting and wrong: the API reports
// failures against `detectionLogic`, `detectionEventName` and `globals` too,
// and pointing those at `rules` sends the practitioner to the wrong part of
// their configuration. attrByAPIName supplies the per-resource translation
// from wire names to attribute names.
//
// Returns false when the error does not correspond to a known attribute, in
// which case the caller reports it without one.
func attributeForFieldError(f pushapi.FieldError, attrByAPIName map[string]string) (path.Path, bool) {
	if idx := f.RuleIndex(); idx >= 0 {
		p := path.Root("rules").AtListIndex(idx)
		// "_schema" means the rule as a whole rather than one of its fields.
		if f.Field != "" && f.Field != "_schema" {
			if attr, ok := attrByAPIName[f.Field]; ok {
				return p.AtName(attr), true
			}
		}
		return p, true
	}

	// Globals are attributes of the globals object, not top-level ones. The
	// failing global is the next path segment, or else the field.
	if len(f.Path) > 0 && f.Path[0] == "globals" {
		key := f.Field
		if len(f.Path) > 1 {
			key = f.Path[1]
		}
		p := path.Root("globals")
		if attr, ok := attrByAPIName[key]; ok && key != "globals" {
			p = p.AtName(attr)
		}
		return p, true
	}

	// Errors outside a rule: the failing key is either the top-level field
	// itself, or the first path segment.
	candidates := []string{f.Field}
	if len(f.Path) > 0 {
		candidates = append(candidates, f.Path[0])
	}
	for _, c := range candidates {
		if c == "" || c == "_schema" {
			continue
		}
		if attr, ok := attrByAPIName[c]; ok {
			return path.Root(attr), true
		}
	}
	return path.Empty(), false
}

// addFieldErrors reports API validation failures against the attributes that
// caused them.
func addFieldErrors(diags *diag.Diagnostics, summary string, fields []pushapi.FieldError, attrByAPIName map[string]string) {
	for _, f := range fields {
		// An error against the document as a whole has no path to name.
		detail := f.Message
		if p := f.AttributePath(); p != "" {
			detail = p + ": " + f.Message
		}
		if p, ok := attributeForFieldError(f, attrByAPIName); ok {
			diags.AddAttributeError(p, summary, detail)
			continue
		}
		diags.AddError(summary, detail)
	}
}
