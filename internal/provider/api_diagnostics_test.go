package provider

import (
	"reflect"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"

	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/provider/controlspec"
	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/pushapi"
)

// A rejected write has to point at the attribute that caused it. Anchoring
// everything to `rules` sends the practitioner to the wrong place: a
// detectionLogic rejection, for one, belongs on detection_logic, not on the
// rules list.
func TestAttributeForFieldError(t *testing.T) {
	attrs := customDetectionAttrNames()

	for _, tc := range []struct {
		name  string
		field pushapi.FieldError
		want  path.Path
		ok    bool
	}{
		{
			name:  "rule-scoped schema error",
			field: pushapi.FieldError{Path: []string{"rules", "0"}, Field: "_schema", Message: "x"},
			want:  path.Root("rules").AtListIndex(0),
			ok:    true,
		},
		{
			name:  "rule-scoped field error",
			field: pushapi.FieldError{Path: []string{"rules", "2"}, Field: "severity", Message: "x"},
			want:  path.Root("rules").AtListIndex(2).AtName("severity"),
			ok:    true,
		},
		{
			// Not a rule field, so it must not be anchored to the rules list.
			name:  "detection logic",
			field: pushapi.FieldError{Field: "detectionLogic", Message: "metadata is required"},
			want:  path.Root("detection_logic"),
			ok:    true,
		},
		{
			name:  "detection name",
			field: pushapi.FieldError{Field: "detectionEventName", Message: "x"},
			want:  path.Root("name"),
			ok:    true,
		},
		{
			name:  "unknown wire name has no attribute",
			field: pushapi.FieldError{Field: "somethingElse", Message: "x"},
			ok:    false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := attributeForFieldError(tc.field, attrs)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v (path %s)", ok, tc.ok, got)
			}
			if ok && !got.Equal(tc.want) {
				t.Errorf("path = %s, want %s", got, tc.want)
			}
		})
	}
}

// findSpec locates a spec by its Terraform type name.
func findSpec(t *testing.T, typeName string) controlspec.Spec {
	t.Helper()
	for _, s := range controlspec.All {
		if s.TypeName == typeName {
			return s
		}
	}
	t.Fatalf("no spec named %q", typeName)
	return controlspec.Spec{}
}

func TestAttributeForFieldErrorOnControls(t *testing.T) {
	// A globals rejection must point at globals, and a rule field at that
	// field, using the control's own attribute names.
	r := &controlResource{spec: findSpec(t, "cloned_login_page_detection")}
	attrs := r.attrNames()

	got, ok := attributeForFieldError(
		pushapi.FieldError{Path: []string{"globals"}, Field: "ignoredHosts", Message: "bad host"}, attrs)
	if !ok || !got.Equal(path.Root("globals").AtName("ignored_hosts")) {
		t.Errorf("globals error mapped to %s (ok=%v), want globals.ignored_hosts", got, ok)
	}

	got, ok = attributeForFieldError(
		pushapi.FieldError{Path: []string{"globals"}, Field: "_schema", Message: "x"}, attrs)
	if !ok || !got.Equal(path.Root("globals")) {
		t.Errorf("globals schema error mapped to %s (ok=%v), want globals", got, ok)
	}

	got, ok = attributeForFieldError(
		pushapi.FieldError{Path: []string{"rules", "1"}, Field: "ignoreButtonText", Message: "x"}, attrs)
	if !ok || !got.Equal(path.Root("rules").AtListIndex(1).AtName("ignore_button_text")) {
		t.Errorf("rule field error mapped to %s (ok=%v)", got, ok)
	}
}

func TestAddFieldErrorsDetail(t *testing.T) {
	// The detail leads with where the error is, and an error with nowhere to
	// point at is reported as its message alone rather than behind a stray
	// colon.
	var diags diag.Diagnostics
	addFieldErrors(&diags, "rejected", []pushapi.FieldError{
		{Path: []string{"rules", "0"}, Field: "severity", Message: "is required"},
		{Message: "the document is invalid"},
		{Field: "_schema", Message: "the detection is invalid"},
	}, customDetectionAttrNames())

	var got []string
	for _, d := range diags {
		got = append(got, d.Detail())
	}
	want := []string{"rules[0].severity: is required", "the document is invalid", "the detection is invalid"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("details = %q, want %q", got, want)
	}
}
