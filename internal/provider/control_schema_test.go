package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/provider/controlspec"
)

// TestAllControlSchemasAreValid runs the framework's own schema validation over
// every generated schema. It catches the mistakes that are easy to make when a
// schema is built from data — an attribute that is neither optional, required
// nor computed, a default on something that is not computed, a nested type
// mismatch — without needing Terraform or a tenant.
func TestAllControlSchemasAreValid(t *testing.T) {
	ctx := context.Background()

	for _, spec := range controlspec.All {
		t.Run(spec.TypeName, func(t *testing.T) {
			r := newControlResource(spec)()

			var meta resource.MetadataResponse
			r.Metadata(ctx, resource.MetadataRequest{}, &meta)
			if meta.TypeName != spec.ResourceName() {
				t.Errorf("TypeName = %q, want %q", meta.TypeName, spec.ResourceName())
			}

			resp := &resource.SchemaResponse{}
			r.Schema(ctx, resource.SchemaRequest{}, resp)
			if resp.Diagnostics.HasError() {
				t.Fatalf("schema diagnostics: %v", resp.Diagnostics)
			}
			if diags := resp.Schema.ValidateImplementation(ctx); diags.HasError() {
				t.Fatalf("schema is not a valid implementation: %v", diags)
			}

			// The object types used to build values when reading from the API
			// must match the schema, or every read fails at runtime with a type
			// error rather than at build time.
			rulesAttr, ok := resp.Schema.Attributes["rules"]
			if !ok {
				t.Fatal("rules attribute missing")
			}
			wantType := types.ListType{ElemType: ruleObjectType(spec)}
			if got := rulesAttr.GetType(); !got.Equal(wantType) {
				t.Errorf("rules schema type and ruleObjectType disagree:\n schema: %v\n built:  %v",
					got, wantType)
			}

			if len(spec.Globals) > 0 {
				globalsAttr, ok := resp.Schema.Attributes["globals"]
				if !ok {
					t.Fatal("globals attribute missing on a control that has globals")
				}
				if got := globalsAttr.GetType(); !got.Equal(globalsObjectType(spec)) {
					t.Errorf("globals schema type and globalsObjectType disagree:\n schema: %v\n built:  %v",
						got, globalsObjectType(spec))
				}
			} else if _, present := resp.Schema.Attributes["globals"]; present {
				t.Error("globals attribute present on a control that has none")
			}
		})
	}
}

// TestDefaultsMatchSchemaTypes checks the object defaults, which are built
// separately from the schema and would panic at plan time if their types
// diverged.
func TestDefaultsMatchSchemaTypes(t *testing.T) {
	for _, spec := range controlspec.All {
		t.Run(spec.TypeName, func(t *testing.T) {
			if len(spec.Criteria) > 0 && !spec.CriteriaRequired {
				got := defaultCriteria(spec)
				if !got.Type(context.Background()).Equal(criteriaObjectType(spec)) {
					t.Errorf("defaultCriteria type does not match criteriaObjectType")
				}
				// profile_scope must appear in the default with the value the
				// server injects, or an omitted criteria block will not match
				// what comes back.
				if c, ok := spec.Criterion("profile_scope"); ok && c.ServerDefault != "" {
					v, present := got.Attributes()["profile_scope"]
					if !present {
						t.Fatal("profile_scope missing from defaultCriteria")
					}
					sv, ok := v.(types.String)
					if !ok || sv.ValueString() != c.ServerDefault {
						t.Errorf("defaultCriteria profile_scope = %v, want %q", v, c.ServerDefault)
					}
				}
			}
			if len(spec.Globals) > 0 {
				if !defaultGlobals(spec).Type(context.Background()).Equal(globalsObjectType(spec)) {
					t.Error("defaultGlobals type does not match globalsObjectType")
				}
			}
		})
	}
}
