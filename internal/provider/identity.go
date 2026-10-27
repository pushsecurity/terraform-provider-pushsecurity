package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/identityschema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Resource identity is what Terraform 1.12 and later import by, with an
// identity attribute in the import block in place of an identifier string,
// and what a list resource hands back for each object it finds. Older
// Terraform does not ask for it, and the resources behave as before.
//
// An identity may not change once stored, except across a replacement or on
// the read straight after an import, and every Read must leave one set, even
// a Read that finds the object gone. So each resource derives its identity
// from what its state already holds and sets it before calling the API.

// singletonID is the identity of every resource there is exactly one of per
// tenant: the control configurations, the blocked URL list and the settings.
// There is nothing to tell them apart by, and the API exposes no tenant
// identifier, but an identity needs a value. It is the same "default" the
// import identifier has always been by convention.
const singletonID = "default"

// singletonIdentitySchema is the identity schema shared by the singletons.
func singletonIdentitySchema(_ context.Context, _ resource.IdentitySchemaRequest, resp *resource.IdentitySchemaResponse) {
	resp.IdentitySchema = identityschema.Schema{
		Attributes: map[string]identityschema.Attribute{
			"id": identityschema.StringAttribute{
				RequiredForImport: true,
				Description: `Always "default": there is one per tenant, so there is ` +
					`nothing to identify. Any value is accepted on import.`,
			},
		},
	}
}

// setSingletonIdentity records a singleton's identity. identity is nil only
// when the framework has not prepared one, which it does for every resource
// that declares an identity schema.
func setSingletonIdentity(ctx context.Context, identity *tfsdk.ResourceIdentity) diag.Diagnostics {
	return setIdentity(ctx, identity, "id", singletonID)
}

// setIdentity sets an identity's one string attribute.
func setIdentity(ctx context.Context, identity *tfsdk.ResourceIdentity, attr, value string) diag.Diagnostics {
	if identity == nil {
		return nil
	}
	return identity.SetAttribute(ctx, path.Root(attr), value)
}

// importIdentifier returns what an import names the object by: the identifier
// string from `terraform import` or an import block's id, or else the given
// attribute of the import block's identity. Empty when neither is given.
func importIdentifier(ctx context.Context, req resource.ImportStateRequest, attr string, diags *diag.Diagnostics) string {
	if req.ID != "" || req.Identity == nil {
		return req.ID
	}
	var v types.String
	diags.Append(req.Identity.GetAttribute(ctx, path.Root(attr), &v)...)
	return v.ValueString()
}
