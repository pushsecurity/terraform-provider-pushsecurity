package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/list"
	listschema "github.com/hashicorp/terraform-plugin-framework/list/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/provider/controlspec"
)

// controlListResource lists a control's configuration for terraform query:
// one result when the control holds configuration, none when it is empty. One
// instance per Spec, as for the managed resource.
type controlListResource struct {
	res controlResource
}

var (
	_ list.ListResource              = &controlListResource{}
	_ list.ListResourceWithConfigure = &controlListResource{}
)

func newControlListResource(spec controlspec.Spec) func() list.ListResource {
	return func() list.ListResource { return &controlListResource{res: controlResource{spec: spec}} }
}

// includeEmptyModel is the configuration of a list block for a singleton that
// can be empty.
type includeEmptyModel struct {
	IncludeEmpty types.Bool `tfsdk:"include_empty"`
}

// includeEmptyAttribute is shared by the singletons that can be empty.
func includeEmptyAttribute(what string) listschema.Attribute {
	return listschema.BoolAttribute{
		Optional: true,
		MarkdownDescription: fmt.Sprintf("Return the %s even when it is empty. Defaults to "+
			"`false`: adopting an empty %s makes Terraform its owner, and every apply from then "+
			"on reverts what is configured in the console.", what, what),
	}
}

func (l *controlListResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	l.res.Metadata(ctx, req, resp)
}

func (l *controlListResource) ListResourceConfigSchema(_ context.Context, _ list.ListResourceSchemaRequest, resp *list.ListResourceSchemaResponse) {
	resp.Schema = listschema.Schema{
		MarkdownDescription: fmt.Sprintf("Finds the %s configuration, to adopt with "+
			"`terraform query`. There is one per tenant, so this returns at most one result, "+
			"and none when the control has no rules and no control-wide entries.",
			inSentence(controlName(l.res.spec))),
		Attributes: map[string]listschema.Attribute{
			"include_empty": includeEmptyAttribute("configuration"),
		},
	}
}

func (l *controlListResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	l.res.client, l.res.resolver = providerClients(req.ProviderData, &resp.Diagnostics)
}

func (l *controlListResource) List(ctx context.Context, req list.ListRequest, stream *list.ListResultsStream) {
	if l.res.client == nil {
		stream.Results = notConfigured()
		return
	}

	var cfg includeEmptyModel
	if diags := req.Config.Get(ctx, &cfg); diags.HasError() {
		stream.Results = list.ListResultsStreamDiagnostics(diags)
		return
	}

	stored, err := l.res.get(ctx)
	if err != nil {
		result := list.ListResult{}
		l.res.addAPIError(&result.Diagnostics, "read", err)
		stream.Results = list.ListResultsStreamDiagnostics(result.Diagnostics)
		return
	}
	if !cfg.IncludeEmpty.ValueBool() && len(stored.Rules) == 0 && !controlspec.HasGlobals(l.res.spec, stored.Globals) {
		stream.Results = list.NoListResults
		return
	}

	name := controlName(l.res.spec)
	result := req.NewListResult(ctx)
	result.DisplayName = fmt.Sprintf("%s (%s)", name, counted(len(stored.Rules), "rule"))
	result.Diagnostics.Append(setSingletonIdentity(ctx, result.Identity)...)
	// From what was read, so that a query without include_resource reports
	// it too.
	result.Diagnostics.Append(storedWarnings(name,
		controlspec.CheckStored(l.res.spec, stored.Rules, stored.Globals))...)
	if req.IncludeResource {
		// The state an import produces: no keys, since the API does not store
		// them, and the employee addresses recovered from the tenant.
		result.Diagnostics.Append(nameWarnings(name,
			l.res.setState(ctx, result.Resource, stored, nil, nil))...)
	}
	stream.Results = listResult(result)
}

// controlName is how a control is named to a person: its type name in words,
// for example "File download blocking" or "MFA enforcement".
func controlName(spec controlspec.Spec) string {
	words := strings.Split(spec.TypeName, "_")
	for i, w := range words {
		switch {
		case acronyms[w] != "":
			words[i] = acronyms[w]
		case i == 0:
			words[i] = strings.ToUpper(w[:1]) + w[1:]
		}
	}
	return strings.Join(words, " ")
}

// acronyms are the words in control type names that are written in capitals.
var acronyms = map[string]string{"mfa": "MFA", "url": "URL"}

// inSentence is a control's name as it reads mid-sentence: lower case, except
// for an acronym, as in "the MFA enforcement configuration".
func inSentence(name string) string {
	first, _, _ := strings.Cut(name, " ")
	for _, a := range acronyms {
		if first == a {
			return name
		}
	}
	return strings.ToLower(name[:1]) + name[1:]
}
