package provider

import (
	"context"
	"slices"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/list"
	listschema "github.com/hashicorp/terraform-plugin-framework/list/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"

	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/provider/controlspec"
	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/pushapi"
)

// customDetectionListResource lists the tenant's custom detections for
// terraform query.
type customDetectionListResource struct {
	res customDetectionResource
}

var (
	_ list.ListResource              = &customDetectionListResource{}
	_ list.ListResourceWithConfigure = &customDetectionListResource{}
)

func newCustomDetectionListResource() list.ListResource { return &customDetectionListResource{} }

func (l *customDetectionListResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	l.res.Metadata(ctx, req, resp)
}

func (l *customDetectionListResource) ListResourceConfigSchema(_ context.Context, _ list.ListResourceSchemaRequest, resp *list.ListResourceSchemaResponse) {
	resp.Schema = listschema.Schema{
		MarkdownDescription: "Finds the tenant's custom detections, to adopt with " +
			"`terraform query`, in order of detection event type.",
	}
}

func (l *customDetectionListResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	l.res.client, l.res.resolver = providerClients(req.ProviderData, &resp.Diagnostics)
}

func (l *customDetectionListResource) List(ctx context.Context, req list.ListRequest, stream *list.ListResultsStream) {
	if l.res.client == nil {
		stream.Results = notConfigured()
		return
	}

	index, err := l.res.client.ListCustomDetections(ctx)
	if err != nil {
		result := list.ListResult{}
		l.res.addAPIError(&result.Diagnostics, "list", "the custom detections", err)
		stream.Results = list.ListResultsStreamDiagnostics(result.Diagnostics)
		return
	}
	// Sorted, so that the resource labels terraform query generates from the
	// result order stay the same from one run to the next.
	slices.SortFunc(index, func(a, b pushapi.CustomDetectionSummary) int {
		return strings.Compare(a.DetectionEventType, b.DetectionEventType)
	})
	if req.Limit > 0 && int64(len(index)) > req.Limit {
		index = index[:req.Limit]
	}

	stream.Results = func(push func(list.ListResult) bool) {
		for _, summary := range index {
			result := req.NewListResult(ctx)
			result.DisplayName = firstNonEmpty(summary.DetectionEventName, summary.DetectionEventType)
			result.Diagnostics.Append(setDetectionIdentity(ctx, result.Identity, summary.DetectionEventType)...)
			if req.IncludeResource {
				// The index carries identity alone, and there is no expand
				// parameter, so each detection needs its own read. That read
				// is also the only source of its rules, so they are checked
				// only here.
				det, err := l.res.client.GetCustomDetection(ctx, summary.DetectionEventType)
				if pushapi.NotFound(err) {
					// Deleted since the index was read.
					continue
				}
				if err != nil {
					l.res.addAPIError(&result.Diagnostics, "read", summary.DetectionEventType, err)
					push(result)
					return
				}
				result.DisplayName = det.DetectionEventName
				result.Diagnostics.Append(storedWarnings(det.DetectionEventName,
					controlspec.CheckStored(ruleSpec, det.Rules, nil))...)
				result.Diagnostics.Append(nameWarnings(det.DetectionEventName,
					l.res.setState(ctx, result.Resource, det, nil, nil))...)
			}
			if !push(result) {
				return
			}
		}
	}
}
