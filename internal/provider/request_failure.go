package provider

import (
	"errors"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"

	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/pushapi"
)

// addRequestFailure reports a failed request the way every resource words the
// failures it has nothing particular to say about: a refused request, and
// anything else by its HTTP status. what completes "Could not", as in
// `update "CUSTOM_PHISHING"` or `read the settings`.
//
// Each resource first picks out the failures it can say more about, such as a
// validation error it can point at an attribute, and leaves the rest to this.
func addRequestFailure(diags *diag.Diagnostics, what string, err error) {
	if addRefusal(diags, what, err) {
		return
	}
	var apiErr *pushapi.APIError
	summary := "Push API request failed"
	if errors.As(err, &apiErr) {
		summary = fmt.Sprintf("Push API returned HTTP %d", apiErr.StatusCode)
	}
	diags.AddError(summary, fmt.Sprintf("Could not %s: %v", what, err))
}

// addRefusal reports a request the API turned away before it reached an
// endpoint, saying which of the key, the base URL or the provider version to
// look at, and reports whether err was such a refusal. what completes "Could
// not", as for addRequestFailure.
func addRefusal(diags *diag.Diagnostics, what string, err error) bool {
	switch pushapi.Refused(err) {
	case pushapi.KeyRejected:
		diags.AddError("Push API rejected the API key",
			fmt.Sprintf("Could not %s: %v\n\nThe request carried no API key, or a value that is "+
				"not a Push API key. Check PUSH_API_KEY, or api_key in the provider "+
				"configuration.", what, err))
	case pushapi.KeyRefused:
		diags.AddError("Push API refused the API key",
			fmt.Sprintf("Could not %s: %v\n\nThe API at this base URL does not accept the key "+
				"for this request. The key may belong to a different Push environment from "+
				"the one PUSH_BASE_URL names, it may have been disabled or deleted, or it may "+
				"be read-only: a read-only key can serve a plan but not an apply.", what, err))
	case pushapi.NoSuchEndpoint:
		diags.AddError("Push API does not serve this endpoint",
			fmt.Sprintf("Could not %s: %v\n\nThe API at this base URL serves no such path or "+
				"method, so the key was not checked. Check PUSH_BASE_URL, and that this "+
				"version of the provider is one the API supports.", what, err))
	case pushapi.Forbidden:
		diags.AddError("Push API refused the request",
			fmt.Sprintf("Could not %s: %v\n\nThe API at this base URL may not accept the key for "+
				"this request, or may not serve this endpoint. Check PUSH_API_KEY, which must "+
				"have full access for an apply, and PUSH_BASE_URL.", what, err))
	default:
		return false
	}
	return true
}
