package provider

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/pushapi"
)

// What the merge resources have in common: turning pairs of addresses into
// merge calls, and confirming each one before reporting it done.
//
// The endpoint answers 200 for a secondary identifier that has already been
// merged away and for one that never existed, so the response does not say
// whether anything was merged. Every merge is therefore confirmed by reading
// the secondary back: it must be gone. That is the observable consequence a
// merge always has.

// performMerges merges each match's secondary into its primary, grouping by
// primary so that one person's aliases cost one request per five addresses.
//
// Returns the matches it confirmed. A match whose secondary still exists
// afterwards is reported as an error and left out.
func performMerges(
	ctx context.Context,
	client *pushapi.Client,
	resolver *employeeResolver,
	matches []aliasMatch,
	diags *diag.Diagnostics,
) []aliasMatch {
	if len(matches) == 0 {
		return nil
	}

	byPrimary := map[string][]aliasMatch{}
	order := []string{}
	for _, m := range matches {
		if _, seen := byPrimary[m.PrimaryID]; !seen {
			order = append(order, m.PrimaryID)
		}
		byPrimary[m.PrimaryID] = append(byPrimary[m.PrimaryID], m)
	}

	var done []aliasMatch
	for _, primaryID := range order {
		group := byPrimary[primaryID]
		ids := make([]string, 0, len(group))
		for _, m := range group {
			ids = append(ids, m.SecondaryID)
		}

		tflog.Debug(ctx, "merging employees", map[string]any{
			"primary":     group[0].PrimaryEmail,
			"secondaries": len(ids),
		})

		if _, err := client.MergeEmployees(ctx, primaryID, ids); err != nil {
			addMergeAPIError(diags, group[0].PrimaryEmail, err)
			continue
		}

		for _, m := range group {
			// The merge has happened only if the secondary has stopped
			// existing. Otherwise the request was accepted but not acted on,
			// and reporting success would record a merge that did not happen.
			if _, err := client.GetEmployee(ctx, m.SecondaryID); err == nil {
				diags.AddError(
					"Merge did not take effect",
					fmt.Sprintf("%s still exists as a separate employee after being merged into %s.\n\n"+
						"The provider confirms every merge by reading the secondary back, and "+
						"this one is still there. Check the employee in the Push console before "+
						"trying again.",
						m.SecondaryEmail, m.PrimaryEmail),
				)
				continue
			} else if !pushapi.NotFound(err) {
				addMergeAPIError(diags, m.SecondaryEmail, err)
				continue
			}

			// The record is gone, so anything cached about it is now stale.
			resolver.Forget(m.SecondaryID, m.SecondaryEmail)
			done = append(done, m)
		}
	}
	return done
}

func addMergeAPIError(diags *diag.Diagnostics, subject string, err error) {
	if fields, ok := pushapi.Validation(err); ok && len(fields) > 0 {
		addFieldErrors(diags, "Push API rejected the merge", fields, map[string]string{
			"email": "secondary_emails",
		})
		return
	}
	addRequestFailure(diags, fmt.Sprintf("merge %q", subject), err)
}

// emailShape is the weakest check worth making on an address: something, an @,
// something with a dot in it. The tenant is the authority on the rest.
var emailShape = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

// emailLike rejects the values that cannot be an address at all. Anything
// finer belongs to the API, which holds the tenant's actual addresses. The
// merge resources check every address they are given with it, and so does
// pushsecurity_employee.
func emailLike() validator.String {
	return stringvalidator.RegexMatches(
		emailShape,
		"must be an email address",
	)
}

// mergeIrreversibleDetail is the warning every code path that stops managing a
// merge carries. Only an address that had accounts of its own leaves anything
// behind on the primary, and only that can be split out again.
const mergeIrreversibleDetail = "The records stay merged, and Terraform has simply stopped " +
	"tracking them. An address that had accounts of its own stays among the primary's known " +
	"addresses, and can be split out again, through the API's /unmerge endpoint or by Push " +
	"support, as a new employee with a new identifier. An address that had no accounts leaves " +
	"nothing behind to split out."

// stringSet builds a Terraform set from addresses, lower-cased and sorted so
// that the same tenant renders the same way twice.
func stringSet(values []string) (types.Set, diag.Diagnostics) {
	sorted := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, v := range values {
		v = strings.ToLower(strings.TrimSpace(v))
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		sorted = append(sorted, v)
	}
	sort.Strings(sorted)

	elems := make([]attr.Value, 0, len(sorted))
	for _, v := range sorted {
		elems = append(elems, types.StringValue(v))
	}
	return types.SetValue(types.StringType, elems)
}

func matchStrings(matches []aliasMatch) []string {
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, m.String())
	}
	return out
}
