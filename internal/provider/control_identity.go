package provider

import (
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
)

// priorRule is one rule as it exists in prior state: its key, if the
// practitioner set one, the identifier the server assigned it, and the
// employee email addresses its criteria named.
type priorRule struct {
	Key    string
	ID     string
	Emails []string
}

// carryIDs assigns server identifiers from prior state to planned rules.
//
// The API's PUT replaces the whole document: a rule sent with an identifier
// updates that rule in place, a rule sent without one is created. A wrong
// mapping does not fail — the API accepts any assignment — it re-points rule
// identity without any error.
//
// Nothing inside Push refers to a control rule identifier: not findings, not
// the activity log, not reporting, not deep links. Re-pointing one therefore
// changes nothing a tenant can observe through Push itself, and the
// configuration is right either way. What is left is that the identifiers are
// returned by the public API, so a customer's own tooling may key on them, and
// they should not change without a reason.
//
// Names cannot be matched on: the console generates them from a template, so
// duplicates are normal. Keys are exact under reorder, rename, insert and
// delete.
//
// The positional fallback is what makes the first apply after an import work.
// Imported state has no keys — the API does not store them, so a Read cannot
// produce them — and the configuration generated from it is in the same order.
// It extends to keyed rules while prior state carries no keys at all, which is
// the apply that adopts a tenant (adoption guide, step 4): the keys are new
// but the rules are not. Without it nothing matches, every rule is sent
// without an identifier, and the API creates a fresh set and drops the ones
// they replace.
func carryIDs(planned []planRule, prior []priorRule, controlName string) diag.Diagnostics {
	var diags diag.Diagnostics

	// A duplicate key can only come from hand-edited state; first wins, and the
	// duplicate stays available for positional matching.
	byKey := make(map[string]int, len(prior))
	for i, p := range prior {
		if p.Key == "" {
			continue
		}
		if _, seen := byKey[p.Key]; !seen {
			byKey[p.Key] = i
		}
	}

	adopting := len(prior) > 0 && len(byKey) == 0

	consumed := make([]bool, len(prior))

	for i := range planned {
		if planned[i].Key == "" {
			continue
		}
		j, ok := byKey[planned[i].Key]
		if !ok || consumed[j] {
			continue
		}
		planned[i].Rule.ID = prior[j].ID
		consumed[j] = true
	}

	// A prior rule its key owns belongs to that key alone. If the key is gone
	// from the plan, so is the rule: handing its identifier to an unkeyed rule
	// would re-point it just as adopting it for an unmatched new key would,
	// which the fallback is careful not to do. Positional matching therefore
	// draws only on the prior rules no key owns: unkeyed ones, and duplicates
	// of a key already taken.
	for _, j := range byKey {
		consumed[j] = true
	}

	next := 0
	unkeyed := 0
	for i := range planned {
		if planned[i].Key == "" {
			unkeyed++
		} else if !adopting {
			continue
		}
		for next < len(prior) && consumed[next] {
			next++
		}
		if next >= len(prior) {
			continue
		}
		planned[i].Rule.ID = prior[next].ID
		consumed[next] = true
		next++
	}

	// Adoption gets no warning, deliberately: it would fire on every tenant
	// adoption, and what it would warn about has no consequence inside Push.
	// Warn once per control, and only where it can bite — a single unkeyed
	// rule cannot be reordered against anything.
	if unkeyed > 0 && len(planned) > 1 {
		diags.AddAttributeWarning(
			path.Root("rules"),
			"Rules without a key are matched by position",
			fmt.Sprintf(
				"%d of %d rules in pushsecurity_%s have no `key`, so the provider matches them to "+
					"existing rules by position.\n\n"+
					"Reordering, inserting or removing a positionally matched rule moves "+
					"server-side rule identifiers onto different rules. The apply succeeds and "+
					"the resulting configuration is correct — nothing in Push refers to those "+
					"identifiers — but anything of your own that reads them from the API will "+
					"be describing a different rule.\n\n"+
					"Set a stable `key` on every rule to avoid this. Names cannot be used "+
					"instead: they are not unique.",
				unkeyed, len(planned), controlName,
			),
		)
	}

	return diags
}

// keyByID inverts the plan's key assignment so that rulesToState can put keys
// back into state alongside the identifiers the server returned.
func keyByID(planned []planRule, returnedIDs []string) map[string]string {
	out := make(map[string]string, len(planned))
	for i, p := range planned {
		if p.Key == "" {
			continue
		}
		if id := returnedID(planned, returnedIDs, i); id != "" {
			out[id] = p.Key
		}
	}
	return out
}

// emailsByID indexes the email addresses each planned rule named, by the
// identifier the rule ends up with — the same shape as keyByID, and for the
// same reason: what state must hold is not what the API returned.
func emailsByID(planned []planRule, returnedIDs []string) map[string][]string {
	out := make(map[string][]string, len(planned))
	for i, p := range planned {
		if len(p.Emails) == 0 {
			continue
		}
		if id := returnedID(planned, returnedIDs, i); id != "" {
			out[id] = p.Emails
		}
	}
	return out
}

// returnedID is the identifier the API answered with for the planned rule at
// index i.
//
// PUT preserves the order it was sent, which the acceptance tests pin, so that
// is the identifier at the same position in the response. Position is used
// even for a rule that was sent with an identifier: should the response carry
// a different one, keying on the identifier sent would leave the rule's key
// and addresses out of state, and Terraform would report an inconsistent
// result. Only a response with a different number of rules makes position
// meaningless, and then the identifier sent is the best there is.
func returnedID(planned []planRule, returnedIDs []string, i int) string {
	if len(returnedIDs) == len(planned) {
		return returnedIDs[i]
	}
	return planned[i].Rule.ID
}
