package provider

import (
	"testing"

	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/pushapi"
)

// ids is a readable view of what carryIDs assigned, for table assertions. An
// empty string means "no identifier", i.e. the rule will be created.
func ids(planned []planRule) []string {
	out := make([]string, len(planned))
	for i, p := range planned {
		out[i] = p.Rule.ID
	}
	return out
}

func keyed(keys ...string) []planRule {
	out := make([]planRule, len(keys))
	for i, k := range keys {
		out[i] = planRule{Key: k, Rule: pushapi.Rule{Name: k}}
	}
	return out
}

func priors(pairs ...[2]string) []priorRule {
	out := make([]priorRule, len(pairs))
	for i, p := range pairs {
		out[i] = priorRule{Key: p[0], ID: p[1]}
	}
	return out
}

func TestCarryIDsByKey(t *testing.T) {
	for _, tc := range []struct {
		name    string
		planned []planRule
		prior   []priorRule
		want    []string
	}{
		{
			name:    "unchanged",
			planned: keyed("a", "b"),
			prior:   priors([2]string{"a", "id-a"}, [2]string{"b", "id-b"}),
			want:    []string{"id-a", "id-b"},
		},
		{
			// The case the whole mechanism exists for: a reorder must move
			// identifiers with their rules, not with their positions.
			name:    "reorder",
			planned: keyed("b", "a"),
			prior:   priors([2]string{"a", "id-a"}, [2]string{"b", "id-b"}),
			want:    []string{"id-b", "id-a"},
		},
		{
			name:    "insert at front",
			planned: keyed("new", "a", "b"),
			prior:   priors([2]string{"a", "id-a"}, [2]string{"b", "id-b"}),
			want:    []string{"", "id-a", "id-b"},
		},
		{
			name:    "insert in middle",
			planned: keyed("a", "new", "b"),
			prior:   priors([2]string{"a", "id-a"}, [2]string{"b", "id-b"}),
			want:    []string{"id-a", "", "id-b"},
		},
		{
			name:    "delete first",
			planned: keyed("b"),
			prior:   priors([2]string{"a", "id-a"}, [2]string{"b", "id-b"}),
			want:    []string{"id-b"},
		},
		{
			// Renaming a rule must not change its identity; that is the point
			// of keying on something other than the name.
			name:    "rename keeps identity",
			planned: []planRule{{Key: "a", Rule: pushapi.Rule{Name: "totally different"}}},
			prior:   priors([2]string{"a", "id-a"}),
			want:    []string{"id-a"},
		},
		{
			name:    "no prior state creates everything",
			planned: keyed("a", "b"),
			prior:   nil,
			want:    []string{"", ""},
		},
		{
			name:    "replace all keys creates everything",
			planned: keyed("x", "y"),
			prior:   priors([2]string{"a", "id-a"}, [2]string{"b", "id-b"}),
			want:    []string{"", ""},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			diags := carryIDs(tc.planned, tc.prior, "test_control")
			if diags.HasError() {
				t.Fatalf("unexpected errors: %v", diags)
			}
			got := ids(tc.planned)
			if len(got) != len(tc.want) {
				t.Fatalf("got %d ids, want %d", len(got), len(tc.want))
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("ids = %v, want %v", got, tc.want)
					break
				}
			}
		})
	}
}

func TestCarryIDsPositionalFallback(t *testing.T) {
	// Unkeyed rules take prior identifiers in order. This is what makes the
	// first apply after an import a no-op: imported state has no keys and the
	// generated configuration is in the same order.
	planned := []planRule{{}, {}}
	prior := priors([2]string{"", "id-0"}, [2]string{"", "id-1"})

	diags := carryIDs(planned, prior, "test_control")
	if diags.HasError() {
		t.Fatalf("unexpected errors: %v", diags)
	}
	if got := ids(planned); got[0] != "id-0" || got[1] != "id-1" {
		t.Errorf("ids = %v, want [id-0 id-1]", got)
	}
	// And it warns: a later reorder of these moves identifiers between rules,
	// which the API exposes even though nothing in Push reads them.
	if diags.WarningsCount() != 1 {
		t.Errorf("warnings = %d, want 1: %v", diags.WarningsCount(), diags)
	}
}

func TestCarryIDsNoWarningForSingleUnkeyedRule(t *testing.T) {
	// One rule cannot be reordered against anything, so warning would be noise.
	planned := []planRule{{}}
	diags := carryIDs(planned, priors([2]string{"", "id-0"}), "test_control")
	if diags.WarningsCount() != 0 {
		t.Errorf("warnings = %d, want 0: %v", diags.WarningsCount(), diags)
	}
}

func TestCarryIDsMixedKeyedAndUnkeyed(t *testing.T) {
	// Keyed rules claim their identifiers first; unkeyed rules take what is
	// left, in order. Without the two-pass ordering, an unkeyed rule at index 0
	// could steal the identifier belonging to a keyed rule.
	planned := []planRule{{}, {Key: "a"}}
	prior := priors([2]string{"a", "id-a"}, [2]string{"", "id-x"})

	diags := carryIDs(planned, prior, "test_control")
	if diags.HasError() {
		t.Fatalf("unexpected errors: %v", diags)
	}
	got := ids(planned)
	if got[1] != "id-a" {
		t.Errorf("keyed rule got id %q, want id-a", got[1])
	}
	if got[0] != "id-x" {
		t.Errorf("unkeyed rule got id %q, want id-x (the identifier no key claimed)", got[0])
	}
}

func TestCarryIDsDuplicatePriorKey(t *testing.T) {
	// Only reachable through hand-edited state, since the schema rejects
	// duplicate keys in configuration. First wins; the second stays available
	// for positional matching rather than being dropped.
	planned := []planRule{{Key: "a"}, {}}
	prior := priors([2]string{"a", "id-1"}, [2]string{"a", "id-2"})

	if diags := carryIDs(planned, prior, "test_control"); diags.HasError() {
		t.Fatalf("unexpected errors: %v", diags)
	}
	got := ids(planned)
	if got[0] != "id-1" || got[1] != "id-2" {
		t.Errorf("ids = %v, want [id-1 id-2]", got)
	}
}

func TestCarryIDsAdoption(t *testing.T) {
	// Step 4 of the adoption guide: prior state came from an import, so it has
	// identifiers and no keys, and the configuration has since been given
	// keys. Nothing matches by key. Without the fallback to position, every
	// rule would be sent without an identifier and the API would replace the
	// whole document with fresh rules, which the plan does not reveal, since
	// it shows `+ key` either way.
	planned := keyed("a", "b", "c")
	prior := priors([2]string{"", "id-0"}, [2]string{"", "id-1"}, [2]string{"", "id-2"})

	diags := carryIDs(planned, prior, "test_control")
	if diags.HasError() {
		t.Fatalf("unexpected errors: %v", diags)
	}
	got := ids(planned)
	if got[0] != "id-0" || got[1] != "id-1" || got[2] != "id-2" {
		t.Errorf("ids = %v, want [id-0 id-1 id-2]", got)
	}
	// Adoption does not warn: positional matching is only wrong if the rules
	// were reordered in the same change, and nothing in Push refers to a rule
	// identifier, so there is nothing to warn about.
	if diags.WarningsCount() != 0 {
		t.Errorf("warnings = %d, want 0: %v", diags.WarningsCount(), diags)
	}
}

func TestCarryIDsAdoptionSingleRule(t *testing.T) {
	planned := keyed("a")
	diags := carryIDs(planned, priors([2]string{"", "id-0"}), "test_control")
	if got := ids(planned); got[0] != "id-0" {
		t.Errorf("ids = %v, want [id-0]", got)
	}
	if diags.WarningsCount() != 0 {
		t.Errorf("warnings = %d, want 0: %v", diags.WarningsCount(), diags)
	}
}

func TestCarryIDsAdoptionFallbackIsImportOnly(t *testing.T) {
	// The fallback keys off prior state having no keys *at all*. Once any
	// prior rule carries one, state has been through a keyed apply, and a key
	// that matches nothing means a genuinely new rule — which must be created,
	// not pointed at whichever rule happens to sit in that position.
	planned := keyed("a", "new")
	prior := priors([2]string{"a", "id-a"}, [2]string{"b", "id-b"})

	diags := carryIDs(planned, prior, "test_control")
	if diags.HasError() {
		t.Fatalf("unexpected errors: %v", diags)
	}
	got := ids(planned)
	if got[0] != "id-a" {
		t.Errorf("ids[0] = %q, want id-a", got[0])
	}
	if got[1] != "" {
		t.Errorf("ids[1] = %q, want \"\" — a new key must create a rule, not adopt id-b", got[1])
	}
	if diags.WarningsCount() != 0 {
		t.Errorf("warnings = %d, want 0: %v", diags.WarningsCount(), diags)
	}
}

func TestCarryIDsAdoptionWithNoPriorState(t *testing.T) {
	// A create, not an adoption: there is no prior state, so every rule is
	// new. The fallback must not fire and must not warn.
	planned := keyed("a", "b")

	diags := carryIDs(planned, nil, "test_control")
	if got := ids(planned); got[0] != "" || got[1] != "" {
		t.Errorf("ids = %v, want two empty identifiers", got)
	}
	if diags.WarningsCount() != 0 {
		t.Errorf("warnings = %d, want 0: %v", diags.WarningsCount(), diags)
	}
}

func TestKeyByID(t *testing.T) {
	planned := []planRule{
		{Key: "existing", Rule: pushapi.Rule{ID: "id-a"}},
		{Key: "created"},
		{}, // unkeyed: contributes nothing
	}
	// PUT preserves the order it was sent, so a newly created rule is matched
	// to its identifier by position in the response.
	got := keyByID(planned, []string{"id-a", "id-new", "id-other"})

	if got["id-a"] != "existing" {
		t.Errorf("keyByID[id-a] = %q, want existing", got["id-a"])
	}
	if got["id-new"] != "created" {
		t.Errorf("keyByID[id-new] = %q, want created", got["id-new"])
	}
	if _, present := got["id-other"]; present {
		t.Error("an unkeyed rule must not contribute a key")
	}
}

func TestCarryIDsRemovedKeyIsNotReassigned(t *testing.T) {
	// The same principle as the adoption fallback, from the other side. State
	// has been through a keyed apply, and the rule keyed "b" is no longer in
	// the plan, so it is gone. The unkeyed rule in its place is new: taking
	// id-b would point the deleted rule's identifier at a different rule.
	for _, tc := range []struct {
		name  string
		prior []priorRule
		want  []string
	}{
		{
			name:  "only keyed prior rules",
			prior: priors([2]string{"a", "id-a"}, [2]string{"b", "id-b"}),
			want:  []string{"id-a", ""},
		},
		{
			// An unkeyed prior rule is still there to be matched by position.
			name:  "an unkeyed prior rule after the removed one",
			prior: priors([2]string{"a", "id-a"}, [2]string{"b", "id-b"}, [2]string{"", "id-x"}),
			want:  []string{"id-a", "id-x"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			planned := []planRule{{Key: "a"}, {}}
			diags := carryIDs(planned, tc.prior, "test_control")
			if diags.HasError() {
				t.Fatalf("unexpected errors: %v", diags)
			}
			if got := ids(planned); got[0] != tc.want[0] || got[1] != tc.want[1] {
				t.Errorf("ids = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestKeyByIDFollowsTheReturnedIdentifier(t *testing.T) {
	// Should the API answer with an identifier other than the one a rule was
	// sent with, the key and the addresses go with the identifier returned,
	// since that is the one state will hold. Keyed on the one sent, both
	// would be dropped from state and the apply reported as inconsistent.
	planned := []planRule{
		{Key: "kept", Emails: []string{"a@example.com"}, Rule: pushapi.Rule{ID: "id-a"}},
		{Key: "created"},
	}
	returned := []string{"id-other", "id-new"}

	keys := keyByID(planned, returned)
	if keys["id-other"] != "kept" || keys["id-new"] != "created" {
		t.Errorf("keyByID = %v, want id-other: kept and id-new: created", keys)
	}
	if _, present := keys["id-a"]; present {
		t.Errorf("keyByID = %v: the identifier sent is not the one state holds", keys)
	}

	emails := emailsByID(planned, returned)
	if got := emails["id-other"]; len(got) != 1 || got[0] != "a@example.com" {
		t.Errorf("emailsByID = %v, want id-other: [a@example.com]", emails)
	}
}

func TestKeyByIDWithAResponseOfADifferentLength(t *testing.T) {
	// Position means nothing when the response does not hold the rules that
	// were sent, so a rule sent with an identifier keeps its key by that
	// identifier, and a new one has nothing to go on.
	planned := []planRule{
		{Key: "existing", Rule: pushapi.Rule{ID: "id-a"}},
		{Key: "created"},
	}
	got := keyByID(planned, []string{"id-a"})
	if len(got) != 1 || got["id-a"] != "existing" {
		t.Errorf("keyByID = %v, want only id-a: existing", got)
	}
}
