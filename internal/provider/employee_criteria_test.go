package provider

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/provider/controlspec"
	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/pushapi"
)

// criteriaWithEmails builds a `criteria` object naming employees by address,
// as configuration would.
func criteriaWithEmails(t *testing.T, s controlspec.Spec, action string, emails ...string) types.Object {
	t.Helper()

	objType := criteriaObjectType(s)
	vals := make(map[string]attr.Value, len(objType.AttrTypes))
	for name, typ := range objType.AttrTypes {
		if ot, ok := typ.(types.ObjectType); ok {
			vals[name] = types.ObjectNull(ot.AttrTypes)
			continue
		}
		vals[name] = types.StringNull()
	}

	elems := make([]attr.Value, 0, len(emails))
	for _, e := range emails {
		elems = append(elems, types.StringValue(e))
	}
	inner := objType.AttrTypes["employee_ids"].(types.ObjectType).AttrTypes
	vals["employee_ids"] = types.ObjectValueMust(inner, map[string]attr.Value{
		"action":  types.StringValue(action),
		"matches": types.SetValueMust(types.StringType, elems),
	})

	return types.ObjectValueMust(objType.AttrTypes, vals)
}

func matchesOf(t *testing.T, criteria attr.Value) []string {
	t.Helper()
	obj, ok := criteria.(types.Object)
	if !ok {
		t.Fatalf("criteria is %T, want types.Object", criteria)
	}
	cond, ok := obj.Attributes()["employee_ids"].(types.Object)
	if !ok || cond.IsNull() {
		return nil
	}
	return stringCollection(cond.Attributes()["matches"])
}

func TestCriterionResolvesEmailsOnlyForEmployeeIDs(t *testing.T) {
	// Every other criterion already matches on something readable; treating
	// one of them as addresses would corrupt it.
	for _, c := range controlspec.ClipboardBlocking.Criteria {
		want := c.APIName == "employeeIds"
		if got := c.ResolvesEmails(); got != want {
			t.Errorf("%s.ResolvesEmails() = %v, want %v", c.Name, got, want)
		}
	}
}

// TestEmployeeCriterionRoundTrips is the property the whole feature rests on:
// configuration written with addresses, sent as identifiers, must come back as
// the same addresses. Anything else diffs on every plan.
func TestEmployeeCriterionRoundTrips(t *testing.T) {
	spec := controlspec.ClonedLoginPageDetection
	stub := &employeeStub{employees: testEmployees}
	res := testResolver(t, stub)
	ctx := context.Background()

	criteria := criteriaWithEmails(t, spec, "EXCLUDE", "adam@example.com", "jo@example.com")

	api, emails, diags := criteriaToAPI(ctx, spec, res, criteria, 0)
	if diags.HasError() {
		t.Fatalf("criteriaToAPI: %v", diags.Errors())
	}

	// The wire carries identifiers, never addresses.
	sent := api["employeeIds"].Matches
	slices.Sort(sent)
	if !slices.Equal(sent, []string{"id-adam", "id-jo"}) {
		t.Errorf("sent %v, want the resolved identifiers", sent)
	}
	if api["employeeIds"].Action != "EXCLUDE" {
		t.Errorf("action = %q, want EXCLUDE", api["employeeIds"].Action)
	}

	back, diags := criteriaFromAPI(ctx, spec, res, api, emails, "a rule")
	if diags.HasError() {
		t.Fatalf("criteriaFromAPI: %v", diags.Errors())
	}
	if len(diags.Warnings()) != 0 {
		t.Errorf("unexpected warnings: %v", diags.Warnings())
	}

	got := matchesOf(t, back)
	slices.Sort(got)
	if !slices.Equal(got, []string{"adam@example.com", "jo@example.com"}) {
		t.Errorf("round trip produced %v, want the original addresses", got)
	}
}

func TestEmployeeCriterionRoundTripsWithoutPriorState(t *testing.T) {
	// What a refresh does when state holds no addresses yet, as after an
	// import: the identifiers still resolve, so the result is the same.
	spec := controlspec.ClonedLoginPageDetection
	res := testResolver(t, &employeeStub{employees: testEmployees})

	api := map[string]pushapi.Condition{
		"employeeIds": {Action: "EXCLUDE", Matches: []string{"id-adam"}},
	}
	back, diags := criteriaFromAPI(context.Background(), spec, res, api, nil, "a rule")
	if diags.HasError() {
		t.Fatalf("criteriaFromAPI: %v", diags.Errors())
	}
	if got := matchesOf(t, back); !slices.Equal(got, []string{"adam@example.com"}) {
		t.Errorf("got %v, want [adam@example.com]", got)
	}
}

func TestResolveEmailsReportsAMissingAddressAgainstTheAttribute(t *testing.T) {
	// A typo has to name the rule and the address, or a large configuration
	// gives no clue where the problem is.
	res := testResolver(t, &employeeStub{employees: testEmployees})
	at := path.Root("rules").AtListIndex(2).AtName("criteria").
		AtName("employee_ids").AtName("matches")

	_, diags := resolveEmails(context.Background(), res, []string{"typo@example.com"}, at)
	if !diags.HasError() {
		t.Fatal("expected an error for an unknown address")
	}
	err := diags.Errors()[0]
	if err.Summary() != "No such employee" {
		t.Errorf("summary = %q", err.Summary())
	}
	if !strings.Contains(err.Detail(), "typo@example.com") {
		t.Errorf("detail does not name the address: %q", err.Detail())
	}
	if got, ok := err.(interface{ Path() path.Path }); ok && got.Path().String() != at.String() {
		t.Errorf("path = %s, want %s", got.Path(), at)
	}
}

func TestResolveEmailsWithoutAClientIsABug(t *testing.T) {
	// Reported, rather than producing an empty condition, which the API
	// would then reject with something unhelpful.
	_, diags := resolveEmails(context.Background(), nil, []string{"adam@example.com"},
		path.Root("rules"))
	if !diags.HasError() {
		t.Fatal("expected an error when the resolver is absent")
	}
}

func TestEmailsFromIDsKeepsConfiguredAddressForAnOffboardedEmployee(t *testing.T) {
	// The decision this encodes: neither fail the refresh — which would leave
	// no way to see the rule — nor drop the value, which would quietly widen a
	// control meant to exclude someone.
	res := testResolver(t, &employeeStub{employees: testEmployees})

	got, diags := emailsFromIDs(context.Background(), res,
		[]string{"id-adam", "id-departed"},
		[]string{"adam@example.com", "departed@example.com"},
		"cloned_login_page_detection", "Block: contractors")

	if diags.HasError() {
		t.Fatalf("unexpected error: %v", diags.Errors())
	}
	if len(diags.Warnings()) != 1 {
		t.Fatalf("got %d warnings, want 1: %v", len(diags.Warnings()), diags.Warnings())
	}
	w := diags.Warnings()[0]
	if w.Summary() != "Rule names an employee the tenant no longer holds" {
		t.Errorf("summary = %q", w.Summary())
	}
	for _, want := range []string{"id-departed", "departed@example.com", "Block: contractors"} {
		if !strings.Contains(w.Detail(), want) {
			t.Errorf("warning does not mention %q: %s", want, w.Detail())
		}
	}

	slices.Sort(got)
	if !slices.Equal(got, []string{"adam@example.com", "departed@example.com"}) {
		t.Errorf("got %v, want both addresses kept so the plan stays empty", got)
	}
}

func TestEmailsFromIDsWarnsOnImportOfADanglingReference(t *testing.T) {
	// No prior state to recover the address from, so the identifier cannot be
	// represented. It must be reported.
	res := testResolver(t, &employeeStub{employees: testEmployees})

	got, diags := emailsFromIDs(context.Background(), res,
		[]string{"id-adam", "id-departed"}, nil,
		"cloned_login_page_detection", "Block: contractors")

	if len(diags.Warnings()) != 1 {
		t.Fatalf("got %d warnings, want 1", len(diags.Warnings()))
	}
	if !strings.Contains(diags.Warnings()[0].Detail(), "after an import") {
		t.Errorf("warning should explain the import case: %s", diags.Warnings()[0].Detail())
	}
	if !slices.Equal(got, []string{"adam@example.com"}) {
		t.Errorf("got %v, want only the address that resolved", got)
	}
}

func TestEmailsFromIDsKeepsAConsoleSideAdditionVisible(t *testing.T) {
	// Drift and offboarding at once. Returning prior state wholesale would
	// hide the person somebody added in the console.
	res := testResolver(t, &employeeStub{employees: testEmployees})

	got, diags := emailsFromIDs(context.Background(), res,
		[]string{"id-adam", "id-jo", "id-departed"},
		[]string{"adam@example.com", "departed@example.com"},
		"cloned_login_page_detection", "Block: contractors")

	if diags.HasError() {
		t.Fatalf("unexpected error: %v", diags.Errors())
	}
	slices.Sort(got)
	want := []string{"adam@example.com", "departed@example.com", "jo@example.com"}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v — the console addition must survive", got, want)
	}
}

func TestEmailsFromIDsKeepsStateWhenTheEmployeeListCannotBeRead(t *testing.T) {
	// A transient API failure must not rewrite state into something wrong: a
	// refresh that dropped the addresses would show a spurious diff, and the
	// next apply would act on it.
	res := testResolver(t, &employeeStub{employees: testEmployees, fail: true})

	prior := []string{"adam@example.com"}
	got, diags := emailsFromIDs(context.Background(), res, []string{"id-adam"}, prior,
		"cloned_login_page_detection", "a rule")

	if diags.HasError() {
		t.Fatalf("a failed lookup should warn, not error: %v", diags.Errors())
	}
	if len(diags.Warnings()) != 1 {
		t.Fatalf("got %d warnings, want 1", len(diags.Warnings()))
	}
	if !strings.Contains(diags.Warnings()[0].Detail(), "may be stale") {
		t.Errorf("warning should say state was kept: %s", diags.Warnings()[0].Detail())
	}
	if !slices.Equal(got, prior) {
		t.Errorf("got %v, want prior state %v", got, prior)
	}
}

// employeeMatchesValidators runs the schema validators on the employee
// criterion's matches set.
func employeeMatchesDiags(t *testing.T, values ...string) diag.Diagnostics {
	t.Helper()

	attrs := buildCriteriaAttributes(controlspec.ClonedLoginPageDetection)
	nested, ok := attrs["employee_ids"].(schema.SingleNestedAttribute)
	if !ok {
		t.Fatalf("employee_ids is %T, want SingleNestedAttribute", attrs["employee_ids"])
	}
	set, ok := nested.Attributes["matches"].(schema.SetAttribute)
	if !ok {
		t.Fatalf("matches is %T, want SetAttribute", nested.Attributes["matches"])
	}

	elems := make([]attr.Value, 0, len(values))
	for _, v := range values {
		elems = append(elems, types.StringValue(v))
	}
	req := validator.SetRequest{
		Path:        path.Root("rules").AtListIndex(0).AtName("criteria").AtName("employee_ids").AtName("matches"),
		ConfigValue: types.SetValueMust(types.StringType, elems),
	}
	resp := &validator.SetResponse{}
	for _, v := range set.Validators {
		v.ValidateSet(context.Background(), req, resp)
	}
	return resp.Diagnostics
}

func TestEmployeeMatchesRejectsAnIdentifier(t *testing.T) {
	// A UUID is what the console shows, so it is an easy thing to paste.
	// Caught by shape so the message says what is wrong, rather than failing
	// later with a confusing "no such employee".
	diags := employeeMatchesDiags(t, "00000000-0000-0000-0000-000000000001")
	if !diags.HasError() {
		t.Fatal("a UUID was accepted as an email address")
	}
	if !strings.Contains(diags.Errors()[0].Detail(), "not an employee identifier") {
		t.Errorf("unhelpful message: %s", diags.Errors()[0].Detail())
	}
}

func TestEmployeeMatchesAcceptsAnAddress(t *testing.T) {
	if diags := employeeMatchesDiags(t, "security.lead@example.com"); diags.HasError() {
		t.Errorf("a valid address was rejected: %v", diags.Errors())
	}
}

func TestEmployeeMatchesRejectsAnEmptySet(t *testing.T) {
	// The API requires minItems: 1; an empty condition is a 400.
	if diags := employeeMatchesDiags(t); !diags.HasError() {
		t.Error("an empty matches set was accepted")
	}
}
