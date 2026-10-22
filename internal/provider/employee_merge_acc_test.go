package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"

	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/pushapi"
)

// Acceptance coverage for employee merging.
//
// These tests are gated behind an environment variable of their own, which no
// other test in this package needs. Every other acceptance test here writes
// something it can put back: a control configuration is replaced, a detection
// is deleted. A merge can only be partly undone: /unmerge splits out an
// address that had accounts of its own, and the employees these tests create
// have none. Nor can an employee be deleted as such: unlicensing removes the
// record together with its accounts and findings, which is only safe for a
// record the test created. Running them therefore leaves a mark on the tenant,
// so opting in is explicit:
//
//	PUSH_ACC_MERGE=1 TF_ACC=1 go test ./internal/provider/ -run TestAccEmployeeMerge
//
// They create their own employees rather than merging anybody real, and each
// one cleans up after itself.
const envAccMerge = "PUSH_ACC_MERGE"

func testAccMergePreCheck(t *testing.T) {
	t.Helper()
	// These tests reach the API from the test body as well as from the steps,
	// so they check TF_ACC themselves rather than relying on resource.Test to
	// skip them.
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC must be set for acceptance tests")
	}
	if os.Getenv(envAccMerge) == "" {
		t.Skipf("%s must be set: these tests merge employees, which the API cannot fully undo", envAccMerge)
	}
	testAccPreCheck(t)
}

// testAccMergeClient builds a client straight from the environment, for the
// setup and teardown the provider has no resources for.
func testAccMergeClient(t *testing.T) *pushapi.Client {
	t.Helper()
	baseURL := firstNonEmpty(os.Getenv(envBaseURL), pushapi.DefaultBaseURL)
	client, err := pushapi.New(baseURL, os.Getenv(envAPIKey))
	if err != nil {
		t.Fatalf("pushapi.New: %v", err)
	}
	return client
}

// testAccEmailDomain picks the domain to create test employees in: whatever
// the tenant's first employee uses, so the test runs anywhere without being
// told. PUSH_ACC_MERGE_DOMAIN overrides it for a tenant with several.
func testAccEmailDomain(t *testing.T, client *pushapi.Client) string {
	t.Helper()
	if d := os.Getenv("PUSH_ACC_MERGE_DOMAIN"); d != "" {
		return strings.TrimPrefix(d, "@")
	}
	employees, err := client.ListEmployees(context.Background(), pushapi.EmployeeFilter{})
	if err != nil {
		t.Fatalf("listing employees: %v", err)
	}
	for _, e := range employees {
		if _, domain, ok := strings.Cut(e.Email, "@"); ok {
			return domain
		}
	}
	t.Skip("the tenant holds no employees, so there is no domain to create one in")
	return ""
}

// testAccCreateEmployee creates one employee and arranges for it to be
// removed afterwards.
//
// Unlicensing is the closest thing to a delete the API has: it removes the
// record, along with any accounts and findings, which anything created this
// way has none of. An employee that has already been merged away is gone, and
// cleanup finds nothing to do.
func testAccCreateEmployee(t *testing.T, client *pushapi.Client, email string) string {
	t.Helper()
	ctx := context.Background()

	created, err := client.CreateEmployee(ctx, pushapi.NewEmployee{
		FirstName: "Terraform", LastName: "Acceptance", Email: email,
		// Never true: these addresses do not exist, and enrolment would send
		// mail to them.
		EnrolBrowser: false,
	})
	if err != nil {
		t.Fatalf("creating %s: %v", email, err)
	}

	t.Cleanup(func() {
		// Unlicensing deletes the employee record, and with it any accounts
		// and findings — never do this to a record the test did not create.
		unlicensed := false
		if err := client.UpdateEmployee(context.Background(), created.ID,
			pushapi.EmployeeUpdate{Licensed: &unlicensed}); err != nil && !pushapi.NotFound(err) {
			t.Logf("could not clean up %s (%s): %v", email, created.ID, err)
		}
	})
	return created.ID
}

func TestAccEmployeeMerge_lifecycle(t *testing.T) {
	testAccMergePreCheck(t)

	client := testAccMergeClient(t)
	domain := testAccEmailDomain(t, client)
	stamp := time.Now().UnixNano()
	primary := fmt.Sprintf("tfacc.merge.%d@%s", stamp, domain)
	secondary := fmt.Sprintf("tfacc.merge.%d.admin@%s", stamp, domain)

	const addr = "pushsecurity_employee_merge.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccMergePreCheck(t)
			testAccCreateEmployee(t, client, primary)
			testAccCreateEmployee(t, client, secondary)
		},
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "pushsecurity_employee_merge" "test" {
  primary_email    = %q
  secondary_emails = [%q]
}
`, primary, secondary),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(addr, "primary_employee_id"),
					// Nothing outstanding: the address has stopped being a
					// separate employee, which is all a merge leaves behind.
					resource.TestCheckResourceAttr(addr, "pending_merges.#", "0"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					// The property that matters: a refresh against a merged
					// tenant finds nothing to do. If the provider looked for
					// evidence the API does not keep, this would churn.
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
			{
				// Re-merging an address that is already merged is the shape of
				// a re-run after state loss, and must be a no-op rather than
				// an error.
				Config: fmt.Sprintf(`
resource "pushsecurity_employee_merge" "test" {
  primary_email    = %q
  secondary_emails = [%q, "tfacc.merge.never.existed@%s"]
}
`, primary, secondary, domain),
				Check: resource.TestCheckResourceAttr(addr, "pending_merges.#", "0"),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
			{
				// The claim the whole design rests on: an address that comes
				// back is merged again. Recreating the employee here is what
				// an HR sync or a first sign-in does.
				PreConfig: func() { testAccCreateEmployee(t, client, secondary) },
				Config: fmt.Sprintf(`
resource "pushsecurity_employee_merge" "test" {
  primary_email    = %q
  secondary_emails = [%q, "tfacc.merge.never.existed@%s"]
}
`, primary, secondary, domain),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					// Nothing in the configuration changed: the plan exists
					// only because the refresh found the address again.
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(addr, plancheck.ResourceActionUpdate),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
				Check: resource.TestCheckResourceAttr(addr, "pending_merges.#", "0"),
			},
		},
	})
}

// TestAccEmployeeMergeRule_lifecycle exercises the pattern-driven rule.
//
// The pattern is deliberately one nobody in a real tenant uses, and
// max_merges is 1: a rule scans the whole tenant, and an acceptance test must
// not be able to merge somebody real if the pattern is wrong.
func TestAccEmployeeMergeRule_lifecycle(t *testing.T) {
	testAccMergePreCheck(t)

	client := testAccMergeClient(t)
	domain := testAccEmailDomain(t, client)
	stamp := time.Now().UnixNano()
	primary := fmt.Sprintf("tfacc.rule.%d@%s", stamp, domain)
	alias := fmt.Sprintf("tfacc.rule.%d.tfaccalias@%s", stamp, domain)

	const addr = "pushsecurity_employee_merge_rule.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccMergePreCheck(t)
			testAccCreateEmployee(t, client, primary)
			testAccCreateEmployee(t, client, alias)
		},
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "pushsecurity_employee_merge_rule" "test" {
  patterns   = ["{local}.tfaccalias@{domain}"]
  domains    = [%q]
  max_merges = 1
}
`, domain),
				Check: resource.ComposeAggregateTestCheckFunc(
					// The pair the plan showed is the pair the apply merged.
					resource.TestCheckResourceAttr(addr, "merged.#", "1"),
					resource.TestCheckTypeSetElemAttr(addr, "merged.*",
						fmt.Sprintf("%s -> %s", alias, primary)),
					resource.TestCheckResourceAttr(addr, "pending_merges.#", "0"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
		},
	})
}

// TestAccEmployeeMerge_unmergeNeedsAccounts confirms what the pushsecurity_employee_merge
// documentation says a merge leaves behind.
//
// The address of a secondary that had no accounts is not among the primary's
// known addresses afterwards, so /unmerge has nothing to split out and refuses
// it, as it refuses the primary's own address. The provider has no resource
// for unmerging, so the requests are made directly.
//
// The other half of the claim, that an address with accounts can be split out
// again, needs an employee with real accounts, which these tests cannot create.
func TestAccEmployeeMerge_unmergeNeedsAccounts(t *testing.T) {
	testAccMergePreCheck(t)

	client := testAccMergeClient(t)
	domain := testAccEmailDomain(t, client)
	stamp := time.Now().UnixNano()
	primary := fmt.Sprintf("tfacc.unmerge.%d@%s", stamp, domain)
	secondary := fmt.Sprintf("tfacc.unmerge.%d.admin@%s", stamp, domain)

	ctx := context.Background()
	primaryID := testAccCreateEmployee(t, client, primary)
	secondaryID := testAccCreateEmployee(t, client, secondary)

	if _, err := client.MergeEmployees(ctx, primaryID, []string{secondaryID}); err != nil {
		t.Fatalf("merging %s into %s: %v", secondary, primary, err)
	}
	if _, err := client.GetEmployee(ctx, secondaryID); !pushapi.NotFound(err) {
		t.Fatalf("after the merge, GetEmployee(%s) = %v, want not found", secondary, err)
	}

	merged, err := client.GetEmployee(ctx, primaryID)
	if err != nil {
		t.Fatalf("reading %s: %v", primary, err)
	}
	for _, e := range merged.KnownEmails {
		if strings.EqualFold(e, secondary) {
			t.Fatalf("%s is among the primary's known addresses although it had no accounts", secondary)
		}
	}

	for _, email := range []string{secondary, primary} {
		status, body := testAccUnmerge(t, primaryID, email)
		if status != http.StatusBadRequest {
			t.Errorf("unmerging %s: HTTP %d, want 400\n%s", email, status, body)
		}
	}

	employees, err := client.ListEmployees(ctx, pushapi.EmployeeFilter{Email: secondary})
	if err != nil {
		t.Fatalf("listing employees: %v", err)
	}
	for _, e := range employees {
		if strings.EqualFold(e.Email, secondary) {
			t.Errorf("a refused unmerge left an employee for %s (%s)", secondary, e.ID)
		}
	}
}

// testAccUnmerge asks the API to split email out of the employee id, and
// returns the status and body it answered with.
func testAccUnmerge(t *testing.T, id, email string) (int, string) {
	t.Helper()
	baseURL := strings.TrimRight(firstNonEmpty(os.Getenv(envBaseURL), pushapi.DefaultBaseURL), "/")
	payload, err := json.Marshal(map[string]string{"email": email})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		baseURL+"/v1/employees/"+url.PathEscape(id)+"/unmerge", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("x-api-key", os.Getenv(envAPIKey))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	httpClient := &http.Client{Timeout: 30 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("POST unmerge: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return resp.StatusCode, string(body)
}
