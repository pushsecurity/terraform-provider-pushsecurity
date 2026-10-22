package provider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"

	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/pushapi"
)

// The employee resources are the irreversible part of the provider — a
// merge is hard to undo, and an unlicense deletes accounts and findings — so
// their acceptance tests are gated behind an extra variable and may never run
// at all. The tests here drive the same paths through real terraform runs
// against tenantStub, on every pull request.

const employeeAddr = "pushsecurity_employee.test"

// TestEmployee_unlicenseRequiresOptIn is the guard that stops a one-word edit
// deleting somebody's accounts and findings. The refusal happens while the
// configuration is being validated, before any request, so it needs no
// tenant, stubbed or real.
func TestEmployee_unlicenseRequiresOptIn(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "pushsecurity_employee" "test" {
  email    = "somebody.who.is.not.there@example.com"
  licensed = false
}
`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`deletes the employee, their accounts and their findings`),
			},
		},
	})
}

// TestEmployee_adoptsAnExistingEmployee: an address the tenant holds is taken
// over, not created, and the attributes configuration does not set are left
// as the tenant has them.
func TestEmployee_adoptsAnExistingEmployee(t *testing.T) {
	stub := offlineTenant(t)
	log := &diagnosticLog{}
	id := stub.addEmployee("ada@example.com", "Ada", "Lovelace", true, "Engineering")

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: log.factories(),
		Steps: []resource.TestStep{
			{
				Config: `
resource "pushsecurity_employee" "test" {
  email = "ada@example.com"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(employeeAddr, "employee_id", id),
					resource.TestCheckResourceAttr(employeeAddr, "first_name", "Ada"),
					resource.TestCheckResourceAttr(employeeAddr, "last_name", "Lovelace"),
					resource.TestCheckResourceAttr(employeeAddr, "licensed", "true"),
					resource.TestCheckResourceAttr(employeeAddr, "allow_unlicense", "false"),
					resource.TestCheckTypeSetElemAttr(employeeAddr, "groups.*", "Engineering"),
					checkNotWarned(log, "Created a new employee"),
					func(*terraform.State) error {
						if n := stub.employeesCreated(); n != 0 {
							return fmt.Errorf("created %d employees while adopting one that exists", n)
						}
						return nil
					},
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
			{
				// Correcting a name is an ordinary update.
				Config: `
resource "pushsecurity_employee" "test" {
  email      = "ada@example.com"
  first_name = "Augusta"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(employeeAddr, "first_name", "Augusta"),
					resource.TestCheckResourceAttr(employeeAddr, "last_name", "Lovelace"),
					func(*terraform.State) error {
						e, ok := stub.employee("ada@example.com")
						if !ok || e.FirstName != "Augusta" {
							return fmt.Errorf("the tenant holds first name %q, want Augusta", e.FirstName)
						}
						return nil
					},
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
			{
				ResourceName:                         employeeAddr,
				ImportState:                          true,
				ImportStateId:                        "ada@example.com",
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "email",
			},
			{
				// Destroy leaves the employee exactly as they are.
				Config: `# pushsecurity_employee.test removed`,
				Check: resource.ComposeAggregateTestCheckFunc(
					checkWarned(log, "The employee is left exactly as they are"),
					func(*terraform.State) error {
						e, ok := stub.employee("ada@example.com")
						if !ok || !e.Licensed {
							return fmt.Errorf("destroy touched the employee: found=%v licensed=%v", ok, e.Licensed)
						}
						return nil
					},
				),
			},
		},
	})
}

// TestEmployee_importThenPlanIsEmpty: an imported employee is settled. The
// tenant cannot supply allow_unlicense, so the import has to, or the first
// plan afterwards would be an update that sets it to its default.
func TestEmployee_importThenPlanIsEmpty(t *testing.T) {
	stub := offlineTenant(t)
	id := stub.addEmployee("ada@example.com", "Ada", "Lovelace", true)

	const config = `
resource "pushsecurity_employee" "test" {
  email = "ada@example.com"
}
`
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:             config,
				ResourceName:       employeeAddr,
				ImportState:        true,
				ImportStateId:      "ada@example.com",
				ImportStatePersist: true,
				ImportStateCheck: func(states []*terraform.InstanceState) error {
					if len(states) != 1 {
						return fmt.Errorf("imported %d instances, want 1", len(states))
					}
					for attr, want := range map[string]string{
						"employee_id":     id,
						"first_name":      "Ada",
						"licensed":        "true",
						"allow_unlicense": "false",
					} {
						if got := states[0].Attributes[attr]; got != want {
							return fmt.Errorf("imported %s = %q, want %q", attr, got, want)
						}
					}
					return nil
				},
			},
			{
				Config: config,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
		},
	})
}

// TestEmployee_createsAMissingEmployee: an address the tenant does not hold
// is created, which uses a seat, and the apply says so.
func TestEmployee_createsAMissingEmployee(t *testing.T) {
	stub := offlineTenant(t)
	log := &diagnosticLog{}

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: log.factories(),
		Steps: []resource.TestStep{
			{
				Config: `
resource "pushsecurity_employee" "test" {
  email      = "grace@example.com"
  first_name = "Grace"
  last_name  = "Hopper"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(employeeAddr, "employee_id"),
					// The API licenses a new employee automatically.
					resource.TestCheckResourceAttr(employeeAddr, "licensed", "true"),
					resource.TestCheckResourceAttr(employeeAddr, "groups.#", "0"),
					checkWarned(log, "Created a new employee"),
					func(s *terraform.State) error {
						e, ok := stub.employee("grace@example.com")
						if !ok {
							return errors.New("the tenant does not hold the employee after apply")
						}
						if got := s.RootModule().Resources[employeeAddr].Primary.Attributes["employee_id"]; got != e.ID {
							return fmt.Errorf("employee_id = %q, the tenant assigned %q", got, e.ID)
						}
						if n := stub.employeesCreated(); n != 1 {
							return fmt.Errorf("created %d employees, want 1", n)
						}
						return nil
					},
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
			{
				// Stating the licence that is already held changes nothing.
				Config: `
resource "pushsecurity_employee" "test" {
  email      = "grace@example.com"
  first_name = "Grace"
  last_name  = "Hopper"
  licensed   = true
}
`,
				Check: resource.TestCheckResourceAttr(employeeAddr, "licensed", "true"),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
		},
	})
}

// TestEmployee_createdEmployeeResolvesInTheSameApply: creating an employee
// looks the address up first, which enumerates the tenant when it is not
// found. The address the apply then creates must still resolve for a control
// that names it later in the same apply. The email reaches the control
// through terraform_data, whose output is unknown until apply, because a
// known address is checked against the tenant during plan.
func TestEmployee_createdEmployeeResolvesInTheSameApply(t *testing.T) {
	stub := offlineTenant(t)
	stub.addEmployee("ada@example.com", "Ada", "Lovelace", true)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "pushsecurity_employee" "test" {
  email      = "grace@example.com"
  first_name = "Grace"
  last_name  = "Hopper"
}

resource "terraform_data" "email" {
  input = pushsecurity_employee.test.email
}

resource "pushsecurity_file_upload_blocking" "test" {
  rules = [{
    key     = "named"
    name    = "Named employee"
    enabled = true
    mode    = "MONITOR"
    criteria = {
      employee_ids = {
        action  = "INCLUDE"
        matches = [terraform_data.email.output]
      }
    }
  }]
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("pushsecurity_file_upload_blocking.test",
						"rules.0.criteria.employee_ids.matches.#", "1"),
					resource.TestCheckTypeSetElemAttr("pushsecurity_file_upload_blocking.test",
						"rules.0.criteria.employee_ids.matches.*", "grace@example.com"),
				),
			},
		},
	})
}

// TestEmployee_unlicensedEmployeeIsForgotten: once unlicensing has deleted the
// record, the run no longer resolves the address to the identifier it had.
func TestEmployee_unlicensedEmployeeIsForgotten(t *testing.T) {
	stub := offlineTenant(t)
	id := stub.addEmployee("ada@example.com", "Ada", "Lovelace", true)
	ctx := context.Background()

	client, err := pushapi.New(os.Getenv(envBaseURL), os.Getenv(envAPIKey))
	if err != nil {
		t.Fatal(err)
	}
	res := newEmployeeResolver(client)
	if _, found, err := res.Lookup(ctx, "ada@example.com"); err != nil || !found {
		t.Fatalf("Lookup before unlicensing: found=%v, err=%v", found, err)
	}

	r := &employeeResource{client: client, resolver: res}
	plan := employeeModel{
		Email:          types.StringValue("ada@example.com"),
		FirstName:      types.StringNull(),
		LastName:       types.StringNull(),
		Licensed:       types.BoolValue(false),
		AllowUnlicense: types.BoolValue(true),
	}
	var diags diag.Diagnostics
	r.applyAttributes(ctx, id, plan, employeeModel{Licensed: types.BoolValue(true)}, &diags)
	if diags.HasError() {
		t.Fatalf("applyAttributes: %v", diags)
	}

	got, found, err := res.Lookup(ctx, "ada@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if found {
		t.Errorf("Lookup after unlicensing = %q, want not found", got)
	}
}

// TestEmployee_createRequiresAName: creating needs a name, and the error says
// which address was not found rather than failing the request.
func TestEmployee_createRequiresAName(t *testing.T) {
	stub := offlineTenant(t)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "pushsecurity_employee" "test" {
  email = "nobody@example.com"
}
`,
				ExpectError: regexp.MustCompile(`creating them needs a name`),
			},
		},
	})
	if n := stub.employeesCreated(); n != 0 {
		t.Errorf("created %d employees without a name", n)
	}
}

// TestEmployee_unlicense: asked for by name, the licence is removed, and the
// API deletes the record with it. The resource treats that as the state it
// asked for: the refresh drops the identifier because there is no record,
// and the plan that follows is empty rather than proposing to create the
// employee again.
func TestEmployee_unlicense(t *testing.T) {
	stub := offlineTenant(t)
	log := &diagnosticLog{}
	stub.addEmployee("ada@example.com", "Ada", "Lovelace", true)

	const unlicensed = `
resource "pushsecurity_employee" "test" {
  email           = "ada@example.com"
  licensed        = false
  allow_unlicense = true
}
`
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: log.factories(),
		Steps: []resource.TestStep{
			{
				Config: `
resource "pushsecurity_employee" "test" {
  email    = "ada@example.com"
  licensed = true
}
`,
				Check: resource.TestCheckResourceAttr(employeeAddr, "licensed", "true"),
			},
			{
				Config: unlicensed,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(employeeAddr, "licensed", "false"),
					checkWarned(log, "Licence removed, and with it the employee, their accounts and their findings"),
					func(*terraform.State) error {
						if _, ok := stub.employee("ada@example.com"); ok {
							return errors.New("the employee still exists after being unlicensed")
						}
						return nil
					},
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
			{
				// Applied again, as a pipeline would on every merge: nothing
				// to do, and no record to name.
				Config: unlicensed,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckNoResourceAttr(employeeAddr, "employee_id"),
					resource.TestCheckResourceAttr(employeeAddr, "licensed", "false"),
					func(*terraform.State) error {
						if n := stub.employeesCreated(); n != 0 {
							return fmt.Errorf("created %d employees while keeping one unlicensed", n)
						}
						return nil
					},
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply:             []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
		},
	})
}

// TestEmployee_absentUnlicensedIsLeftAlone: an address the tenant does not
// hold, described as unlicensed, is neither created nor deleted. Nothing is
// sent, and the warning says the block can go.
func TestEmployee_absentUnlicensedIsLeftAlone(t *testing.T) {
	stub := offlineTenant(t)
	log := &diagnosticLog{}

	const config = `
resource "pushsecurity_employee" "test" {
  email           = "nobody@example.com"
  licensed        = false
  allow_unlicense = true
}
`
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: log.factories(),
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckNoResourceAttr(employeeAddr, "employee_id"),
					resource.TestCheckResourceAttr(employeeAddr, "licensed", "false"),
					resource.TestCheckResourceAttr(employeeAddr, "groups.#", "0"),
					checkWarned(log, "This employee does not exist, so there is nothing to unlicense"),
					func(*terraform.State) error {
						if n := stub.employeesCreated(); n != 0 {
							return fmt.Errorf("created %d employees for an address that should stay absent", n)
						}
						return nil
					},
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
			{
				Config: config,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply:             []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
		},
	})
}

const mergeRuleAddr = "pushsecurity_employee_merge_rule.test"

// TestEmployeeMergeRule_mergesThePairsThePlanShowed: the plan names the pair,
// the apply merges exactly that, nothing is outstanding afterwards, and an
// address that comes back is merged again by the next plan.
func TestEmployeeMergeRule_mergesThePairsThePlanShowed(t *testing.T) {
	stub := offlineTenant(t)
	stub.addEmployee("ada@example.org", "Ada", "Lovelace", true)
	stub.addEmployee("ada.admin@example.org", "Ada", "Lovelace", true)
	stub.addEmployee("bob@example.org", "Bob", "Example", true)
	// Out of scope by domain, so never touched.
	stub.addEmployee("eve@other.example", "Eve", "Example", true)
	stub.addEmployee("eve.admin@other.example", "Eve", "Example", true)

	const config = `
resource "pushsecurity_employee_merge_rule" "test" {
  patterns = ["{local}.admin@{domain}"]
  domains  = ["example.org"]
}
`
	pairShown := []plancheck.PlanCheck{
		plancheck.ExpectKnownValue(mergeRuleAddr, tfjsonpath.New("merged"),
			knownvalue.SetExact([]knownvalue.Check{
				knownvalue.StringExact("ada.admin@example.org -> ada@example.org"),
			})),
		plancheck.ExpectKnownValue(mergeRuleAddr, tfjsonpath.New("pending_merges"),
			knownvalue.SetSizeExact(0)),
	}

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply:             pairShown,
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(mergeRuleAddr, "merged.#", "1"),
					resource.TestCheckTypeSetElemAttr(mergeRuleAddr, "merged.*", "ada.admin@example.org -> ada@example.org"),
					resource.TestCheckResourceAttr(mergeRuleAddr, "pending_merges.#", "0"),
					resource.TestCheckResourceAttr(mergeRuleAddr, "max_merges", "25"),
					checkMerged(stub, "ada.admin@example.org"),
					func(*terraform.State) error {
						if got := stub.mergeRequests(); len(got) != 1 || len(got[0]) != 1 {
							return fmt.Errorf("merge requests = %v, want one request with one secondary", got)
						}
						if _, ok := stub.employee("eve.admin@other.example"); !ok {
							return errors.New("an address outside the rule's domains was merged")
						}
						return nil
					},
				),
			},
			{
				// The address returns, as an HR sync or a first sign-in would
				// bring it back. Nothing in the configuration changed; the
				// refresh finds the pair and plans the same merge again.
				PreConfig: func() { stub.addEmployee("ada.admin@example.org", "Ada", "Lovelace", true) },
				Config:    config,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: append([]plancheck.PlanCheck{
						plancheck.ExpectResourceAction(mergeRuleAddr, plancheck.ResourceActionUpdate),
					}, pairShown...),
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(mergeRuleAddr, "merged.#", "1"),
					resource.TestCheckResourceAttr(mergeRuleAddr, "pending_merges.#", "0"),
					checkMerged(stub, "ada.admin@example.org"),
				),
			},
		},
	})
}

// TestEmployeeMergeRule_maxMergesStopsThePlan: a pattern that matches more
// than max_merges fails during plan, naming the count, and nothing is merged.
func TestEmployeeMergeRule_maxMergesStopsThePlan(t *testing.T) {
	stub := offlineTenant(t)
	stub.addEmployee("ada@example.org", "Ada", "Lovelace", true)
	stub.addEmployee("ada.admin@example.org", "Ada", "Lovelace", true)
	stub.addEmployee("bob@example.org", "Bob", "Example", true)
	stub.addEmployee("bob.admin@example.org", "Bob", "Example", true)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "pushsecurity_employee_merge_rule" "test" {
  patterns   = ["{local}.admin@{domain}"]
  max_merges = 1
}
`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?s)More merges than this rule allows.*matches 2 addresses, and max_merges is 1`),
			},
		},
	})
	if got := stub.mergeRequests(); len(got) != 0 {
		t.Errorf("merge requests = %v, want none: the plan failed", got)
	}
}

// TestEmployeeMergeRule_unknownScopeMergesAtApply: a scope that is unknown at
// plan time leaves the pairs unknown too. The apply finds and merges them, and
// records them in merged, rather than leaving merged unknown.
func TestEmployeeMergeRule_unknownScopeMergesAtApply(t *testing.T) {
	stub := offlineTenant(t)
	stub.addEmployee("ada@example.com", "Ada", "Lovelace", true)
	stub.addEmployee("ada.admin@example.com", "Ada", "Lovelace", true)
	stub.addEmployee("bob@example.com", "Bob", "Example", true)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "terraform_data" "patterns" {
  input = ["{local}.admin@{domain}"]
}

resource "pushsecurity_employee_merge_rule" "test" {
  patterns = terraform_data.patterns.output
}
`,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectUnknownValue(mergeRuleAddr, tfjsonpath.New("merged")),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(mergeRuleAddr, "merged.#", "1"),
					resource.TestCheckTypeSetElemAttr(mergeRuleAddr, "merged.*", "ada.admin@example.com -> ada@example.com"),
					resource.TestCheckResourceAttr(mergeRuleAddr, "pending_merges.#", "0"),
					checkMerged(stub, "ada.admin@example.com"),
				),
			},
		},
	})
}

// TestEmployeeMergeRule_unknownScopeStillHonoursMaxMerges: with no pairs to
// check at plan time, max_merges is enforced by the apply instead.
func TestEmployeeMergeRule_unknownScopeStillHonoursMaxMerges(t *testing.T) {
	stub := offlineTenant(t)
	stub.addEmployee("ada@example.com", "Ada", "Lovelace", true)
	stub.addEmployee("ada.admin@example.com", "Ada", "Lovelace", true)
	stub.addEmployee("bob@example.com", "Bob", "Example", true)
	stub.addEmployee("bob.admin@example.com", "Bob", "Example", true)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "terraform_data" "patterns" {
  input = ["{local}.admin@{domain}"]
}

resource "pushsecurity_employee_merge_rule" "test" {
  patterns   = terraform_data.patterns.output
  max_merges = 1
}
`,
				ExpectError: regexp.MustCompile(`(?s)More merges than this rule allows.*matches 2 addresses, and max_merges is 1`),
			},
		},
	})
	if got := stub.mergeRequests(); len(got) != 0 {
		t.Errorf("merge requests = %v, want none: the apply stopped", got)
	}
}

// TestEmployeeMergeRule_conflictIsAnError: an address two employees could
// claim is reported, not merged into whichever was seen first.
func TestEmployeeMergeRule_conflictIsAnError(t *testing.T) {
	stub := offlineTenant(t)
	stub.addEmployee("ada@example.org", "Ada", "Lovelace", true)
	stub.addEmployee("bob@example.org", "Bob", "Example", true)
	stub.addEmployee("admin@example.org", "Shared", "Mailbox", true)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "pushsecurity_employee_merge_rule" "test" {
  patterns = ["admin@{domain}"]
}
`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?s)One address matches two employees.*admin@example.org could be merged into ada@example.org or bob@example.org`),
			},
		},
	})
	if got := stub.mergeRequests(); len(got) != 0 {
		t.Errorf("merge requests = %v, want none: the plan failed", got)
	}
	if _, ok := stub.employee("admin@example.org"); !ok {
		t.Error("the contested address was merged away")
	}
}

const mergeAddr = "pushsecurity_employee_merge.test"

// TestEmployeeMerge_mergesWhatIsConfigured: the apply merges exactly the
// configured address and nothing else, nothing is outstanding afterwards, an
// address the tenant does not hold is a warning rather than an error, and an
// address that comes back is merged again by the next plan.
func TestEmployeeMerge_mergesWhatIsConfigured(t *testing.T) {
	stub := offlineTenant(t)
	log := &diagnosticLog{}
	adaID := stub.addEmployee("ada@example.org", "Ada", "Lovelace", true)
	adminID := stub.addEmployee("ada.admin@example.org", "Ada", "Lovelace", true)
	stub.addEmployee("bob@example.org", "Bob", "Example", true)

	const merged = `
resource "pushsecurity_employee_merge" "test" {
  primary_email    = "ada@example.org"
  secondary_emails = ["ada.admin@example.org"]
}
`
	const withAbsent = `
resource "pushsecurity_employee_merge" "test" {
  primary_email    = "ada@example.org"
  secondary_emails = ["ada.admin@example.org", "ada.never.existed@example.org"]
}
`
	var returnedID string // the record the address comes back as

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: log.factories(),
		Steps: []resource.TestStep{
			{
				Config: merged,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(mergeAddr, plancheck.ResourceActionCreate),
					},
					// A refresh against a merged tenant finds nothing to do. If
					// the provider looked for anything beyond the secondary's
					// absence, this would churn.
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(mergeAddr, "primary_employee_id", adaID),
					resource.TestCheckResourceAttr(mergeAddr, "pending_merges.#", "0"),
					checkMerged(stub, "ada.admin@example.org"),
					checkNotMerged(stub, "ada@example.org"),
					checkNotMerged(stub, "bob@example.org"),
					checkMergeRequests(stub, []string{adminID}),
					checkNotWarned(log, "Nothing to merge for some addresses"),
				),
			},
			{
				// Re-merging an address that is already merged is the shape of
				// a re-run after state loss, and must be a no-op rather than an
				// error. An address that never existed looks the same, so it
				// is a warning.
				Config: withAbsent,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(mergeAddr, plancheck.ResourceActionUpdate),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(mergeAddr, "secondary_emails.#", "2"),
					resource.TestCheckResourceAttr(mergeAddr, "pending_merges.#", "0"),
					checkWarned(log, "Nothing to merge for some addresses"),
					checkMergeRequests(stub, []string{adminID}),
				),
			},
			{
				// The claim the whole design rests on: an address that comes
				// back, as an HR sync or a first sign-in would bring it back,
				// shows up on refresh, and the plan merges it again although
				// nothing in the configuration changed.
				PreConfig: func() {
					returnedID = stub.addEmployee("ada.admin@example.org", "Ada", "Lovelace", true)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(mergeAddr, "pending_merges.#", "1"),
					resource.TestCheckTypeSetElemAttr(mergeAddr, "pending_merges.*", "ada.admin@example.org"),
				),
				RefreshPlanChecks: resource.RefreshPlanChecks{
					PostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(mergeAddr, plancheck.ResourceActionUpdate),
						plancheck.ExpectKnownValue(mergeAddr, tfjsonpath.New("pending_merges"),
							knownvalue.SetSizeExact(0)),
					},
				},
			},
			{
				Config: withAbsent,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(mergeAddr, plancheck.ResourceActionUpdate),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(mergeAddr, "pending_merges.#", "0"),
					checkMerged(stub, "ada.admin@example.org"),
					func(s *terraform.State) error {
						return checkMergeRequests(stub, []string{adminID}, []string{returnedID})(s)
					},
				),
			},
			{
				// Dropping an address stops Terraform tracking it. It does not
				// unmerge anything, and the apply says so.
				Config: merged,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(mergeAddr, "secondary_emails.#", "1"),
					checkWarned(log, "Removed addresses stay merged"),
					func(s *terraform.State) error {
						return checkMergeRequests(stub, []string{adminID}, []string{returnedID})(s)
					},
				),
			},
			{
				// Destroy does not undo a merge, and says so rather than
				// passing as a no-op.
				Config: `# pushsecurity_employee_merge.test removed`,
				Check: resource.ComposeAggregateTestCheckFunc(
					checkWarned(log, "The employees stay merged"),
					checkMerged(stub, "ada.admin@example.org"),
					checkNotMerged(stub, "ada@example.org"),
					func(s *terraform.State) error {
						return checkMergeRequests(stub, []string{adminID}, []string{returnedID})(s)
					},
				),
			},
		},
	})
}

// TestEmployeeMerge_absentAddressIsAWarning: an address the tenant does not
// hold cannot be told apart from one already merged, so creating the merge
// warns about it and merges the rest.
func TestEmployeeMerge_absentAddressIsAWarning(t *testing.T) {
	stub := offlineTenant(t)
	log := &diagnosticLog{}
	stub.addEmployee("ada@example.org", "Ada", "Lovelace", true)
	adminID := stub.addEmployee("ada.admin@example.org", "Ada", "Lovelace", true)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: log.factories(),
		Steps: []resource.TestStep{
			{
				Config: `
resource "pushsecurity_employee_merge" "test" {
  primary_email    = "ada@example.org"
  secondary_emails = ["ada.admin@example.org", "ada.amdin@example.org"]
}
`,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(mergeAddr, "secondary_emails.#", "2"),
					resource.TestCheckResourceAttr(mergeAddr, "pending_merges.#", "0"),
					checkWarned(log, "Nothing to merge for some addresses"),
					checkMerged(stub, "ada.admin@example.org"),
					checkMergeRequests(stub, []string{adminID}),
				),
			},
		},
	})
}

// TestEmployeeMerge_primaryMustExist: the primary is the record that survives,
// so a primary the tenant does not hold is an error. Here it is merged into
// somebody else by a second merge, which is how a primary usually goes: the
// refresh drops the first merge from state, the plan offers to create it
// again, and the apply says to name the new primary instead.
func TestEmployeeMerge_primaryMustExist(t *testing.T) {
	stub := offlineTenant(t)
	stub.addEmployee("ada@example.org", "Ada", "Lovelace", true)
	stub.addEmployee("ada.admin@example.org", "Ada", "Lovelace", true)
	stub.addEmployee("augusta@example.org", "Augusta", "King", true)

	const first = `
resource "pushsecurity_employee_merge" "test" {
  primary_email    = "ada@example.org"
  secondary_emails = ["ada.admin@example.org"]
}
`
	const both = first + `
resource "pushsecurity_employee_merge" "other" {
  primary_email    = "augusta@example.org"
  secondary_emails = ["ada@example.org"]
}
`
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: first,
				Check:  checkMerged(stub, "ada.admin@example.org"),
			},
			{
				Config:             both,
				ExpectNonEmptyPlan: true,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(mergeAddr, plancheck.ResourceActionCreate),
						plancheck.ExpectResourceAction("pushsecurity_employee_merge.other", plancheck.ResourceActionNoop),
					},
				},
				Check: checkMerged(stub, "ada@example.org"),
			},
			{
				Config:      both,
				ExpectError: regexp.MustCompile(`No employee has this email address`),
			},
		},
	})
}

// TestEmployeeMerge_cannotMergeIntoThemselves: an address that is also the
// primary usually means the wrong one was copied, so it is refused while the
// configuration is validated, ignoring case, before any request.
func TestEmployeeMerge_cannotMergeIntoThemselves(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "pushsecurity_employee_merge" "test" {
  primary_email    = "ada@example.org"
  secondary_emails = ["ada.admin@example.org", "Ada@Example.org"]
}
`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`An employee cannot be merged into themselves`),
			},
		},
	})
}

// TestEmployeeMerge_unperformedMergeIsAnError: the merge endpoint answers 200
// whether or not it merged anything, so an address still there afterwards
// fails the apply, and nothing is recorded as merged.
func TestEmployeeMerge_unperformedMergeIsAnError(t *testing.T) {
	stub := offlineTenant(t)
	stub.addEmployee("ada@example.org", "Ada", "Lovelace", true)
	adminID := stub.addEmployee("ada.admin@example.org", "Ada", "Lovelace", true)
	stub.survivesMerge(adminID)

	const config = `
resource "pushsecurity_employee_merge" "test" {
  primary_email    = "ada@example.org"
  secondary_emails = ["ada.admin@example.org"]
}
`
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      config,
				ExpectError: regexp.MustCompile(`Merge did not take effect`),
			},
			{
				// The failed apply left nothing in state: the merge is still
				// to do.
				Config:             config,
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(mergeAddr, plancheck.ResourceActionCreate),
					},
				},
			},
		},
	})
	if got := stub.mergeRequests(); len(got) != 1 {
		t.Errorf("merge requests = %v, want the one the failed apply sent", got)
	}
}

// TestEmployeeMerge_importAdoptsThePrimary: an import cannot discover what
// was merged into somebody, so it takes the primary alone, and the
// first apply afterwards adopts the configured addresses without merging
// anything that is already merged.
func TestEmployeeMerge_importAdoptsThePrimary(t *testing.T) {
	stub := offlineTenant(t)
	log := &diagnosticLog{}
	// ada.admin@example.org was merged before Terraform managed anything, so the
	// tenant no longer holds it.
	adaID := stub.addEmployee("ada@example.org", "Ada", "Lovelace", true)

	const config = `
resource "pushsecurity_employee_merge" "test" {
  primary_email    = "ada@example.org"
  secondary_emails = ["ada.admin@example.org"]
}
`
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: log.factories(),
		Steps: []resource.TestStep{
			{
				Config:        config,
				ResourceName:  mergeAddr,
				ImportState:   true,
				ImportStateId: "ada",
				ExpectError:   regexp.MustCompile(`Invalid import identifier`),
			},
			{
				Config:             config,
				ResourceName:       mergeAddr,
				ImportState:        true,
				ImportStateId:      "ada@example.org",
				ImportStatePersist: true,
				ImportStateCheck: func(states []*terraform.InstanceState) error {
					if len(states) != 1 {
						return fmt.Errorf("imported %d instances, want 1", len(states))
					}
					for attr, want := range map[string]string{
						"primary_email":       "ada@example.org",
						"primary_employee_id": adaID,
						"secondary_emails.#":  "0",
						"pending_merges.#":    "0",
					} {
						if got := states[0].Attributes[attr]; got != want {
							return fmt.Errorf("imported %s = %q, want %q", attr, got, want)
						}
					}
					return nil
				},
			},
			{
				Config: config,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(mergeAddr, plancheck.ResourceActionUpdate),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(mergeAddr, "secondary_emails.#", "1"),
					resource.TestCheckResourceAttr(mergeAddr, "pending_merges.#", "0"),
					checkWarned(log, "Nothing to merge for some addresses"),
					checkMergeRequests(stub),
				),
			},
		},
	})
}

// checkMerged asserts the tenant no longer holds an address, which is the
// evidence a merge always leaves.
func checkMerged(stub *tenantStub, secondary string) resource.TestCheckFunc {
	return func(*terraform.State) error {
		if _, ok := stub.employee(secondary); ok {
			return fmt.Errorf("%s still exists as a separate employee", secondary)
		}
		return nil
	}
}

// checkNotMerged asserts the tenant still holds an address as an employee of
// its own.
func checkNotMerged(stub *tenantStub, email string) resource.TestCheckFunc {
	return func(*terraform.State) error {
		if _, ok := stub.employee(email); !ok {
			return fmt.Errorf("%s no longer exists as an employee", email)
		}
		return nil
	}
}

// checkMergeRequests asserts every merge request the tenant has received so
// far, as the secondary identifiers each one named.
func checkMergeRequests(stub *tenantStub, want ...[]string) resource.TestCheckFunc {
	return func(*terraform.State) error {
		got := stub.mergeRequests()
		if !slices.EqualFunc(got, want, slices.Equal) {
			return fmt.Errorf("merge requests = %v, want %v", got, want)
		}
		return nil
	}
}

// TestEmployee_noSeatsLeft: once every licence is in use, neither creating an
// employee, whom the API licenses, nor licensing one is possible, and the
// apply says that rather than reporting a bare failure.
func TestEmployee_noSeatsLeft(t *testing.T) {
	stub := offlineTenant(t)
	stub.addEmployee("ada@example.com", "Ada", "Lovelace", true)
	bob := stub.addEmployee("bob@example.com", "Bob", "Example", false)
	stub.limitSeats(1)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "pushsecurity_employee" "test" {
  email      = "grace@example.com"
  first_name = "Grace"
  last_name  = "Hopper"
}
`,
				ExpectError: regexp.MustCompile(`(?s)The tenant has no licence seats left.*grace@example.com`),
			},
			{
				Config: `
resource "pushsecurity_employee" "test" {
  email    = "bob@example.com"
  licensed = true
}
`,
				ExpectError: regexp.MustCompile(`(?s)The tenant has no licence seats left.*bob@example.com`),
			},
		},
	})
	if n := stub.employeesCreated(); n != 0 {
		t.Errorf("created %d employees with no seat to license them", n)
	}
	if e, ok := stub.employee("bob@example.com"); !ok || e.ID != bob || e.Licensed {
		t.Errorf("bob after the refused licence: found=%v licensed=%v, want still there unlicensed", ok, e.Licensed)
	}
}

// TestEmployee_emailCaseIsTheSamePerson: the tenant compares addresses
// ignoring case, so respelling one in the configuration is an update in place
// that sends nothing, not a replacement that adopts somebody afresh.
func TestEmployee_emailCaseIsTheSamePerson(t *testing.T) {
	stub := offlineTenant(t)
	id := stub.addEmployee("ada@example.com", "Ada", "Lovelace", true)
	log := logRequests(t)
	var requests int

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "pushsecurity_employee" "test" {
  email = "ada@example.com"
}
`,
				Check: func(*terraform.State) error { requests = len(employeeWrites(log)); return nil },
			},
			{
				Config: `
resource "pushsecurity_employee" "test" {
  email = "Ada@Example.com"
}
`,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(employeeAddr, plancheck.ResourceActionUpdate),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(employeeAddr, "email", "Ada@Example.com"),
					resource.TestCheckResourceAttr(employeeAddr, "employee_id", id),
					func(*terraform.State) error {
						if got := employeeWrites(log); len(got) != requests {
							return fmt.Errorf("respelling the address wrote to the tenant: %v", got[requests:])
						}
						return nil
					},
				),
			},
		},
	})
}

// TestEmployee_importInAnotherCase: an employee imported by their address as
// the console spells it is the one the configuration names in lower case, so
// the first plan updates the resource in place rather than replacing it.
func TestEmployee_importInAnotherCase(t *testing.T) {
	stub := offlineTenant(t)
	id := stub.addEmployee("ada@example.com", "Ada", "Lovelace", true)

	const config = `
resource "pushsecurity_employee" "test" {
  email = "ada@example.com"
}
`
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:             config,
				ResourceName:       employeeAddr,
				ImportState:        true,
				ImportStateId:      "Ada@Example.com",
				ImportStatePersist: true,
			},
			{
				Config: config,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(employeeAddr, plancheck.ResourceActionUpdate),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(employeeAddr, "email", "ada@example.com"),
					resource.TestCheckResourceAttr(employeeAddr, "employee_id", id),
				),
			},
		},
	})
}

// TestEmployee_updatePlansOnlyWhatChanges: an update of one attribute plans
// the others as they are, not as values known only after apply, because
// nothing the update sends can change them. When the tenant changes one of
// them between the plan and the apply anyway, here as a directory sync and a
// console edit would, the apply keeps what it planned rather than failing as
// an inconsistent result, and the next refresh picks the change up.
func TestEmployee_updatePlansOnlyWhatChanges(t *testing.T) {
	stub := offlineTenant(t)
	id := stub.addEmployee("ada@example.com", "Ada", "Lovelace", true, "Engineering")

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "pushsecurity_employee" "test" {
  email = "ada@example.com"
}
`,
			},
			{
				Config: `
resource "pushsecurity_employee" "test" {
  email      = "ada@example.com"
  first_name = "Augusta"
}
`,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectKnownValue(employeeAddr, tfjsonpath.New("last_name"),
							knownvalue.StringExact("Lovelace")),
						plancheck.ExpectKnownValue(employeeAddr, tfjsonpath.New("licensed"),
							knownvalue.Bool(true)),
						plancheck.ExpectKnownValue(employeeAddr, tfjsonpath.New("groups"),
							knownvalue.SetExact([]knownvalue.Check{knownvalue.StringExact("Engineering")})),
						plancheck.ExpectKnownValue(employeeAddr, tfjsonpath.New("employee_id"),
							knownvalue.StringExact(id)),
						planHook(func() {
							stub.editEmployee(id, func(e *pushapi.Employee) {
								e.LastName = "King"
								e.Groups = append(e.Groups, "Leadership")
							})
						}),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(employeeAddr, "first_name", "Augusta"),
					resource.TestCheckResourceAttr(employeeAddr, "last_name", "Lovelace"),
					resource.TestCheckResourceAttr(employeeAddr, "groups.#", "1"),
					func(*terraform.State) error {
						e, _ := stub.employee("ada@example.com")
						if e.FirstName != "Augusta" || e.LastName != "King" {
							return fmt.Errorf("the tenant holds %s %s, want Augusta King", e.FirstName, e.LastName)
						}
						return nil
					},
				),
			},
			{
				// The refresh brings in what changed behind the plan.
				Config: `
resource "pushsecurity_employee" "test" {
  email      = "ada@example.com"
  first_name = "Augusta"
}
`,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(employeeAddr, "last_name", "King"),
					resource.TestCheckTypeSetElemAttr(employeeAddr, "groups.*", "Leadership"),
				),
			},
		},
	})
}

// TestEmployee_listsEveryPage: the employee list is served a page at a time,
// and an address found only by reading the whole tenant, here because the
// tenant spells it with capitals the API's filter minds, is on the last page.
// Both the data source and the resource have to read to the end to find it.
func TestEmployee_listsEveryPage(t *testing.T) {
	stub := offlineTenant(t)
	for i := range 5 {
		stub.addEmployee(fmt.Sprintf("person%d@example.org", i), "Person", strconv.Itoa(i), true)
	}
	last := stub.addEmployee("Last.Page@Example.org", "Last", "Page", true)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: `
data "pushsecurity_employees" "all" {}

data "pushsecurity_employee" "last" {
  email = "last.page@example.org"
}

resource "pushsecurity_employee" "test" {
  email = "last.page@example.org"
}
`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr("data.pushsecurity_employees.all", "employees.#", "6"),
				resource.TestCheckResourceAttr("data.pushsecurity_employee.last", "id", last),
				resource.TestCheckResourceAttr(employeeAddr, "employee_id", last),
			),
		}},
	})
}

// employeeWrites returns the requests so far that wrote to an employee, in
// order.
func employeeWrites(log *requestLog) []loggedRequest {
	var out []loggedRequest
	for _, r := range log.all() {
		if strings.HasPrefix(r.path, "/v1/employees") && r.method != http.MethodGet {
			out = append(out, r)
		}
	}
	return out
}

// planHook runs between a step's plan and its apply, as a PreApply plan
// check: the window in which a change somebody else makes is one the plan
// cannot have seen.
type planHook func()

func (h planHook) CheckPlan(context.Context, plancheck.CheckPlanRequest, *plancheck.CheckPlanResponse) {
	h()
}

// TestEmployeeMerge_batchFailsPartway: the API takes five addresses a request,
// so six take two, and the second can fail after the first has merged. The
// apply fails, and the next one merges only what is still outstanding.
func TestEmployeeMerge_batchFailsPartway(t *testing.T) {
	stub := offlineTenant(t)
	stub.addEmployee("ada@example.org", "Ada", "Lovelace", true)
	var addrs []string
	for i := 1; i <= 6; i++ {
		addr := fmt.Sprintf("ada.%d@example.org", i)
		stub.addEmployee(addr, "Ada", "Lovelace", true)
		addrs = append(addrs, addr)
	}
	stub.refuseMergeAfter(1)

	config := `
resource "pushsecurity_employee_merge" "test" {
  primary_email    = "ada@example.org"
  secondary_emails = ["` + strings.Join(addrs, `", "`) + `"]
}
`

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      config,
				ExpectError: regexp.MustCompile(`Push API rejected the merge`),
			},
			{
				PreConfig: func() {
					var left []string
					for _, a := range addrs {
						if _, ok := stub.employee(a); ok {
							left = append(left, a)
						}
					}
					if len(left) != 1 {
						t.Errorf("after the second request failed, %q are still separate, want one", left)
					}
				},
				Config: config,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
				Check: func(s *terraform.State) error {
					for _, a := range addrs {
						if err := checkMerged(stub, a)(s); err != nil {
							return err
						}
					}
					got := stub.mergeRequests()
					if len(got) != 2 || len(got[0]) != 5 || len(got[1]) != 1 {
						return fmt.Errorf("merge requests = %v, want five secondaries, then the one left", got)
					}
					return nil
				},
			},
		},
	})
}

// TestEmployeeMerge_ignoresCase: addresses are compared ignoring case, on
// both sides of the merge and whichever side spells them with capitals, so
// a merge configured in one case finds records the tenant holds in another,
// and settles.
func TestEmployeeMerge_ignoresCase(t *testing.T) {
	stub := offlineTenant(t)
	adaID := stub.addEmployee("Ada.Lovelace@Example.org", "Ada", "Lovelace", true)
	adminID := stub.addEmployee("ada.admin@example.org", "Ada", "Lovelace", true)
	supportID := stub.addEmployee("Ada.Support@Example.org", "Ada", "Lovelace", true)

	const config = `
resource "pushsecurity_employee_merge" "test" {
  primary_email    = "ada.lovelace@example.org"
  secondary_emails = ["ADA.ADMIN@example.org", "ada.support@example.org"]
}
`
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(mergeAddr, "primary_employee_id", adaID),
					resource.TestCheckResourceAttr(mergeAddr, "pending_merges.#", "0"),
					checkMerged(stub, "ada.admin@example.org"),
					checkMerged(stub, "ada.support@example.org"),
					checkNotMerged(stub, "ada.lovelace@example.org"),
					func(*terraform.State) error {
						got := stub.mergeRequests()
						if len(got) != 1 || !sameStrings(got[0], []string{adminID, supportID}) {
							return fmt.Errorf("merge requests = %v, want one naming %s and %s", got, adminID, supportID)
						}
						return nil
					},
				),
			},
			{
				Config: config,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
		},
	})
}

// TestEmployeeMergeRule_pairBackAfterThePlanWaits: a pair the rule merged
// before, whose address comes back after the plan was made, is not merged by
// that apply, although merged names it: the plan did not show it. The next
// plan does, and its apply merges it.
func TestEmployeeMergeRule_pairBackAfterThePlanWaits(t *testing.T) {
	stub := offlineTenant(t)
	stub.addEmployee("ada@example.org", "Ada", "Lovelace", true)
	firstAdmin := stub.addEmployee("ada.admin@example.org", "Ada", "Lovelace", true)
	stub.addEmployee("bob@example.org", "Bob", "Example", true)
	var bobAdmin, returned string

	const config = `
resource "pushsecurity_employee_merge_rule" "test" {
  patterns = ["{local}.admin@{domain}"]
}
`
	adaPair := "ada.admin@example.org -> ada@example.org"
	bobPair := "bob.admin@example.org -> bob@example.org"

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check:  checkMerged(stub, "ada.admin@example.org"),
			},
			{
				PreConfig: func() { bobAdmin = stub.addEmployee("bob.admin@example.org", "Bob", "Example", true) },
				Config:    config,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectKnownValue(mergeRuleAddr, tfjsonpath.New("merged"),
							knownvalue.SetExact([]knownvalue.Check{
								knownvalue.StringExact(adaPair), knownvalue.StringExact(bobPair),
							})),
						planHook(func() {
							returned = stub.addEmployee("ada.admin@example.org", "Ada", "Lovelace", true)
						}),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(mergeRuleAddr, plancheck.ResourceActionUpdate),
					},
				},
				ExpectNonEmptyPlan: true,
				Check: resource.ComposeAggregateTestCheckFunc(
					checkMerged(stub, "bob.admin@example.org"),
					checkNotMerged(stub, "ada.admin@example.org"),
					func(s *terraform.State) error {
						return checkMergeRequests(stub, []string{firstAdmin}, []string{bobAdmin})(s)
					},
				),
			},
			{
				Config: config,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(mergeRuleAddr, plancheck.ResourceActionUpdate),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					checkMerged(stub, "ada.admin@example.org"),
					func(s *terraform.State) error {
						return checkMergeRequests(stub,
							[]string{firstAdmin}, []string{bobAdmin}, []string{returned})(s)
					},
				),
			},
		},
	})
}

// TestEmployeeMergeRule_partialFailureRecordsOnlyWhatMerged: when one of an
// apply's merges is refused, the state it leaves records the merges that
// happened and holds the refused one as still pending, rather than the plan's
// claim that all of them did. The next apply merges what is left.
func TestEmployeeMergeRule_partialFailureRecordsOnlyWhatMerged(t *testing.T) {
	stub := offlineTenant(t)
	stub.addEmployee("ada@example.org", "Ada", "Lovelace", true)
	stub.addEmployee("bob@example.org", "Bob", "Example", true)

	const config = `
resource "pushsecurity_employee_merge_rule" "test" {
  patterns = ["{local}.admin@{domain}"]
}
`
	adaPair := "ada.admin@example.org -> ada@example.org"
	bobPair := "bob.admin@example.org -> bob@example.org"

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check:  resource.TestCheckResourceAttr(mergeRuleAddr, "merged.#", "0"),
			},
			{
				// The pairs merge one request each, in the order they sort:
				// Ada's goes through and Bob's is refused.
				PreConfig: func() {
					stub.addEmployee("ada.admin@example.org", "Ada", "Lovelace", true)
					stub.addEmployee("bob.admin@example.org", "Bob", "Example", true)
					stub.refuseMergeAfter(1)
				},
				Config:      config,
				ExpectError: regexp.MustCompile(`Push API rejected the merge`),
			},
			{
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(mergeRuleAddr, "merged.#", "1"),
					resource.TestCheckTypeSetElemAttr(mergeRuleAddr, "merged.*", adaPair),
					resource.TestCheckResourceAttr(mergeRuleAddr, "pending_merges.#", "1"),
					resource.TestCheckTypeSetElemAttr(mergeRuleAddr, "pending_merges.*", bobPair),
					checkMerged(stub, "ada.admin@example.org"),
					checkNotMerged(stub, "bob.admin@example.org"),
				),
			},
			{
				Config: config,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(mergeRuleAddr, "merged.#", "2"),
					resource.TestCheckResourceAttr(mergeRuleAddr, "pending_merges.#", "0"),
					checkMerged(stub, "bob.admin@example.org"),
				),
			},
		},
	})
}

// TestEmployeeMergeRule_excludeEmails: an excluded address is never merged,
// and an excluded employee is never a primary, so their alias stays too.
func TestEmployeeMergeRule_excludeEmails(t *testing.T) {
	stub := offlineTenant(t)
	for _, name := range []string{"ada", "bob", "carol"} {
		stub.addEmployee(name+"@example.org", name, "Example", true)
		stub.addEmployee(name+".admin@example.org", name, "Example", true)
	}

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: `
resource "pushsecurity_employee_merge_rule" "test" {
  patterns       = ["{local}.admin@{domain}"]
  exclude_emails = ["ada.admin@example.org", "Carol@Example.org"]
}
`,
			ConfigPlanChecks: resource.ConfigPlanChecks{
				PreApply: []plancheck.PlanCheck{
					plancheck.ExpectKnownValue(mergeRuleAddr, tfjsonpath.New("merged"),
						knownvalue.SetExact([]knownvalue.Check{
							knownvalue.StringExact("bob.admin@example.org -> bob@example.org"),
						})),
				},
				PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
			},
			Check: resource.ComposeAggregateTestCheckFunc(
				checkMerged(stub, "bob.admin@example.org"),
				checkNotMerged(stub, "ada.admin@example.org"),
				checkNotMerged(stub, "carol.admin@example.org"),
			),
		}},
	})
}
