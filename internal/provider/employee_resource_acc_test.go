package provider

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/pushapi"
)

// TestAccEmployee_lifecycle creates an employee, then removes the licence the
// only way this provider allows: by asking for it explicitly.
//
// It shares the merge tests' gate because it leaves the same kind of mark —
// creating an employee consumes a licence, and the tenant this runs against
// has a ceiling.
func TestAccEmployee_lifecycle(t *testing.T) {
	testAccMergePreCheck(t)

	client := testAccMergeClient(t)
	domain := testAccEmailDomain(t, client)
	email := fmt.Sprintf("tfacc.employee.%d@%s", time.Now().UnixNano(), domain)

	const addr = "pushsecurity_employee.test"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// The address is not in the tenant, so this creates it. The
				// API licenses a new employee automatically.
				Config: fmt.Sprintf(`
resource "pushsecurity_employee" "test" {
  email      = %q
  first_name = "Terraform"
  last_name  = "Acceptance"
}
`, email),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(addr, "employee_id"),
					resource.TestCheckResourceAttr(addr, "licensed", "true"),
					resource.TestCheckResourceAttr(addr, "allow_unlicense", "false"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
			{
				// Re-applying the same configuration adopts what is there
				// rather than creating anything: the create path has to be
				// idempotent, because the API's create is an upsert.
				Config: fmt.Sprintf(`
resource "pushsecurity_employee" "test" {
  email      = %q
  first_name = "Terraform"
  last_name  = "Acceptance"
  licensed   = true
}
`, email),
				Check: resource.TestCheckResourceAttr(addr, "licensed", "true"),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
			{
				// Unlicensing, asked for by name. The API deletes the record
				// along with the licence. The resource treats that as the
				// state it asked for: the follow-up plan is empty rather than
				// proposing to create the employee again, and the refresh
				// drops the identifier because there is no longer a record it
				// names.
				Config: fmt.Sprintf(`
resource "pushsecurity_employee" "test" {
  email           = %q
  first_name      = "Terraform"
  last_name       = "Acceptance"
  licensed        = false
  allow_unlicense = true
}
`, email),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(addr, "licensed", "false"),
					func(*terraform.State) error {
						employees, err := client.ListEmployees(context.Background(),
							pushapi.EmployeeFilter{Email: email})
						if err != nil {
							return err
						}
						for _, e := range employees {
							if e.Email == email {
								return fmt.Errorf("%s still exists after being unlicensed", email)
							}
						}
						return nil
					},
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
			{
				// The same configuration applied again, as an apply-on-merge
				// pipeline would on every merge: still nothing to do.
				Config: fmt.Sprintf(`
resource "pushsecurity_employee" "test" {
  email           = %q
  first_name      = "Terraform"
  last_name       = "Acceptance"
  licensed        = false
  allow_unlicense = true
}
`, email),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckNoResourceAttr(addr, "employee_id"),
					resource.TestCheckResourceAttr(addr, "licensed", "false"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
		},
	})
}

// TestAccEmployee_absentUnlicensed writes nothing to the tenant: an address it
// does not hold, described as unlicensed, is left absent rather than created
// and deleted again. It therefore needs only credentials, not the merge gate.
func TestAccEmployee_absentUnlicensed(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC must be set for acceptance tests")
	}
	testAccPreCheck(t)

	const addr = "pushsecurity_employee.absent"
	config := fmt.Sprintf(`
resource "pushsecurity_employee" "absent" {
  email           = "tfacc.absent.%d@example.com"
  licensed        = false
  allow_unlicense = true
}
`, time.Now().UnixNano())

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckNoResourceAttr(addr, "employee_id"),
					resource.TestCheckResourceAttr(addr, "licensed", "false"),
					resource.TestCheckResourceAttr(addr, "groups.#", "0"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
			{
				// Applied again, nothing changes and nothing is sent.
				Config: config,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply:             []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
		},
	})
}
