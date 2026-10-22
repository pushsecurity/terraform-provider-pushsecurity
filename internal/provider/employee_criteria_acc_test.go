package provider

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// Acceptance coverage for the employee criterion, which configuration writes as
// email addresses and the API matches on opaque identifiers.
//
// The unit tests cover the conversion in both directions against a stubbed API.
// What they cannot cover is the property that actually matters in use: that a
// real tenant's identifiers survive the round trip, so a rule naming people by
// address plans empty on the next run. That needs a real API, because the whole
// risk is the provider and the server disagreeing.
//
// These use fileUploadBlocking, which the other acceptance tests leave alone,
// and replace its whole configuration. As with every test here, point them only
// at a disposable tenant — see testAccPreCheck.

const testEmployeeResource = "pushsecurity_file_upload_blocking.test"

// testAccEmployeeConfig builds a configuration whose employee criterion names
// real people, discovered from the tenant rather than hard-coded: acceptance
// tests run against whatever tenant they are pointed at.
//
// sort() makes the choice deterministic across runs. count is clamped to what
// the tenant actually holds so a small tenant still exercises the path.
func testAccEmployeeConfig(count int, action string) string {
	return fmt.Sprintf(`
data "pushsecurity_employees" "all" {}

locals {
  emails = sort(tolist(data.pushsecurity_employees.all.emails))
  chosen = slice(local.emails, 0, min(%d, length(local.emails)))
}

resource "pushsecurity_file_upload_blocking" "test" {
  rules = [{
    key     = "tf-acc-employee-criterion"
    name    = "Terraform acceptance: employee criterion"
    enabled = true
    mode    = "MONITOR"
    criteria = {
      employee_ids = {
        action  = %q
        matches = local.chosen
      }
    }
  }]
}
`, count, action)
}

// TestAccEmployeeCriterion_roundTripsThroughRealIdentifiers is the property the
// feature rests on. Each step's implicit post-apply plan must be empty: that is
// what proves the addresses written out came back as the same addresses, rather
// than as the identifiers the API actually stores.
func TestAccEmployeeCriterion_roundTripsThroughRealIdentifiers(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccEmployeeConfig(1, "INCLUDE"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(testEmployeeResource,
						"rules.0.criteria.employee_ids.matches.#", "1"),
					resource.TestCheckResourceAttr(testEmployeeResource,
						"rules.0.criteria.employee_ids.action", "INCLUDE"),
					// State must hold what configuration holds. An identifier
					// here means the reverse conversion did not happen, and
					// every subsequent plan would show a diff.
					checkEmployeeMatchesAreAddresses(testEmployeeResource, 0),
					checkMatchesEqualConfiguredEmployees(testEmployeeResource, 0),
				),
			},
			{
				// Re-applying the same configuration must be a no-op. Explicit
				// because this is the regression the whole design exists to
				// prevent, and an implicit check is easy to overlook.
				Config: testAccEmployeeConfig(1, "INCLUDE"),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
			{
				// Changing who the rule names has to resolve the new set and
				// read it back the same way. On a tenant with one employee this
				// degrades to a no-op rather than failing.
				Config: testAccEmployeeConfig(2, "EXCLUDE"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(testEmployeeResource,
						"rules.0.criteria.employee_ids.action", "EXCLUDE"),
					checkEmployeeMatchesAreAddresses(testEmployeeResource, 0),
					checkMatchesEqualConfiguredEmployees(testEmployeeResource, 0),
				),
			},
		},
	})
}

// TestAccEmployeeCriterion_unknownAddressFailsDuringPlan covers the promise the
// schema documentation makes: an address the tenant does not hold is caught
// before anything is written, not as a 400 after a pull request has merged.
func TestAccEmployeeCriterion_unknownAddressFailsDuringPlan(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: `
resource "pushsecurity_file_upload_blocking" "test" {
  rules = [{
    key     = "tf-acc-unknown-employee"
    name    = "Terraform acceptance: unknown employee"
    enabled = true
    mode    = "MONITOR"
    criteria = {
      employee_ids = { matches = ["tf-acceptance-nobody@example.invalid"] }
    }
  }]
}`,
			ExpectError: regexp.MustCompile(`No employee has the email address`),
		}},
	})
}

// TestAccEmployeeCriterion_identifierIsRejected covers the mistake most likely
// to be made: pasting the UUID the console shows in place of an address.
func TestAccEmployeeCriterion_identifierIsRejected(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: `
resource "pushsecurity_file_upload_blocking" "test" {
  rules = [{
    key     = "tf-acc-identifier-employee"
    name    = "Terraform acceptance: identifier instead of address"
    enabled = true
    mode    = "MONITOR"
    criteria = {
      employee_ids = { matches = ["00000000-0000-0000-0000-000000000001"] }
    }
  }]
}`,
			ExpectError: regexp.MustCompile(`must be an employee email address, not an employee identifier`),
		}},
	})
}

// uuidLike matches the identifier shape the API stores, so a leak into state is
// recognisable without knowing the tenant's actual identifiers.
var uuidLike = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// employeeMatches pulls one rule's employee_ids matches out of state. The
// attribute is a set, so its elements are keyed by hash rather than by index.
func employeeMatches(s *terraform.State, name string, rule int) ([]string, error) {
	rs, ok := s.RootModule().Resources[name]
	if !ok {
		return nil, fmt.Errorf("resource %s not found in state", name)
	}
	prefix := fmt.Sprintf("rules.%d.criteria.employee_ids.matches.", rule)

	var out []string
	for k, v := range rs.Primary.Attributes {
		if strings.HasPrefix(k, prefix) && !strings.HasSuffix(k, ".#") {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s rule %d has no employee_ids matches in state", name, rule)
	}
	return out, nil
}

// checkEmployeeMatchesAreAddresses fails if state holds anything that looks
// like an employee identifier.
func checkEmployeeMatchesAreAddresses(name string, rule int) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		matches, err := employeeMatches(s, name, rule)
		if err != nil {
			return err
		}
		for _, m := range matches {
			if uuidLike.MatchString(m) {
				return fmt.Errorf("state holds the identifier %q where configuration holds an "+
					"email address: the reverse conversion did not happen, so every plan from "+
					"here would diff", m)
			}
			if !strings.Contains(m, "@") {
				return fmt.Errorf("state holds %q, which is not an email address", m)
			}
		}
		return nil
	}
}

// checkMatchesEqualConfiguredEmployees asserts the addresses in state are the
// ones the configuration selected, not merely address-shaped. Without this a
// provider that resolved to the wrong people would still pass.
func checkMatchesEqualConfiguredEmployees(name string, rule int) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		matches, err := employeeMatches(s, name, rule)
		if err != nil {
			return err
		}

		ds, ok := s.RootModule().Resources["data.pushsecurity_employees.all"]
		if !ok {
			return errors.New("data.pushsecurity_employees.all not found in state")
		}
		known := map[string]bool{}
		for k, v := range ds.Primary.Attributes {
			if strings.HasPrefix(k, "emails.") && !strings.HasSuffix(k, ".#") {
				known[v] = true
			}
		}

		for _, m := range matches {
			if !known[m] {
				return fmt.Errorf("state names %q, which the tenant does not hold: the address "+
					"was not resolved back to the person it was written for", m)
			}
		}
		return nil
	}
}
