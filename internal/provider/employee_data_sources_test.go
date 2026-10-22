package provider

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/pushapi"
)

// The employee data sources exist so that criteria can be written in terms a
// reviewer understands. The acceptance tests assert only shape and invariants,
// not specific values, because they run against whatever the test tenant holds.
// They only read, so they run in parallel with one another. Go starts parallel
// tests once every other test has finished, so nothing writes alongside them.

func TestAccEmployeesDataSource(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: `data "pushsecurity_employees" "all" {}`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet("data.pushsecurity_employees.all", "employees.#"),
				resource.TestCheckResourceAttrSet("data.pushsecurity_employees.all", "ids.#"),
				// Every employee must contribute exactly one identifier and one
				// email, or the convenience sets do not match the list.
				sameLength("data.pushsecurity_employees.all", "employees.#", "ids.#"),
				sameLength("data.pushsecurity_employees.all", "employees.#", "emails.#"),
			),
		}},
	})
}

func TestAccEmployeesDataSource_groupFilterIsApplied(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			// A group no tenant has must produce an empty result rather than
			// being ignored — a filter that was dropped and matched everything
			// would widen a control to the whole company.
			Config: `data "pushsecurity_employees" "none" { groups = ["tf-acceptance-nonexistent-group"] }`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr("data.pushsecurity_employees.none", "employees.#", "0"),
				resource.TestCheckResourceAttr("data.pushsecurity_employees.none", "ids.#", "0"),
			),
		}},
	})
}

func TestAccEmployeeDataSource_notFound(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config:      `data "pushsecurity_employee" "nope" { email = "tf-acceptance-nobody@example.invalid" }`,
			ExpectError: regexp.MustCompile("No employee has the email address"),
		}},
	})
}

// TestAccEmployeeDataSources_emailLookup looks one of the tenant's employees up
// by their address in capitals, which must find them, and by a strict prefix
// of it, which must find nobody. It writes nothing.
//
// The data sources compare whole addresses, ignoring case, themselves, because
// tenantStub models the API's email filter as returning every address that
// contains the one asked for, spelled in the same case. They would pass
// whatever the filter did, so the filter is also asked directly. If it turns out to ignore case, or to match only prefixes
// or whole addresses, the stub is wrong about the API and is what needs
// changing. TestEmployeeDataSources_emailLookup runs the same steps against
// tenantStub.
func TestAccEmployeeDataSources_emailLookup(t *testing.T) {
	if os.Getenv(resource.EnvTfAcc) == "" {
		t.Skipf("acceptance tests skipped unless env %q is set", resource.EnvTfAcc)
	}
	testAccPreCheck(t)
	tc := emailLookupTestCase(t)
	tc.PreCheck = func() { testAccPreCheck(t) }
	resource.ParallelTest(t, tc)
}

// emailLookupTestCase is the lookup test for whichever tenant the provider is
// pointed at, built around one of its employees.
func emailLookupTestCase(t *testing.T) resource.TestCase {
	t.Helper()
	e := employeeToLookUp(t)
	upper := strings.ToUpper(e.Email)
	local, _, _ := strings.Cut(e.Email, "@")
	prefix := local + "@"

	return resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
data "pushsecurity_employee" "tf_acc_upper" {
  email = %[1]q
}

data "pushsecurity_employees" "tf_acc_upper" {
  email = %[1]q
}

data "pushsecurity_employees" "tf_acc_prefix" {
  email = %[2]q
}
`, upper, prefix),
				Check: resource.ComposeAggregateTestCheckFunc(
					checkEmailFilter(e, upper, prefix),

					resource.TestCheckResourceAttr("data.pushsecurity_employee.tf_acc_upper", "id", e.ID),
					resource.TestCheckResourceAttr("data.pushsecurity_employee.tf_acc_upper", "email", e.Email),

					resource.TestCheckResourceAttr("data.pushsecurity_employees.tf_acc_upper", "employees.#", "1"),
					resource.TestCheckResourceAttr("data.pushsecurity_employees.tf_acc_upper", "employees.0.id", e.ID),
					resource.TestCheckTypeSetElemAttr("data.pushsecurity_employees.tf_acc_upper", "emails.*", e.Email),

					resource.TestCheckResourceAttr("data.pushsecurity_employees.tf_acc_prefix", "employees.#", "0"),
					resource.TestCheckResourceAttr("data.pushsecurity_employees.tf_acc_prefix", "ids.#", "0"),
				),
			},
			{
				Config:      fmt.Sprintf(`data "pushsecurity_employee" "tf_acc_prefix" { email = %q }`, prefix),
				ExpectError: regexp.MustCompile("No employee has the email address"),
			},
		},
	}
}

// employeeToLookUp picks the first of the tenant's employees, by address,
// whose address has a lower-case letter for the capitals to change, and is
// long enough to have a part that is neither its start nor its end.
func employeeToLookUp(t *testing.T) pushapi.Employee {
	t.Helper()
	for _, e := range tenantEmployees(t, 100) {
		local, _, ok := strings.Cut(e.Email, "@")
		if ok && local != "" && len(e.Email) >= 3 && strings.ToUpper(e.Email) != e.Email {
			return e
		}
	}
	t.Fatal("the tenant has no employee whose address has a lower-case letter to look up")
	return pushapi.Employee{}
}

// checkEmailFilter asks the API's email filter directly what tenantStub
// assumes of it: an address in capitals does not find the employee, and a
// prefix of it and a part from its middle both do.
func checkEmailFilter(e pushapi.Employee, upper, prefix string) resource.TestCheckFunc {
	return func(*terraform.State) error {
		for _, tc := range []struct {
			filter string
			found  bool
			wrong  string // what the stub has wrong if the API disagrees
		}{
			{upper, false, "it ignores case, which tenantStub's does not"},
			{prefix, true, "it does not match a prefix, which tenantStub's does"},
			{e.Email[1 : len(e.Email)-1], true, "it does not match the middle of an address, which tenantStub's does"},
		} {
			var page struct {
				Result []pushapi.Employee `json:"result"`
				Paging struct {
					MoreResults bool `json:"moreResults"`
				} `json:"paging"`
			}
			if err := tenantRequest(http.MethodGet, "/v1/employees?email="+url.QueryEscape(tc.filter), nil, &page); err != nil {
				return err
			}
			found := slices.ContainsFunc(page.Result, func(r pushapi.Employee) bool { return r.ID == e.ID })
			switch {
			case found == tc.found:
			case !found && page.Paging.MoreResults:
				return fmt.Errorf("the API's email filter %q matched more than a page of employees "+
					"without %s on the first; the test needs a less common address", tc.filter, e.Email)
			case found:
				return fmt.Errorf("the API's email filter %q finds %s, so %s", tc.filter, e.Email, tc.wrong)
			default:
				return fmt.Errorf("the API's email filter %q does not find %s, so %s", tc.filter, e.Email, tc.wrong)
			}
		}
		return nil
	}
}

// TestEmployeeDataSources_emailLookup is
// TestAccEmployeeDataSources_emailLookup against tenantStub.
func TestEmployeeDataSources_emailLookup(t *testing.T) {
	stub := offlineTenant(t)
	seedDirectory(stub)
	stub.addEmployee("lada@example.org", "Lada", "Example", true)
	resource.UnitTest(t, emailLookupTestCase(t))
}

// The tests below run the same lookups offline, against tenantStub. Its
// employees are known, so they can assert values as well as shape.

// seedDirectory gives the data source tests a tenant whose answers are known:
// three employees, added out of email order, who differ in everything a
// filter reads.
func seedDirectory(stub *tenantStub) (ada, bob, grace string) {
	grace = stub.addEmployee("grace@example.org", "Grace", "Hopper", true, "Engineering", "Leadership")
	stub.editEmployee(grace, func(e *pushapi.Employee) {
		e.Department, e.Location, e.ChatopsEnabled = "Research", "Arlington", true
	})
	ada = stub.addEmployee("ada@example.org", "Ada", "Lovelace", true, "Engineering")
	bob = stub.addEmployee("bob@example.org", "Bob", "Example", false)
	return ada, bob, grace
}

// TestEmployeesDataSource_listsTheTenant: every employee, ordered by email
// whatever order the API answers in, each attribute read from its own field,
// and the convenience sets agreeing with the list.
func TestEmployeesDataSource_listsTheTenant(t *testing.T) {
	stub := offlineTenant(t)
	ada, bob, grace := seedDirectory(stub)

	const addr = "data.pushsecurity_employees.all"
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: `data "pushsecurity_employees" "all" {}`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr(addr, "employees.#", "3"),
				sameLength(addr, "employees.#", "ids.#"),
				sameLength(addr, "employees.#", "emails.#"),

				resource.TestCheckResourceAttr(addr, "employees.0.email", "ada@example.org"),
				resource.TestCheckResourceAttr(addr, "employees.1.email", "bob@example.org"),
				resource.TestCheckResourceAttr(addr, "employees.2.email", "grace@example.org"),

				resource.TestCheckResourceAttr(addr, "employees.2.id", grace),
				resource.TestCheckResourceAttr(addr, "employees.2.first_name", "Grace"),
				resource.TestCheckResourceAttr(addr, "employees.2.last_name", "Hopper"),
				resource.TestCheckResourceAttr(addr, "employees.2.department", "Research"),
				resource.TestCheckResourceAttr(addr, "employees.2.location", "Arlington"),
				resource.TestCheckResourceAttr(addr, "employees.2.licensed", "true"),
				resource.TestCheckResourceAttr(addr, "employees.2.chatops_enabled", "true"),
				resource.TestCheckResourceAttr(addr, "employees.2.groups.#", "2"),
				resource.TestCheckTypeSetElemAttr(addr, "employees.2.groups.*", "Leadership"),

				resource.TestCheckResourceAttr(addr, "employees.1.licensed", "false"),
				resource.TestCheckResourceAttr(addr, "employees.1.chatops_enabled", "false"),
				resource.TestCheckResourceAttr(addr, "employees.1.groups.#", "0"),

				resource.TestCheckTypeSetElemAttr(addr, "ids.*", ada),
				resource.TestCheckTypeSetElemAttr(addr, "ids.*", bob),
				resource.TestCheckTypeSetElemAttr(addr, "ids.*", grace),
				resource.TestCheckTypeSetElemAttr(addr, "emails.*", "bob@example.org"),
			),
		}},
	})
}

// TestEmployeesDataSource_filtersAreApplied: each filter reaches the API and
// narrows the result. A group nobody is in must give nothing rather than be
// ignored, because a filter that was dropped and matched everything would
// widen a control to the whole company. Several groups mean all of them.
func TestEmployeesDataSource_filtersAreApplied(t *testing.T) {
	stub := offlineTenant(t)
	seedDirectory(stub)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: `
data "pushsecurity_employees" "none" {
  groups = ["no-such-group"]
}

data "pushsecurity_employees" "engineering" {
  groups = ["Engineering"]
}

data "pushsecurity_employees" "leads" {
  groups = ["Engineering", "Leadership"]
}

data "pushsecurity_employees" "unlicensed" {
  licensed = false
}

data "pushsecurity_employees" "chatops" {
  chatops_enabled = true
}

data "pushsecurity_employees" "by_email" {
  email = "ada@example.org"
}
`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr("data.pushsecurity_employees.none", "employees.#", "0"),
				resource.TestCheckResourceAttr("data.pushsecurity_employees.none", "ids.#", "0"),
				resource.TestCheckResourceAttr("data.pushsecurity_employees.none", "emails.#", "0"),

				resource.TestCheckResourceAttr("data.pushsecurity_employees.engineering", "emails.#", "2"),
				resource.TestCheckTypeSetElemAttr("data.pushsecurity_employees.engineering", "emails.*", "ada@example.org"),
				resource.TestCheckTypeSetElemAttr("data.pushsecurity_employees.engineering", "emails.*", "grace@example.org"),

				resource.TestCheckResourceAttr("data.pushsecurity_employees.leads", "emails.#", "1"),
				resource.TestCheckTypeSetElemAttr("data.pushsecurity_employees.leads", "emails.*", "grace@example.org"),

				resource.TestCheckResourceAttr("data.pushsecurity_employees.unlicensed", "emails.#", "1"),
				resource.TestCheckTypeSetElemAttr("data.pushsecurity_employees.unlicensed", "emails.*", "bob@example.org"),

				resource.TestCheckResourceAttr("data.pushsecurity_employees.chatops", "emails.#", "1"),
				resource.TestCheckTypeSetElemAttr("data.pushsecurity_employees.chatops", "emails.*", "grace@example.org"),

				resource.TestCheckResourceAttr("data.pushsecurity_employees.by_email", "emails.#", "1"),
				resource.TestCheckTypeSetElemAttr("data.pushsecurity_employees.by_email", "emails.*", "ada@example.org"),
			),
		}},
	})
}

// TestEmployeesDataSource_emailMatchesWholeAddress: the API's email filter
// also returns longer addresses that contain the one asked for, so an address
// contained in a longer one must return only its own employee, and part of an
// address must return nobody. Anything more would widen a control fed from
// emails.
func TestEmployeesDataSource_emailMatchesWholeAddress(t *testing.T) {
	stub := offlineTenant(t)
	seedDirectory(stub)
	stub.addEmployee("lada@example.org", "Lada", "Example", true)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: `
data "pushsecurity_employees" "ada" {
  email = "ada@example.org"
}

data "pushsecurity_employees" "part" {
  email = "da@example.org"
}
`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr("data.pushsecurity_employees.ada", "employees.#", "1"),
				resource.TestCheckResourceAttr("data.pushsecurity_employees.ada", "emails.#", "1"),
				resource.TestCheckTypeSetElemAttr("data.pushsecurity_employees.ada", "emails.*", "ada@example.org"),

				resource.TestCheckResourceAttr("data.pushsecurity_employees.part", "employees.#", "0"),
				resource.TestCheckResourceAttr("data.pushsecurity_employees.part", "emails.#", "0"),
			),
		}},
	})
}

// TestEmployeeDataSource_ignoresCase: the API's email filter can miss an
// address spelled in different case, so an address configured with different
// capitals from the tenant's must still find its employee, whichever side has
// the capitals.
func TestEmployeeDataSource_ignoresCase(t *testing.T) {
	stub := offlineTenant(t)
	ada, _, _ := seedDirectory(stub)
	lin := stub.addEmployee("Lin@Example.org", "Lin", "Example", true)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: `
data "pushsecurity_employee" "ada" {
  email = " Ada@EXAMPLE.org "
}

data "pushsecurity_employee" "lin" {
  email = "lin@example.org"
}

data "pushsecurity_employees" "lin" {
  email = "LIN@example.org"
}
`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr("data.pushsecurity_employee.ada", "id", ada),
				resource.TestCheckResourceAttr("data.pushsecurity_employee.ada", "email", "ada@example.org"),

				resource.TestCheckResourceAttr("data.pushsecurity_employee.lin", "id", lin),
				resource.TestCheckResourceAttr("data.pushsecurity_employee.lin", "email", "Lin@Example.org"),

				resource.TestCheckResourceAttr("data.pushsecurity_employees.lin", "employees.#", "1"),
				resource.TestCheckTypeSetElemAttr("data.pushsecurity_employees.lin", "ids.*", lin),
			),
		}},
	})
}

// TestEmployeeDataSource_findsExactlyOne: the API's email filter also returns
// longer addresses that contain the one asked for, so an address contained in
// a longer one must still resolve to its own employee rather than be
// ambiguous.
func TestEmployeeDataSource_findsExactlyOne(t *testing.T) {
	stub := offlineTenant(t)
	ada, _, _ := seedDirectory(stub)
	stub.addEmployee("lada@example.org", "Lada", "Example", true)

	const addr = "data.pushsecurity_employee.ada"
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: `data "pushsecurity_employee" "ada" { email = "ada@example.org" }`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr(addr, "id", ada),
				resource.TestCheckResourceAttr(addr, "email", "ada@example.org"),
				resource.TestCheckResourceAttr(addr, "first_name", "Ada"),
				resource.TestCheckResourceAttr(addr, "last_name", "Lovelace"),
				resource.TestCheckResourceAttr(addr, "licensed", "true"),
				resource.TestCheckResourceAttr(addr, "chatops_enabled", "false"),
				resource.TestCheckResourceAttr(addr, "groups.#", "1"),
				resource.TestCheckTypeSetElemAttr(addr, "groups.*", "Engineering"),
			),
		}},
	})
}

// TestEmployeeDataSource_notFound: an address nobody has fails the plan,
// rather than narrowing a control to nobody.
func TestEmployeeDataSource_notFound(t *testing.T) {
	stub := offlineTenant(t)
	seedDirectory(stub)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config:      `data "pushsecurity_employee" "nope" { email = "nobody@example.org" }`,
			ExpectError: regexp.MustCompile("No employee has the email address"),
		}},
	})
}

// TestEmployeeDataSource_ambiguous: two records with one address should not
// exist, and if they do, the lookup refuses rather than picking whichever came
// first.
func TestEmployeeDataSource_ambiguous(t *testing.T) {
	stub := offlineTenant(t)
	stub.addEmployee("ada@example.org", "Ada", "Lovelace", true)
	stub.addEmployee("ada@example.org", "Ada", "King", true)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config:      `data "pushsecurity_employee" "ada" { email = "ada@example.org" }`,
			ExpectError: regexp.MustCompile("Ambiguous employee lookup"),
		}},
	})
}
