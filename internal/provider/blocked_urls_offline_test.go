package provider

import (
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// The tests in this file drive pushsecurity_blocked_urls through real terraform runs
// against tenantStub, which stores each pattern in the canonical form the API
// does, worked out from the API's rules rather than the provider's. A plan
// that is empty after an apply is therefore the check that the provider
// canonicalises a pattern exactly as the API stores it.

// TestBlockedURLs_lifecycle is TestAccBlockedURLs_lifecycle without the
// tenant, with checks of what the tenant holds.
func TestBlockedURLs_lifecycle(t *testing.T) {
	offlineTenant(t)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		// The list cannot be removed, only emptied.
		CheckDestroy: checkStoredBlockedURLs(),
		Steps: []resource.TestStep{
			{
				Config: testAccBlockedURLsTwo,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(testBlockedURLs, "patterns.#", "2"),
					resource.TestCheckTypeSetElemAttr(testBlockedURLs, "patterns.*",
						"tf-acc-one.example.com"),
					resource.TestCheckTypeSetElemAttr(testBlockedURLs, "canonical_patterns.*",
						"*://tf-acc-one.example.com/*"),
					resource.TestCheckTypeSetElemAttr(testBlockedURLs, "canonical_patterns.*",
						"*://tf-acc-two.example.com/path*"),
					checkStoredBlockedURLs("*://tf-acc-one.example.com/*", "*://tf-acc-two.example.com/path*"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
			{
				// The stub, like the API, refuses its own canonical form on
				// POST, so this settles only if the provider converts it.
				Config: testAccBlockedURLsCanonical,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(testBlockedURLs, "patterns.#", "1"),
					resource.TestCheckTypeSetElemAttr(testBlockedURLs, "canonical_patterns.*",
						"*://tf-acc-one.example.com/*"),
					checkStoredBlockedURLs("*://tf-acc-one.example.com/*"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
			{
				Config: testAccBlockedURLsEmpty,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(testBlockedURLs, "patterns.#", "0"),
					checkStoredBlockedURLs(),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
		},
	})
}

// TestBlockedURLs_patternForms covers the parts of a pattern the API keeps
// that the lifecycle does not reach: a port, an IPv4 address, a query string
// with no path before it, a fragment, and a bare trailing slash.
func TestBlockedURLs_patternForms(t *testing.T) {
	offlineTenant(t)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: `
resource "pushsecurity_blocked_urls" "test" {
  patterns = [
    "intranet:8080/admin",
    "10.0.0.1/*",
    "example.com?q=1",
    "*.example.org/docs#top",
    "example.net/",
  ]
}`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckTypeSetElemAttr(testBlockedURLs, "patterns.*", "example.com?q=1"),
				checkStoredBlockedURLs(
					"*://intranet:8080/admin",
					"*://10.0.0.1/*",
					"*://example.com/?q=1",
					"*://*.example.org/docs#top",
					"*://example.net/*",
				),
			),
			ConfigPlanChecks: resource.ConfigPlanChecks{
				PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
			},
		}},
	})
}

// TestBlockedURLs_changedOutsideTerraform: an entry added in the console is
// drift, which the next apply removes, and an import reads the list as the
// tenant holds it.
func TestBlockedURLs_changedOutsideTerraform(t *testing.T) {
	stub := offlineTenant(t)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccBlockedURLsTwo,
			},
			{
				PreConfig: func() { stub.addBlockedURL("*://added-in-console.example.com/*") },
				Config:    testAccBlockedURLsTwo,
				Check: checkStoredBlockedURLs(
					"*://tf-acc-one.example.com/*", "*://tf-acc-two.example.com/path*"),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						expectBlockedURLDrift("*://added-in-console.example.com/*"),
						plancheck.ExpectResourceAction(testBlockedURLs, plancheck.ResourceActionUpdate),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
			{
				// One list per tenant, so the identifier is a convention and
				// the list itself is what has to come back.
				ResourceName:                         testBlockedURLs,
				ImportState:                          true,
				ImportStateId:                        "default",
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "canonical_patterns.#",
			},
		},
	})
}

// TestBlockedURLs_limits is TestAccBlockedURLs_limits without the tenant.
func TestBlockedURLs_limits(t *testing.T) {
	offlineTenant(t)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             checkStoredBlockedURLs(),
		Steps:                    []resource.TestStep{blockedURLLimitStep()},
	})
}

// checkStoredBlockedURLs asserts the tenant's blocked URL list is exactly
// these canonical patterns, in any order. It reads the tenant over the API,
// so it holds against a real tenant as well as the stub.
func checkStoredBlockedURLs(want ...string) resource.TestCheckFunc {
	want = slices.Sorted(slices.Values(want))
	return func(*terraform.State) error {
		var list struct {
			Result []string `json:"result"`
		}
		if err := tenantRequest(http.MethodGet, "/v1/controls/blockedUrls", nil, &list); err != nil {
			return err
		}
		got := slices.Sorted(slices.Values(list.Result))
		if !slices.Equal(got, want) {
			return fmt.Errorf("the tenant blocks %q, want %q", got, want)
		}
		return nil
	}
}

// TestBlockedURLs_respellingSendsNothing: patterns that mean what the list
// already holds change only how state spells them. Rewriting the list for
// that would leave URLs unblocked while it ran, for nothing.
func TestBlockedURLs_respellingSendsNothing(t *testing.T) {
	offlineTenant(t)
	log := logRequests(t)
	var writes int

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccBlockedURLsTwo,
				Check:  func(*terraform.State) error { writes = len(blockedURLWrites(log)); return nil },
			},
			{
				Config: `
resource "pushsecurity_blocked_urls" "test" {
  patterns = ["tf-acc-one.example.com/*", "tf-acc-two.example.com/path*"]
}`,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(testBlockedURLs, plancheck.ResourceActionUpdate),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckTypeSetElemAttr(testBlockedURLs, "patterns.*", "tf-acc-one.example.com/*"),
					checkStoredBlockedURLs("*://tf-acc-one.example.com/*", "*://tf-acc-two.example.com/path*"),
					func(*terraform.State) error {
						if got := blockedURLWrites(log); len(got) != writes {
							return fmt.Errorf("respelling wrote to the list: %v", got[writes:])
						}
						return nil
					},
				),
			},
		},
	})
}

// TestBlockedURLs_additionsAddOnlyTheNew: a change that removes nothing adds
// the new patterns and leaves the rest of the list alone, so nothing it
// already blocked stops being blocked while the apply runs.
func TestBlockedURLs_additionsAddOnlyTheNew(t *testing.T) {
	offlineTenant(t)
	log := logRequests(t)
	var writes int

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccBlockedURLsTwo,
				Check:  func(*terraform.State) error { writes = len(blockedURLWrites(log)); return nil },
			},
			{
				Config: `
resource "pushsecurity_blocked_urls" "test" {
  patterns = ["tf-acc-one.example.com", "tf-acc-two.example.com/path*", "tf-acc-three.example.com"]
}`,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					checkStoredBlockedURLs("*://tf-acc-one.example.com/*",
						"*://tf-acc-two.example.com/path*", "*://tf-acc-three.example.com/*"),
					func(*terraform.State) error {
						got := blockedURLWrites(log)[writes:]
						if len(got) != 1 || got[0].method != http.MethodPost {
							return fmt.Errorf("adding one pattern wrote %v, want one POST", got)
						}
						return nil
					},
				),
			},
		},
	})
}

// TestBlockedURLs_refusedWhileAdding: a pattern the API refuses partway
// through an apply that only adds leaves everything the list held before in
// place, says so, and the next apply adds the rest.
func TestBlockedURLs_refusedWhileAdding(t *testing.T) {
	stub := offlineTenant(t)
	log := logRequests(t)
	const four = `
resource "pushsecurity_blocked_urls" "test" {
  patterns = [
    "tf-acc-one.example.com", "tf-acc-two.example.com/path*",
    "tf-acc-three.example.com", "tf-acc-four.example.com",
  ]
}`
	all := []string{"*://tf-acc-one.example.com/*", "*://tf-acc-two.example.com/path*",
		"*://tf-acc-three.example.com/*", "*://tf-acc-four.example.com/*"}

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             checkStoredBlockedURLs(),
		Steps: []resource.TestStep{
			{
				Config: testAccBlockedURLsTwo,
			},
			{
				PreConfig: func() { stub.refuseBlockedURL("*://tf-acc-three.example.com/*", true) },
				Config:    four,
				ExpectError: regexp.MustCompile(`(?s)Push API rejected a URL pattern` +
					`.*every\s+entry\s+the\s+list\s+held\s+before\s+is\s+still\s+there`),
			},
			{
				PreConfig: func() {
					// What the failed apply left: everything there before, and
					// whatever it added before the refusal.
					var list struct {
						Result []string `json:"result"`
					}
					if err := tenantRequest(http.MethodGet, "/v1/controls/blockedUrls", nil, &list); err != nil {
						t.Fatal(err)
					}
					for _, want := range all[:2] {
						if !slices.Contains(list.Result, want) {
							t.Errorf("after the refusal the tenant blocks %q, without %q", list.Result, want)
						}
					}
					stub.refuseBlockedURL("*://tf-acc-three.example.com/*", false)
				},
				Config: four,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					checkStoredBlockedURLs(all...),
					func(*terraform.State) error {
						for _, w := range blockedURLWrites(log) {
							if w.method == http.MethodDelete {
								return fmt.Errorf("the list was emptied although nothing was removed: %v",
									blockedURLWrites(log))
							}
						}
						return nil
					},
				),
			},
		},
	})
}

// TestBlockedURLs_destroyEmptiesTheList: the list cannot be removed, so
// destroy empties it, entries added in the console included.
func TestBlockedURLs_destroyEmptiesTheList(t *testing.T) {
	stub := offlineTenant(t)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             checkStoredBlockedURLs(),
		Steps: []resource.TestStep{
			{
				Config: testAccBlockedURLsTwo,
				Check: checkStoredBlockedURLs(
					"*://tf-acc-one.example.com/*", "*://tf-acc-two.example.com/path*"),
			},
			{
				// Planned and not applied, so that the destroy that ends the
				// test finds the console's entry still there.
				PreConfig:          func() { stub.addBlockedURL("*://added-in-console.example.com/*") },
				Config:             testAccBlockedURLsTwo,
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// blockedURLWrites returns the requests so far that changed the blocked URL
// list, in order.
func blockedURLWrites(log *requestLog) []loggedRequest {
	var out []loggedRequest
	for _, r := range log.all() {
		if r.path == "/v1/controls/blockedUrls" && r.method != http.MethodGet {
			out = append(out, r)
		}
	}
	return out
}
