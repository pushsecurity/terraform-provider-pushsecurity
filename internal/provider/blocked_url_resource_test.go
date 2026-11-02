package provider

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// TestAccBlockedURL_sharedList is TestBlockedURL_lifecycle against the
// tenant: a pattern added over the API, as an incident-response workflow
// would add it, is not drift; a respelling settles; a different URL replaces
// the resource; and destroy leaves every pattern blocked.
//
// Whatever the tenant's list held before is part of the shared list the test
// is about, so it is expected to survive every step, and is put back
// afterwards.
func TestAccBlockedURL_sharedList(t *testing.T) {
	var before []string
	stored := func(added ...string) resource.TestCheckFunc {
		return func(s *terraform.State) error {
			return checkStoredBlockedURLs(append(slices.Clone(before), added...)...)(s)
		}
	}

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
			before = readBlockedURLs(t)
			// Destroy leaves the test's patterns in the tenant, and the API can
			// only empty the list, so empty it and add back what was there.
			// Registered here, which only runs when the test does.
			t.Cleanup(func() { restoreBlockedURLs(t, before) })
		},
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: stored("*://tf-acc-one.example.com/*", "*://tf-acc-two.example.com/path*",
			"*://tf-acc-three.example.com/*", "*://tf-acc-console.example.com/*"),
		Steps: []resource.TestStep{
			{
				Config: testAccBlockedURLPair,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(testBlockedURL, "canonical_pattern",
						"*://tf-acc-one.example.com/*"),
					stored("*://tf-acc-one.example.com/*", "*://tf-acc-two.example.com/path*"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
			{
				PreConfig: func() { addBlockedURLOutsideTerraform(t, "tf-acc-console.example.com") },
				Config:    testAccBlockedURLPair,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
			{
				Config: strings.Replace(testAccBlockedURLPair,
					`"tf-acc-one.example.com"`, `"tf-acc-one.example.com/*"`, 1),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(testBlockedURL, plancheck.ResourceActionUpdate),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
			{
				Config: strings.Replace(testAccBlockedURLPair,
					`"tf-acc-one.example.com"`, `"tf-acc-three.example.com"`, 1),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(testBlockedURL, plancheck.ResourceActionReplace),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
				Check: stored("*://tf-acc-one.example.com/*", "*://tf-acc-two.example.com/path*",
					"*://tf-acc-three.example.com/*", "*://tf-acc-console.example.com/*"),
			},
			{
				ResourceName:                         testBlockedURL,
				ImportState:                          true,
				ImportStateId:                        "tf-acc-three.example.com",
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "canonical_pattern",
			},
		},
	})
}

// readBlockedURLs returns the canonical patterns the tenant's list holds.
func readBlockedURLs(t *testing.T) []string {
	t.Helper()
	var list struct {
		Result []string `json:"result"`
	}
	if err := tenantRequest(http.MethodGet, "/v1/controls/blockedUrls", nil, &list); err != nil {
		t.Fatalf("reading the blocked URL list: %v", err)
	}
	return list.Result
}

// restoreBlockedURLs puts the tenant's list back to these canonical patterns,
// the only way the API allows: empty it, then add each one.
func restoreBlockedURLs(t *testing.T, canonical []string) {
	t.Helper()
	if err := tenantRequest(http.MethodDelete, "/v1/controls/blockedUrls", nil, nil); err != nil {
		t.Errorf("emptying the blocked URL list after the test: %v", err)
		return
	}
	for _, c := range canonical {
		body := map[string]string{"url": blockedURLPattern(c)}
		if err := tenantRequest(http.MethodPost, "/v1/controls/blockedUrls", body, nil); err != nil {
			t.Errorf("restoring %q to the blocked URL list after the test: %v", c, err)
		}
	}
}
