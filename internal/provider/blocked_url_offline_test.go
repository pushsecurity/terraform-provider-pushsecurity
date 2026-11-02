package provider

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	tfresource "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

// The tests in this file drive pushsecurity_blocked_url through real
// terraform runs against tenantStub. The resource shares the list with
// entries added outside Terraform, so what they check is that it touches its
// own pattern and nothing else, and that it never empties the list.

const testBlockedURL = "pushsecurity_blocked_url.test"

const testAccBlockedURLPair = `
resource "pushsecurity_blocked_url" "test" {
  pattern = "tf-acc-one.example.com"
}

resource "pushsecurity_blocked_url" "other" {
  pattern = "tf-acc-two.example.com/path*"
}`

// TestBlockedURL_lifecycle: entries added outside Terraform are not drift, a
// respelling sends nothing, a different URL is a replacement that leaves the
// old one blocked, and destroy leaves everything blocked.
func TestBlockedURL_lifecycle(t *testing.T) {
	stub := offlineTenant(t)
	log := logRequests(t)
	var writes int

	tfresource.UnitTest(t, tfresource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: tfresource.ComposeAggregateTestCheckFunc(
			checkStoredBlockedURLs("*://tf-acc-one.example.com/*", "*://tf-acc-two.example.com/path*",
				"*://tf-acc-three.example.com/*", "*://added-in-console.example.com/*"),
			checkBlockedURLListNeverEmptied(log),
		),
		Steps: []tfresource.TestStep{
			{
				Config: testAccBlockedURLPair,
				Check: tfresource.ComposeAggregateTestCheckFunc(
					tfresource.TestCheckResourceAttr(testBlockedURL, "pattern", "tf-acc-one.example.com"),
					tfresource.TestCheckResourceAttr(testBlockedURL, "canonical_pattern",
						"*://tf-acc-one.example.com/*"),
					checkStoredBlockedURLs("*://tf-acc-one.example.com/*", "*://tf-acc-two.example.com/path*"),
				),
				ConfigPlanChecks: tfresource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						// Worked out from the pattern alone, so known before apply.
						plancheck.ExpectKnownValue(testBlockedURL, tfjsonpath.New("canonical_pattern"),
							knownvalue.StringExact("*://tf-acc-one.example.com/*")),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
			{
				PreConfig: func() { stub.addBlockedURL("*://added-in-console.example.com/*") },
				Config:    testAccBlockedURLPair,
				ConfigPlanChecks: tfresource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
				Check: tfresource.ComposeAggregateTestCheckFunc(
					checkStoredBlockedURLs("*://tf-acc-one.example.com/*", "*://tf-acc-two.example.com/path*",
						"*://added-in-console.example.com/*"),
					func(*terraform.State) error { writes = len(blockedURLWrites(log)); return nil },
				),
			},
			{
				Config: strings.Replace(testAccBlockedURLPair,
					`"tf-acc-one.example.com"`, `"tf-acc-one.example.com/*"`, 1),
				ConfigPlanChecks: tfresource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(testBlockedURL, plancheck.ResourceActionUpdate),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
				Check: tfresource.ComposeAggregateTestCheckFunc(
					tfresource.TestCheckResourceAttr(testBlockedURL, "pattern", "tf-acc-one.example.com/*"),
					func(*terraform.State) error {
						if got := blockedURLWrites(log); len(got) != writes {
							return fmt.Errorf("respelling wrote to the list: %v", got[writes:])
						}
						return nil
					},
				),
			},
			{
				Config: strings.Replace(testAccBlockedURLPair,
					`"tf-acc-one.example.com"`, `"tf-acc-three.example.com"`, 1),
				ConfigPlanChecks: tfresource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(testBlockedURL, plancheck.ResourceActionReplace),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
				Check: checkStoredBlockedURLs("*://tf-acc-one.example.com/*",
					"*://tf-acc-two.example.com/path*", "*://tf-acc-three.example.com/*",
					"*://added-in-console.example.com/*"),
			},
		},
	})
}

// TestBlockedURL_removedOutsideTerraform: a pattern removed outside Terraform
// is drift, and the next apply adds back that pattern alone.
func TestBlockedURL_removedOutsideTerraform(t *testing.T) {
	stub := offlineTenant(t)
	log := logRequests(t)
	var writes int

	tfresource.UnitTest(t, tfresource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []tfresource.TestStep{
			{
				Config: testAccBlockedURLPair,
			},
			{
				PreConfig: func() {
					// The console's view of a removal: the API can only empty
					// the list, so empty it and put back what stays.
					if err := tenantRequest(http.MethodDelete, "/v1/controls/blockedUrls", nil, nil); err != nil {
						t.Fatal(err)
					}
					stub.addBlockedURL("*://tf-acc-two.example.com/path*")
					stub.addBlockedURL("*://added-in-console.example.com/*")
					writes = len(blockedURLWrites(log))
				},
				Config: testAccBlockedURLPair,
				ConfigPlanChecks: tfresource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(testBlockedURL, plancheck.ResourceActionCreate),
						plancheck.ExpectResourceAction("pushsecurity_blocked_url.other",
							plancheck.ResourceActionNoop),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
				Check: tfresource.ComposeAggregateTestCheckFunc(
					checkStoredBlockedURLs("*://tf-acc-one.example.com/*", "*://tf-acc-two.example.com/path*",
						"*://added-in-console.example.com/*"),
					func(*terraform.State) error {
						got := blockedURLWrites(log)[writes:]
						if len(got) != 1 || got[0].method != http.MethodPost {
							return fmt.Errorf("adding one pattern back wrote %v, want one POST", got)
						}
						return nil
					},
				),
			},
		},
	})
}

// TestBlockedURL_alreadyBlocked: a pattern the list already holds, however it
// got there, is taken over without being sent again.
func TestBlockedURL_alreadyBlocked(t *testing.T) {
	stub := offlineTenant(t)
	log := logRequests(t)
	stub.addBlockedURL("*://tf-acc-one.example.com/*")

	tfresource.UnitTest(t, tfresource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []tfresource.TestStep{{
			Config: `resource "pushsecurity_blocked_url" "test" { pattern = "tf-acc-one.example.com/" }`,
			ConfigPlanChecks: tfresource.ConfigPlanChecks{
				PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
			},
			Check: tfresource.ComposeAggregateTestCheckFunc(
				tfresource.TestCheckResourceAttr(testBlockedURL, "pattern", "tf-acc-one.example.com/"),
				checkStoredBlockedURLs("*://tf-acc-one.example.com/*"),
				func(*terraform.State) error {
					if got := blockedURLWrites(log); len(got) != 0 {
						return fmt.Errorf("taking over a blocked pattern wrote %v", got)
					}
					return nil
				},
			),
		}},
	})
}

// TestBlockedURL_import: an import names the pattern in either form, and
// fails for a pattern the list does not hold.
func TestBlockedURL_import(t *testing.T) {
	offlineTenant(t)

	tfresource.UnitTest(t, tfresource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []tfresource.TestStep{
			{
				Config: `resource "pushsecurity_blocked_url" "test" { pattern = "tf-acc-two.example.com/path*" }`,
			},
			{
				ResourceName:                         testBlockedURL,
				ImportState:                          true,
				ImportStateId:                        "tf-acc-two.example.com/path*",
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "canonical_pattern",
			},
			{
				ResourceName:                         testBlockedURL,
				ImportState:                          true,
				ImportStateId:                        "*://tf-acc-two.example.com/path*",
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "canonical_pattern",
			},
			{
				ResourceName:  testBlockedURL,
				ImportState:   true,
				ImportStateId: "tf-acc-absent.example.com",
				ExpectError:   regexp.MustCompile(`Cannot import non-existent remote object`),
			},
			{
				ResourceName:  testBlockedURL,
				ImportState:   true,
				ImportStateId: "https://tf-acc-one.example.com",
				ExpectError:   regexp.MustCompile(`(?s)Invalid import identifier.*must\s+not\s+include\s+a\s+scheme`),
			},
		},
	})
}

// TestBlockedURL_movingFromTheWholeList is the move its page describes: forget
// pushsecurity_blocked_urls and import its patterns, in one apply that writes
// nothing. The page uses for_each, which the testing framework cannot read
// back from state, so this names each resource instead.
func TestBlockedURL_movingFromTheWholeList(t *testing.T) {
	offlineTenant(t)
	log := logRequests(t)
	var writes int

	tfresource.UnitTest(t, tfresource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []tfresource.TestStep{
			{
				Config: testAccBlockedURLsTwo,
				Check:  func(*terraform.State) error { writes = len(blockedURLWrites(log)); return nil },
			},
			{
				Config: `
removed {
  from = pushsecurity_blocked_urls.test

  lifecycle {
    destroy = false
  }
}

import {
  to = pushsecurity_blocked_url.test
  id = "tf-acc-one.example.com"
}

import {
  to = pushsecurity_blocked_url.other
  id = "tf-acc-two.example.com/path*"
}
` + testAccBlockedURLPair,
				ConfigPlanChecks: tfresource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
				Check: tfresource.ComposeAggregateTestCheckFunc(
					checkStoredBlockedURLs("*://tf-acc-one.example.com/*", "*://tf-acc-two.example.com/path*"),
					tfresource.TestCheckResourceAttr("pushsecurity_blocked_url.other",
						"canonical_pattern", "*://tf-acc-two.example.com/path*"),
					func(*terraform.State) error {
						if got := blockedURLWrites(log); len(got) != writes {
							return fmt.Errorf("the move wrote to the list: %v", got[writes:])
						}
						return nil
					},
				),
			},
		},
	})
}

// TestBlockedURL_invalidPattern: the API's rules are checked during plan.
func TestBlockedURL_invalidPattern(t *testing.T) {
	offlineTenant(t)

	tfresource.UnitTest(t, tfresource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []tfresource.TestStep{{
			Config:      `resource "pushsecurity_blocked_url" "test" { pattern = "https://tf-acc-one.example.com" }`,
			PlanOnly:    true,
			ExpectError: regexp.MustCompile(`must\s+not\s+include\s+a\s+scheme`),
		}},
	})
}

// TestBlockedURL_destroyWarns: destroy sends nothing, so it has to say that
// the URL is still blocked. The testing framework does not surface warnings,
// so this calls Delete directly.
func TestBlockedURL_destroyWarns(t *testing.T) {
	ctx := context.Background()
	r := &blockedURLResource{}
	var s resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &s)

	req := resource.DeleteRequest{State: tfsdk.State{
		Schema: s.Schema,
		Raw: tftypes.NewValue(s.Schema.Type().TerraformType(ctx), map[string]tftypes.Value{
			"pattern":           tftypes.NewValue(tftypes.String, "tf-acc-one.example.com"),
			"canonical_pattern": tftypes.NewValue(tftypes.String, "*://tf-acc-one.example.com/*"),
		}),
	}}
	var resp resource.DeleteResponse
	r.Delete(ctx, req, &resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("destroy failed: %v", resp.Diagnostics)
	}
	warnings := resp.Diagnostics.Warnings()
	if len(warnings) != 1 || !strings.Contains(warnings[0].Detail(), `"tf-acc-one.example.com"`) {
		t.Fatalf("destroy warned %v, want one warning naming the pattern", warnings)
	}
}

// checkBlockedURLListNeverEmptied asserts the provider never sent the API's
// one delete, which empties the whole list.
func checkBlockedURLListNeverEmptied(log *requestLog) tfresource.TestCheckFunc {
	return func(*terraform.State) error {
		for _, w := range blockedURLWrites(log) {
			if w.method == http.MethodDelete {
				return fmt.Errorf("the provider emptied the blocked URL list: %v", blockedURLWrites(log))
			}
		}
		return nil
	}
}
