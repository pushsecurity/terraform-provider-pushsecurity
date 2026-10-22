package provider

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"

	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/pushapi"
)

const testBlockedURLs = "pushsecurity_blocked_urls.test"

func TestAccBlockedURLs_lifecycle(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccBlockedURLsTwo,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(testBlockedURLs, "patterns.#", "2"),
					// The practitioner's own spelling is kept in state; the
					// API's form is exposed separately. Storing the API's form
					// in `patterns` would show a permanent diff.
					resource.TestCheckTypeSetElemAttr(testBlockedURLs, "patterns.*",
						"tf-acc-one.example.com"),
					resource.TestCheckTypeSetElemAttr(testBlockedURLs, "canonical_patterns.*",
						"*://tf-acc-one.example.com/*"),
					resource.TestCheckTypeSetElemAttr(testBlockedURLs, "canonical_patterns.*",
						"*://tf-acc-two.example.com/path*"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
			{
				// Writing the API's own canonical form must also settle, even
				// though POST rejects it: the provider converts before sending.
				Config: testAccBlockedURLsCanonical,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(testBlockedURLs, "patterns.#", "1"),
					resource.TestCheckTypeSetElemAttr(testBlockedURLs, "canonical_patterns.*",
						"*://tf-acc-one.example.com/*"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
			{
				Config: testAccBlockedURLsEmpty,
				Check:  resource.TestCheckResourceAttr(testBlockedURLs, "patterns.#", "0"),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
		},
	})
}

const testAccBlockedURLsTwo = `
resource "pushsecurity_blocked_urls" "test" {
  patterns = ["tf-acc-one.example.com", "tf-acc-two.example.com/path*"]
}`

const testAccBlockedURLsCanonical = `
resource "pushsecurity_blocked_urls" "test" {
  patterns = ["*://tf-acc-one.example.com/*"]
}`

const testAccBlockedURLsEmpty = `resource "pushsecurity_blocked_urls" "test" { patterns = [] }`

// TestAccBlockedURLs_patternForms is TestBlockedURLs_patternForms against the
// tenant: a port, an IPv4 address, a query string with no path before it, a
// fragment, and a bare trailing slash, each of which the API stores in a form
// of its own. The hosts are made up, and the address is one reserved for
// documentation, so nothing real is blocked while the test runs.
func TestAccBlockedURLs_patternForms(t *testing.T) {
	stored := []string{
		"*://tf-acc-port.example.com:8080/admin",
		"*://192.0.2.1/*",
		"*://tf-acc-query.example.com/?q=1",
		"*://*.tf-acc-fragment.example.org/docs#top",
		"*://tf-acc-slash.example.net/*",
	}
	checks := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(testBlockedURLs, "patterns.#", "5"),
		resource.TestCheckTypeSetElemAttr(testBlockedURLs, "patterns.*", "tf-acc-query.example.com?q=1"),
		checkStoredBlockedURLs(stored...),
	}
	for _, s := range stored {
		checks = append(checks, resource.TestCheckTypeSetElemAttr(testBlockedURLs, "canonical_patterns.*", s))
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             checkStoredBlockedURLs(),
		Steps: []resource.TestStep{
			{
				Config: `
resource "pushsecurity_blocked_urls" "test" {
  patterns = [
    "tf-acc-port.example.com:8080/admin",
    "192.0.2.1/*",
    "tf-acc-query.example.com?q=1",
    "*.tf-acc-fragment.example.org/docs#top",
    "tf-acc-slash.example.net/",
  ]
}`,
				Check: resource.ComposeAggregateTestCheckFunc(checks...),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
			{
				Config: testAccBlockedURLsEmpty,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(testBlockedURLs, "canonical_patterns.#", "0"),
					checkStoredBlockedURLs(),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
		},
	})
}

// TestAccBlockedURLs_changedOutsideTerraform is
// TestBlockedURLs_changedOutsideTerraform against the tenant: an entry added
// over the API, as the console would add it, is drift, which the next apply
// removes, and an import reads the list as the tenant holds it.
func TestAccBlockedURLs_changedOutsideTerraform(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             checkStoredBlockedURLs(),
		Steps: []resource.TestStep{
			{
				Config: testAccBlockedURLsTwo,
			},
			{
				PreConfig: func() { addBlockedURLOutsideTerraform(t, "tf-acc-console.example.com") },
				Config:    testAccBlockedURLsTwo,
				Check: checkStoredBlockedURLs(
					"*://tf-acc-one.example.com/*", "*://tf-acc-two.example.com/path*"),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						expectBlockedURLDrift("*://tf-acc-console.example.com/*"),
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

// addBlockedURLOutsideTerraform adds a pattern to the tenant over the API,
// without Terraform: the stand-in for one added in the console. It checks the
// API stored the pattern as the provider would have canonicalised it, since
// the drift the test goes on to look for depends on that.
func addBlockedURLOutsideTerraform(t *testing.T, pattern string) {
	t.Helper()
	client, err := pushapi.New(firstNonEmpty(os.Getenv(envBaseURL), pushapi.DefaultBaseURL), os.Getenv(envAPIKey))
	if err != nil {
		t.Fatalf("pushapi.New: %v", err)
	}
	stored, err := client.AddBlockedURL(context.Background(), pattern)
	if err != nil {
		t.Fatalf("adding %q outside Terraform: %v", pattern, err)
	}
	if want := mustCanonical(pattern); stored != want {
		t.Fatalf("the API stored %q as %q, want %q", pattern, stored, want)
	}
}

// expectBlockedURLDrift asserts the plan reports, as a change made outside
// Terraform, that the tenant's list has gained this canonical pattern.
func expectBlockedURLDrift(canonical string) plancheck.PlanCheck {
	return blockedURLDrift{canonical}
}

type blockedURLDrift struct{ canonical string }

func (d blockedURLDrift) CheckPlan(_ context.Context, req plancheck.CheckPlanRequest, resp *plancheck.CheckPlanResponse) {
	for _, rc := range req.Plan.ResourceDrift {
		if rc.Address != testBlockedURLs || rc.Change == nil {
			continue
		}
		after, _ := rc.Change.After.(map[string]any)
		stored, _ := after["canonical_patterns"].([]any)
		if !slices.Contains(stored, any(d.canonical)) {
			resp.Error = fmt.Errorf("%s drifted, but its refreshed canonical_patterns %v lack %q",
				testBlockedURLs, stored, d.canonical)
		}
		return
	}
	resp.Error = fmt.Errorf("the plan reports no drift in %s, want %q added outside Terraform",
		testBlockedURLs, d.canonical)
}

// TestAccBlockedURLs_limits applies a host and a path exactly as long as the
// API allows, which is also the longest the provider accepts during plan. Both
// must be accepted and settle, or the provider is stricter than the API.
func TestAccBlockedURLs_limits(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             checkStoredBlockedURLs(),
		Steps:                    []resource.TestStep{blockedURLLimitStep()},
	})
}

// The patterns at the limits. The host's limit counts its port, so it is
// reached once without a port and once with one.
var (
	blockedURLHostAtLimit     = padBlockedURL("tf-acc-host-", ".example.com", maxBlockedURLHostLength)
	blockedURLHostPortAtLimit = padBlockedURL("tf-acc-port-", ".example.com:8080", maxBlockedURLHostLength)
	blockedURLPathAtLimit     = "tf-acc-path.example.com/" + padBlockedURL("tf-acc-", "*", maxBlockedURLPathLength)
)

// padBlockedURL pads between prefix and suffix to make a string of length n.
func padBlockedURL(prefix, suffix string, n int) string {
	return prefix + strings.Repeat("x", n-len(prefix)-len(suffix)) + suffix
}

// blockedURLLimitStep is the step of TestAccBlockedURLs_limits, shared with
// its offline twin.
func blockedURLLimitStep() resource.TestStep {
	stored := []string{
		"*://" + blockedURLHostAtLimit + "/*",
		"*://" + blockedURLHostPortAtLimit + "/*",
		"*://" + blockedURLPathAtLimit,
	}
	return resource.TestStep{
		Config: fmt.Sprintf(`
resource "pushsecurity_blocked_urls" "test" {
  patterns = [%q, %q, %q]
}`, blockedURLHostAtLimit, blockedURLHostPortAtLimit, blockedURLPathAtLimit),
		Check: resource.ComposeAggregateTestCheckFunc(
			resource.TestCheckTypeSetElemAttr(testBlockedURLs, "canonical_patterns.*", stored[0]),
			resource.TestCheckTypeSetElemAttr(testBlockedURLs, "canonical_patterns.*", stored[1]),
			resource.TestCheckTypeSetElemAttr(testBlockedURLs, "canonical_patterns.*", stored[2]),
			checkStoredBlockedURLs(stored...),
		),
		ConfigPlanChecks: resource.ConfigPlanChecks{
			PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
		},
	}
}

func TestAccBlockedURLs_validation(t *testing.T) {
	for _, tc := range []struct {
		name, config string
		wantErr      *regexp.Regexp
	}{
		{
			name:    "scheme rejected with a suggestion",
			config:  `resource "pushsecurity_blocked_urls" "test" { patterns = ["https://example.com"] }`,
			wantErr: regexp.MustCompile("must not include a scheme"),
		},
		{
			name:    "upper-case host rejected",
			config:  `resource "pushsecurity_blocked_urls" "test" { patterns = ["EXAMPLE.com"] }`,
			wantErr: regexp.MustCompile("upper-case"),
		},
		{
			// The API stores a bare trailing slash as every path.
			name:    "trailing slash is the bare host",
			config:  `resource "pushsecurity_blocked_urls" "test" { patterns = ["example.com/", "example.com"] }`,
			wantErr: regexp.MustCompile("Duplicate URL pattern"),
		},
		{
			// Two spellings of one pattern: the API would store one and the
			// plan would never settle.
			name:    "equivalent duplicates rejected",
			config:  `resource "pushsecurity_blocked_urls" "test" { patterns = ["example.com", "example.com/*"] }`,
			wantErr: regexp.MustCompile("Duplicate URL pattern"),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resource.UnitTest(t, resource.TestCase{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				Steps: []resource.TestStep{{
					Config:      tc.config,
					PlanOnly:    true,
					ExpectError: tc.wantErr,
				}},
			})
		})
	}
}
