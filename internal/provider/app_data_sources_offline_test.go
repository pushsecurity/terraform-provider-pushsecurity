package provider

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// The tests in this file read the app data sources against tenantStub,
// seeded with a known inventory. The TestAcc tests read whatever a real
// tenant holds, so they can assert only what is true of any tenant; here the
// values themselves are asserted, and the inventory spans several pages.

// testInventory is five apps, three pages at the stub's page size. Miro has
// not been reviewed: a real tenant served such an app with a null approval
// status and no labels.
func testInventory() []map[string]any {
	it := map[string]any{"code": 34, "name": "Information Technology", "group": "Technology"}
	productivity := map[string]any{"code": 56, "name": "Productivity Applications", "group": "Technology"}
	ai := map[string]any{"code": 112, "name": "Generative AI", "group": "Technology"}
	finance := map[string]any{"code": 9, "name": "Business/Economy", "group": "Business"}

	return []map[string]any{
		inventoryApp("app-1", "ZAPIER", "Zapier", "APPROVED", "MEDIUM", []any{"Automation"}, productivity),
		inventoryApp("app-2", "OPENAI_CHATGPT", "ChatGPT", "UNDER_REVIEW", "HIGH", []any{"AI", "Chat"}, ai),
		inventoryApp("app-3", "MIRO", "Miro", nil, nil, []any{}, it, productivity),
		inventoryApp("app-4", "ANTHROPIC_CLAUDE", "Claude", "APPROVED", "HIGH", []any{"AI"}, ai, it),
		inventoryApp("app-5", "XERO", "Xero", "NOT_APPROVED", "HIGH", []any{"Finance"}, finance),
	}
}

func inventoryApp(id, appType, name string, approval, sensitivity any, labels []any, categories ...map[string]any) map[string]any {
	cats := make([]any, 0, len(categories))
	for _, c := range categories {
		cats = append(cats, c)
	}
	return map[string]any{
		"id": id, "type": appType, "friendlyName": name,
		"approvalStatus": approval, "sensitivityLevel": sensitivity,
		"ownerId": nil, "notes": nil, "description": nil,
		"website":           "https://" + id + ".example.com",
		"labels":            labels,
		"creationTimestamp": 1760000000,
		"categories":        cats,
	}
}

// TestAppsDataSource is TestAccAppsDataSource without the tenant, plus the
// two filters, alone and together.
func TestAppsDataSource(t *testing.T) {
	stub := offlineTenant(t)
	stub.seedApps(testInventory()...)
	const all, ai, approved, both = "data.pushsecurity_apps.all", "data.pushsecurity_apps.ai",
		"data.pushsecurity_apps.approved", "data.pushsecurity_apps.approved_ai"

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: `
data "pushsecurity_apps" "all" {}

data "pushsecurity_apps" "ai" {
  labels = ["AI", "Finance"]
}

data "pushsecurity_apps" "approved" {
  approval_statuses = ["APPROVED"]
}

data "pushsecurity_apps" "approved_ai" {
  labels            = ["AI"]
  approval_statuses = ["APPROVED"]
}`,
			Check: resource.ComposeAggregateTestCheckFunc(
				// Every page, ordered by type.
				resource.TestCheckResourceAttr(all, "apps.#", "5"),
				sameLength(all, "apps.#", "types.#"),
				resource.TestCheckResourceAttr(all, "apps.0.type", "ANTHROPIC_CLAUDE"),
				resource.TestCheckResourceAttr(all, "apps.1.type", "MIRO"),
				resource.TestCheckResourceAttr(all, "apps.2.type", "OPENAI_CHATGPT"),
				resource.TestCheckResourceAttr(all, "apps.3.type", "XERO"),
				resource.TestCheckResourceAttr(all, "apps.4.type", "ZAPIER"),
				resource.TestCheckResourceAttr(all, "all_labels.#", "4"),
				// An unreviewed app reads as empty strings, not an error.
				resource.TestCheckResourceAttr(all, "apps.1.approval_status", ""),
				resource.TestCheckResourceAttr(all, "apps.1.sensitivity_level", ""),
				resource.TestCheckResourceAttr(all, "apps.1.labels.#", "0"),
				// Category codes are strings, which is what criteria match on.
				resource.TestCheckResourceAttr(all, "apps.1.category_codes.#", "2"),
				resource.TestCheckTypeSetElemAttr(all, "apps.1.category_codes.*", "34"),
				resource.TestCheckTypeSetElemAttr(all, "apps.1.category_names.*", "Information Technology"),

				// Any of several labels.
				resource.TestCheckResourceAttr(ai, "apps.#", "3"),
				resource.TestCheckTypeSetElemAttr(ai, "types.*", "XERO"),
				resource.TestCheckTypeSetElemAttr(ai, "all_labels.*", "Chat"),
				resource.TestCheckResourceAttr(approved, "apps.#", "2"),
				resource.TestCheckTypeSetElemAttr(approved, "types.*", "ZAPIER"),
				// Both filters at once, not either.
				resource.TestCheckResourceAttr(both, "apps.#", "1"),
				resource.TestCheckResourceAttr(both, "apps.0.type", "ANTHROPIC_CLAUDE"),
			),
		}},
	})
}

// TestAppDataSource reads one app in full. Its failures are covered by the
// tests that follow.
func TestAppDataSource(t *testing.T) {
	stub := offlineTenant(t)
	stub.seedApps(testInventory()...)
	const claude = "data.pushsecurity_app.claude"

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: `data "pushsecurity_app" "claude" { type = "ANTHROPIC_CLAUDE" }`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr(claude, "id", "app-4"),
				resource.TestCheckResourceAttr(claude, "friendly_name", "Claude"),
				resource.TestCheckResourceAttr(claude, "approval_status", "APPROVED"),
				resource.TestCheckResourceAttr(claude, "sensitivity_level", "HIGH"),
				resource.TestCheckResourceAttr(claude, "website", "https://app-4.example.com"),
				resource.TestCheckResourceAttr(claude, "labels.#", "1"),
				resource.TestCheckTypeSetElemAttr(claude, "category_codes.*", "112"),
				resource.TestCheckTypeSetElemAttr(claude, "category_names.*", "Generative AI"),
			),
		}},
	})
}

// TestAppDataSource_notFound is TestAccAppDataSource_notFound without the
// tenant.
func TestAppDataSource_notFound(t *testing.T) {
	stub := offlineTenant(t)
	stub.seedApps(testInventory()...)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config:      `data "pushsecurity_app" "nope" { type = "TF_ACCEPTANCE_NOT_AN_APP" }`,
			ExpectError: regexp.MustCompile(`No app of type "TF_ACCEPTANCE_NOT_AN_APP" exists`),
		}},
	})
}

// TestAppDataSource_ambiguous: no live test has seen two apps share a type,
// but if a tenant holds them the lookup refuses to pick one.
func TestAppDataSource_ambiguous(t *testing.T) {
	stub := offlineTenant(t)
	stub.seedApps(testInventory()...)
	stub.seedApps(inventoryApp("app-6", "MIRO", "Miro (second)", "APPROVED", "LOW", []any{}))

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config:      `data "pushsecurity_app" "miro" { type = "MIRO" }`,
			ExpectError: regexp.MustCompile(`2 apps have the type "MIRO"`),
		}},
	})
}

// TestAppCategoriesDataSource is TestAccAppCategoriesDataSource without the
// tenant: one entry per category across every page, by code, ordered by name.
func TestAppCategoriesDataSource(t *testing.T) {
	stub := offlineTenant(t)
	stub.seedApps(testInventory()...)
	const all = "data.pushsecurity_app_categories.all"

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: `data "pushsecurity_app_categories" "all" {}`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr(all, "categories.#", "4"),
				sameLength(all, "categories.#", "codes_by_name.%"),
				resource.TestCheckResourceAttr(all, "categories.0.name", "Business/Economy"),
				resource.TestCheckResourceAttr(all, "categories.0.code", "9"),
				resource.TestCheckResourceAttr(all, "categories.0.group", "Business"),
				resource.TestCheckResourceAttr(all, "categories.1.name", "Generative AI"),
				resource.TestCheckResourceAttr(all, "categories.2.name", "Information Technology"),
				resource.TestCheckResourceAttr(all, "categories.3.name", "Productivity Applications"),
				resource.TestCheckResourceAttr(all, "codes_by_name.Generative AI", "112"),
				resource.TestCheckResourceAttr(all, "codes_by_name.Productivity Applications", "56"),
			),
		}},
	})
}

// TestAppsDataSource_sameTypeOrderedByID: apps that share a type, which the
// API does not rule out, are ordered by identifier, so that the order the API
// serves them in cannot reorder the list between reads, and their type is
// listed once.
func TestAppsDataSource_sameTypeOrderedByID(t *testing.T) {
	stub := offlineTenant(t)
	stub.seedApps(
		inventoryApp("app-9", "MIRO", "Miro", "APPROVED", "LOW", []any{}),
		inventoryApp("app-3", "MIRO", "Miro (second)", "APPROVED", "LOW", []any{}),
		inventoryApp("app-5", "MIRO", "Miro (third)", "APPROVED", "LOW", []any{}),
	)
	const all = "data.pushsecurity_apps.all"

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: `data "pushsecurity_apps" "all" {}`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr(all, "apps.0.id", "app-3"),
				resource.TestCheckResourceAttr(all, "apps.1.id", "app-5"),
				resource.TestCheckResourceAttr(all, "apps.2.id", "app-9"),
				resource.TestCheckResourceAttr(all, "types.#", "1"),
			),
		}},
	})
}

// TestAppCategoriesDataSource_sharedName: a category name that two codes
// carry cannot say which one a criterion means, so codes_by_name leaves it out
// and warns, rather than picking one, while categories lists both, ordered by
// code.
func TestAppCategoriesDataSource_sharedName(t *testing.T) {
	stub := offlineTenant(t)
	log := &diagnosticLog{}
	sharedHigh := map[string]any{"code": 7, "name": "Shared", "group": "Business"}
	sharedLow := map[string]any{"code": 5, "name": "Shared", "group": "Technology"}
	unique := map[string]any{"code": 9, "name": "Unique", "group": "Technology"}
	stub.seedApps(
		inventoryApp("app-1", "ZAPIER", "Zapier", "APPROVED", "LOW", []any{}, sharedHigh),
		inventoryApp("app-2", "MIRO", "Miro", "APPROVED", "LOW", []any{}, sharedLow, unique),
	)
	const all = "data.pushsecurity_app_categories.all"

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: log.factories(),
		Steps: []resource.TestStep{{
			Config: `data "pushsecurity_app_categories" "all" {}`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr(all, "categories.#", "3"),
				resource.TestCheckResourceAttr(all, "categories.0.code", "5"),
				resource.TestCheckResourceAttr(all, "categories.1.code", "7"),
				resource.TestCheckResourceAttr(all, "categories.2.name", "Unique"),
				resource.TestCheckResourceAttr(all, "codes_by_name.%", "1"),
				resource.TestCheckResourceAttr(all, "codes_by_name.Unique", "9"),
				resource.TestCheckNoResourceAttr(all, "codes_by_name.Shared"),
				checkWarned(log, "App category name carried by more than one code"),
			),
		}},
	})
}
