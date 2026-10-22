package provider

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/pushapi"
)

// The app data sources exist so that criteria can be written in terms a
// reviewer understands. The acceptance tests assert only shape and invariants,
// not specific values, because they run against whatever the test tenant holds.
// They only read, so they run in parallel with one another. Go starts parallel
// tests once every other test has finished, so nothing writes alongside them.

func TestAccAppsDataSource(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: `data "pushsecurity_apps" "all" {}`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet("data.pushsecurity_apps.all", "apps.#"),
				sameLength("data.pushsecurity_apps.all", "apps.#", "types.#"),
			),
		}},
	})
}

func TestAccAppDataSource_notFound(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config:      `data "pushsecurity_app" "nope" { type = "TF_ACCEPTANCE_NOT_AN_APP" }`,
			ExpectError: regexp.MustCompile(`No app of type "TF_ACCEPTANCE_NOT_AN_APP" exists`),
		}},
	})
}

func TestAccAppCategoriesDataSource(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: `data "pushsecurity_app_categories" "all" {}`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet("data.pushsecurity_app_categories.all", "categories.#"),
				// The map is the whole point: one entry per category, keyed by
				// name.
				sameLength("data.pushsecurity_app_categories.all", "categories.#", "codes_by_name.%"),
			),
		}},
	})
}

func TestCollectCategories(t *testing.T) {
	// Distinct by code, ordered by name, so a read is stable and does not churn
	// consumers of the list.
	apps := []pushapi.App{
		{Categories: []pushapi.AppCategory{
			{Code: 56, Name: "Productivity Applications", Group: "Technology"},
			{Code: 34, Name: "Information Technology", Group: "Technology"},
		}},
		{Categories: []pushapi.AppCategory{
			{Code: 34, Name: "Information Technology", Group: "Technology"},
			{Code: 9, Name: "Business/Economy", Group: "Business"},
		}},
		{},
	}

	got := collectCategories(apps)
	if len(got) != 3 {
		t.Fatalf("got %d categories, want 3 distinct: %+v", len(got), got)
	}
	want := []string{"Business/Economy", "Information Technology", "Productivity Applications"}
	for i, w := range want {
		if got[i].Name != w {
			t.Errorf("categories[%d] = %q, want %q (ordered by name)", i, got[i].Name, w)
		}
	}
}

func TestFilterApps(t *testing.T) {
	apps := []pushapi.App{
		{Type: "A", Labels: []string{"ai"}, ApprovalStatus: "NOT_REVIEWED"},
		{Type: "B", Labels: []string{"finance", "ai"}, ApprovalStatus: "APPROVED"},
		{Type: "C", ApprovalStatus: "APPROVED"},
	}

	for _, tc := range []struct {
		name     string
		labels   []string
		statuses []string
		want     []string
	}{
		{name: "no filter matches everything", want: []string{"A", "B", "C"}},
		{name: "by label", labels: []string{"ai"}, want: []string{"A", "B"}},
		{name: "any of several labels", labels: []string{"finance", "nope"}, want: []string{"B"}},
		{name: "by status", statuses: []string{"APPROVED"}, want: []string{"B", "C"}},
		{
			// Both filters must apply, not either.
			name: "label and status together", labels: []string{"ai"},
			statuses: []string{"APPROVED"}, want: []string{"B"},
		},
		{name: "no match", labels: []string{"absent"}, want: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := filterApps(apps, tc.labels, tc.statuses)
			if len(got) != len(tc.want) {
				t.Fatalf("got %d apps, want %d: %+v", len(got), len(tc.want), got)
			}
			for i, w := range tc.want {
				if got[i].Type != w {
					t.Errorf("apps[%d] = %q, want %q", i, got[i].Type, w)
				}
			}
		})
	}
}
