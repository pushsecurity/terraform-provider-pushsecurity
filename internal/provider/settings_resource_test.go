package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/pushapi"
)

const settingsAddr = "pushsecurity_settings.this"

// TestSettings_lifecycle drives pushsecurity_settings through adoption, an update of
// each attribute, import, a change made in the console, and destroy.
func TestSettings_lifecycle(t *testing.T) {
	stub := offlineTenant(t)
	log := &diagnosticLog{}
	stub.seedSettings([]string{"example.com"}, true)

	const domainsOnly = `
resource "pushsecurity_settings" "this" {
  monitored_domains = ["example.net", "example.com"]
}
`
	const both = `
resource "pushsecurity_settings" "this" {
  monitored_domains   = ["example.net", "example.com"]
  monitor_all_domains = false
}
`

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: log.factories(),
		Steps: []resource.TestStep{
			{
				// Adoption sends what is configured and nothing else, and
				// reads the rest from the tenant.
				Config: domainsOnly,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(settingsAddr, "monitored_domains.#", "2"),
					resource.TestCheckTypeSetElemAttr(settingsAddr, "monitored_domains.*", "example.com"),
					resource.TestCheckTypeSetElemAttr(settingsAddr, "monitored_domains.*", "example.net"),
					resource.TestCheckResourceAttr(settingsAddr, "monitor_all_domains", "true"),
					checkSettingsUpdates(stub,
						map[string]any{"monitoredDomains": []any{"example.com", "example.net"}}),
					checkTenantDomains(stub, "example.com", "example.net"),
					// Nothing the tenant held was dropped.
					checkNotWarned(log, "Monitored domains will be removed"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
			{
				// Changing the toggle sends the toggle alone: the list is
				// unchanged, so it is not sent again.
				Config: both,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(settingsAddr, "monitor_all_domains", "false"),
					checkSettingsUpdates(stub,
						map[string]any{"monitoredDomains": []any{"example.com", "example.net"}},
						map[string]any{"monitorAllDomains": false}),
					func(*terraform.State) error {
						if stub.monitorAllDomains() {
							return errors.New("the tenant still monitors all domains")
						}
						return nil
					},
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
			{
				ResourceName:                         settingsAddr,
				ImportState:                          true,
				ImportStateId:                        "default",
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "monitor_all_domains",
			},
			{
				// A domain added in the console is not in the configuration,
				// so the apply removes it, and the plan says what that does.
				PreConfig: func() {
					stub.seedSettings([]string{"console.example.org", "example.com", "example.net"}, false)
				},
				Config: both,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(settingsAddr, plancheck.ResourceActionUpdate),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					checkWarned(log, "Monitored domains will be removed"),
					checkTenantDomains(stub, "example.com", "example.net"),
				),
			},
			{
				// Destroy leaves the settings exactly as they are.
				Config: `# pushsecurity_settings.this removed`,
				Check: resource.ComposeAggregateTestCheckFunc(
					checkWarned(log, "The settings are left as they are"),
					checkTenantDomains(stub, "example.com", "example.net"),
					func(*terraform.State) error {
						if n := len(stub.settingsUpdates()); n != 3 {
							return fmt.Errorf("%d settings updates by the end, want 3: destroy must not send one", n)
						}
						if stub.monitorAllDomains() {
							return errors.New("destroy turned monitor_all_domains back on")
						}
						return nil
					},
				),
			},
		},
	})
}

// TestSettings_adoptionWarnsAboutDomainsItRemoves: a create replaces the
// tenant's list, and its plan shows only the configured one, so the domains
// it drops have to be named some other way.
func TestSettings_adoptionWarnsAboutDomainsItRemoves(t *testing.T) {
	stub := offlineTenant(t)
	log := &diagnosticLog{}
	stub.seedSettings([]string{"example.org", "example.com"}, true)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: log.factories(),
		Steps: []resource.TestStep{
			{
				Config: `
resource "pushsecurity_settings" "this" {
  monitored_domains = ["example.com"]
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					checkWarned(log, "Monitored domains will be removed"),
					checkTenantDomains(stub, "example.com"),
				),
			},
		},
	})
}

// TestSettings_emptyListClearsTheDomains: an empty list is a value, sent as
// [], not a field left out.
func TestSettings_emptyListClearsTheDomains(t *testing.T) {
	stub := offlineTenant(t)
	log := &diagnosticLog{}
	stub.seedSettings([]string{"example.com"}, true)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: log.factories(),
		Steps: []resource.TestStep{
			{
				Config: `
resource "pushsecurity_settings" "this" {
  monitored_domains = []
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(settingsAddr, "monitored_domains.#", "0"),
					checkSettingsUpdates(stub, map[string]any{"monitoredDomains": []any{}}),
					checkTenantDomains(stub),
					checkWarned(log, "Monitored domains will be removed"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
		},
	})
}

// TestSettings_unsetAttributeIsLeftToTheTenant: an attribute that is not
// configured is read, never sent, and a console change to it plans nothing.
func TestSettings_unsetAttributeIsLeftToTheTenant(t *testing.T) {
	stub := offlineTenant(t)
	stub.seedSettings([]string{"example.com"}, true)

	const config = `
resource "pushsecurity_settings" "this" {
  monitor_all_domains = false
}
`
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(settingsAddr, "monitored_domains.#", "1"),
					resource.TestCheckTypeSetElemAttr(settingsAddr, "monitored_domains.*", "example.com"),
					checkSettingsUpdates(stub, map[string]any{"monitorAllDomains": false}),
				),
			},
			{
				PreConfig: func() {
					stub.seedSettings([]string{"example.com", "example.org"}, false)
				},
				Config:   config,
				PlanOnly: true,
			},
			{
				// The refresh picked the console's domain up, and nothing
				// was sent for it.
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(settingsAddr, "monitored_domains.#", "2"),
					checkSettingsUpdates(stub, map[string]any{"monitorAllDomains": false}),
					checkTenantDomains(stub, "example.com", "example.org"),
				),
			},
		},
	})
}

// TestSettings_rejectedDuringPlan: everything here fails while the
// configuration is validated, before any request is made.
func TestSettings_rejectedDuringPlan(t *testing.T) {
	offlineTenant(t)

	cases := []struct {
		name, config string
		want         *regexp.Regexp
	}{
		{
			name:   "nothing to manage",
			config: `resource "pushsecurity_settings" "this" {}`,
			want:   regexp.MustCompile(`Missing Attribute Configuration`),
		},
		{
			name:   "capitals",
			config: `resource "pushsecurity_settings" "this" { monitored_domains = ["Example.com"] }`,
			want:   regexp.MustCompile(`Write "Example.com" as "example.com"`),
		},
		{
			name:   "wildcard",
			config: `resource "pushsecurity_settings" "this" { monitored_domains = ["*.example.com"] }`,
			want:   regexp.MustCompile(`Invalid monitored domain`),
		},
		{
			name:   "scheme",
			config: `resource "pushsecurity_settings" "this" { monitored_domains = ["https://example.com"] }`,
			want:   regexp.MustCompile(`Invalid monitored domain`),
		},
		{
			name: "too many",
			config: `resource "pushsecurity_settings" "this" {
  monitored_domains = [for i in range(101) : "d${i}.example.com"]
}`,
			want: regexp.MustCompile(`at most 100`),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resource.UnitTest(t, resource.TestCase{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				Steps: []resource.TestStep{
					{Config: tc.config, PlanOnly: true, ExpectError: tc.want},
				},
			})
		})
	}
}

// TestSettings_refusalPointsAtTheAttribute: a value the API refuses that the
// plan could not catch fails the apply with the API's reason, attached to the
// attribute that carries it rather than to the resource as a whole, and
// nothing in the tenant changes.
func TestSettings_refusalPointsAtTheAttribute(t *testing.T) {
	stub := offlineTenant(t)
	stub.seedSettings([]string{"example.org"}, true)
	stub.refuseNextSettingsUpdate(map[string]any{
		"monitoredDomains": map[string]any{"0": []string{"Not a domain this tenant may monitor."}},
	})

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: `
resource "pushsecurity_settings" "this" {
  monitored_domains = ["example.com"]
}
`,
			ExpectError: regexp.MustCompile(`(?s)Push API rejected the settings` +
				`.*monitored_domains\s+=\s+\["example.com"\]` +
				`.*monitoredDomains\.0:\s+Not\s+a\s+domain\s+this\s+tenant\s+may\s+monitor`),
		}},
	})
	if got := stub.monitoredDomains(); !sameStrings(got, []string{"example.org"}) {
		t.Errorf("the tenant monitors %q after a refused update, want only example.org", got)
	}
}

// TestValidMonitoredDomain holds the rule to the API's: dot-separated labels
// of letters, digits and hyphens, a letters-only top-level domain of 2 to 15,
// and no public-suffix awareness.
func TestValidMonitoredDomain(t *testing.T) {
	valid := []string{
		"example.com",
		"a.bc",
		"mail.example.co.uk",
		"co.uk",
		"1password.com",
		"123.example.com",
		"my-company.example",
		"xn--bcher-kva.example",
		"EXAMPLE.COM", // case is a separate check
		strings.Repeat("a", 63) + ".com",
		"example.abcdefghijklmno", // a 15-letter top-level domain
	}
	invalid := []string{
		"",
		"example",
		"example.c",
		"example.abcdefghijklmnop", // 16 letters
		"example.123",
		"example.xn--p1ai",
		"-example.com",
		"example-.com",
		"exa_mple.com",
		"*.example.com",
		"example.com.",
		".example.com",
		"example..com",
		"https://example.com",
		"example.com/path",
		"example.com:443",
		" example.com",
		strings.Repeat("a", 64) + ".com",
	}
	for _, d := range valid {
		if !validMonitoredDomain(d) {
			t.Errorf("validMonitoredDomain(%q) = false, want true", d)
		}
	}
	for _, d := range invalid {
		if validMonitoredDomain(d) {
			t.Errorf("validMonitoredDomain(%q) = true, want false", d)
		}
	}
}

// TestAccSettings_roundTrip applies the tenant's own settings back to it. It
// proves the read and write shapes against the real API without changing
// anything: no domain is added or removed, so no account is marked or
// unmarked, and destroy leaves the settings alone.
func TestAccSettings_roundTrip(t *testing.T) {
	if os.Getenv(resource.EnvTfAcc) == "" {
		t.Skipf("acceptance test; set %s to run it", resource.EnvTfAcc)
	}
	testAccPreCheck(t)

	client, err := pushapi.New(os.Getenv(envBaseURL), os.Getenv(envAPIKey))
	if err != nil {
		t.Fatalf("building a client: %v", err)
	}
	before, err := client.GetSettings(context.Background())
	if err != nil {
		t.Fatalf("reading the tenant's settings: %v", err)
	}

	quoted := make([]string, len(before.MonitoredDomains))
	for i, d := range before.MonitoredDomains {
		quoted[i] = fmt.Sprintf("%q", d)
	}
	config := fmt.Sprintf(`
resource "pushsecurity_settings" "this" {
  monitored_domains   = [%s]
  monitor_all_domains = %t
}
`, strings.Join(quoted, ", "), before.MonitorAllDomains)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(settingsAddr, "monitored_domains.#",
						strconv.Itoa(len(before.MonitoredDomains))),
					resource.TestCheckResourceAttr(settingsAddr, "monitor_all_domains",
						strconv.FormatBool(before.MonitorAllDomains)),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
			{
				ResourceName:                         settingsAddr,
				ImportState:                          true,
				ImportStateId:                        "default",
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "monitor_all_domains",
			},
		},
		CheckDestroy: func(*terraform.State) error {
			after, err := client.GetSettings(context.Background())
			if err != nil {
				return err
			}
			if !sameStrings(before.MonitoredDomains, after.MonitoredDomains) ||
				before.MonitorAllDomains != after.MonitorAllDomains {
				return fmt.Errorf("the settings changed: before %+v, after %+v", before, after)
			}
			return nil
		},
	})
}

// Settings on the stub tenant.

// newTenantSettings is what a new tenant starts with.
func newTenantSettings() map[string]any {
	return map[string]any{"monitoredDomains": []any{}, "monitorAllDomains": true}
}

func (s *tenantStub) serveSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.settings)

	case http.MethodPatch:
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			invalidInput(w, map[string]any{"_schema": []string{"Invalid input type."}})
			return
		}

		errs := map[string]any{}
		for k := range body {
			if k != "monitoredDomains" && k != "monitorAllDomains" {
				errs[k] = []string{"Unknown field."}
			}
		}
		rawDomains, hasDomains := body["monitoredDomains"]
		rawAll, hasAll := body["monitorAllDomains"]
		if !hasDomains && !hasAll {
			errs["_schema"] = []string{`At least one of "monitoredDomains" or "monitorAllDomains" must be provided.`}
		}
		var domains []string
		if hasDomains {
			items, ok := rawDomains.([]any)
			switch {
			case !ok:
				errs["monitoredDomains"] = []string{"Not a valid list."}
			case len(items) > pushapi.MaxMonitoredDomains:
				errs["monitoredDomains"] = []string{"Longer than maximum length 100."}
			}
			for _, it := range items {
				d, ok := it.(string)
				if !ok {
					errs["monitoredDomains"] = []string{"Not a valid string."}
					break
				}
				domains = append(domains, d)
			}
		}
		if _, ok := rawAll.(bool); hasAll && !ok {
			errs["monitorAllDomains"] = []string{"Not a valid boolean."}
		}
		if len(errs) == 0 && s.settingsRefusal != nil {
			errs, s.settingsRefusal = s.settingsRefusal, nil
		}
		if len(errs) > 0 {
			invalidInput(w, errs)
			return
		}

		s.settingsPatches = append(s.settingsPatches, body)
		if hasDomains {
			seen := map[string]bool{}
			stored := []any{}
			for _, d := range domains {
				d = strings.ToLower(d)
				if !seen[d] {
					seen[d] = true
					stored = append(stored, d)
				}
			}
			s.settings["monitoredDomains"] = stored
		}
		if hasAll {
			s.settings["monitorAllDomains"] = rawAll
		}
		writeJSON(w, http.StatusOK, s.settings)

	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"status": "METHOD_NOT_ALLOWED"})
	}
}

// seedSettings writes the settings straight into the tenant, without
// Terraform: the stand-in for a change made in the console.
func (s *tenantStub) seedSettings(domains []string, monitorAll bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stored := make([]any, len(domains))
	for i, d := range domains {
		stored[i] = d
	}
	s.settings = map[string]any{"monitoredDomains": stored, "monitorAllDomains": monitorAll}
}

// refuseNextSettingsUpdate makes the next PATCH that would be accepted fail
// validation with these field errors instead: the stand-in for a value the
// API refuses that the provider could not check during plan.
func (s *tenantStub) refuseNextSettingsUpdate(errs map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.settingsRefusal = errs
}

// monitoredDomains returns the tenant's monitored domains, sorted.
func (s *tenantStub) monitoredDomains() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	items, _ := s.settings["monitoredDomains"].([]any)
	out := make([]string, 0, len(items))
	for _, it := range items {
		out = append(out, it.(string))
	}
	sort.Strings(out)
	return out
}

func (s *tenantStub) monitorAllDomains() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, _ := s.settings["monitorAllDomains"].(bool)
	return v
}

// settingsUpdates returns the body of every accepted PATCH /v1/settings so
// far, in order.
func (s *tenantStub) settingsUpdates() []map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]map[string]any(nil), s.settingsPatches...)
}

// checkSettingsUpdates asserts the bodies of every settings update so far.
func checkSettingsUpdates(stub *tenantStub, want ...map[string]any) resource.TestCheckFunc {
	return func(*terraform.State) error {
		got := stub.settingsUpdates()
		if len(got) == 0 && len(want) == 0 {
			return nil
		}
		if !reflect.DeepEqual(got, want) {
			return fmt.Errorf("settings updates = %v, want %v", got, want)
		}
		return nil
	}
}

// checkTenantDomains asserts the tenant's monitored domains, in any order.
func checkTenantDomains(stub *tenantStub, want ...string) resource.TestCheckFunc {
	return func(*terraform.State) error {
		if got := stub.monitoredDomains(); !sameStrings(got, want) {
			return fmt.Errorf("the tenant monitors %q, want %q", got, want)
		}
		return nil
	}
}

func sameStrings(a, b []string) bool {
	x := append([]string(nil), a...)
	y := append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	return len(x) == len(y) && (len(x) == 0 || reflect.DeepEqual(x, y))
}
