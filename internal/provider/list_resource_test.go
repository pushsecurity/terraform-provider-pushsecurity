package provider

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/querycheck"
	"github.com/hashicorp/terraform-plugin-testing/querycheck/queryfilter"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"

	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/provider/controlspec"
)

// terraform query, and the list blocks it reads, arrived in Terraform 1.14.
var queryVersions = []tfversion.TerraformVersionCheck{
	tfversion.SkipBelow(tfversion.Version1_14_0),
}

// queryOnly runs one query step. The step before it gives the working
// directory the provider requirement a query step does not write.
func queryOnly(t *testing.T, query string, checks ...querycheck.QueryResultCheck) {
	t.Helper()
	queryWith(t, testAccProtoV6ProviderFactories, query, checks...)
}

func queryWith(t *testing.T, factories map[string]func() (tfprotov6.ProviderServer, error), query string, checks ...querycheck.QueryResultCheck) {
	t.Helper()
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		TerraformVersionChecks:   queryVersions,
		Steps: []resource.TestStep{
			{Config: `provider "pushsecurity" {}`},
			{Query: true, Config: query, QueryResultChecks: checks},
		},
	})
}

// listWarnings collects the warnings the list resources raise on their
// results. terraform query shows them, but the query checks cannot see them.
type listWarnings struct {
	mu       sync.Mutex
	warnings map[string]string // detail by summary
}

func (l *listWarnings) factories() map[string]func() (tfprotov6.ProviderServer, error) {
	l.warnings = map[string]string{}
	return map[string]func() (tfprotov6.ProviderServer, error){
		"pushsecurity": func() (tfprotov6.ProviderServer, error) {
			srv, err := providerserver.NewProtocol6WithError(New("test")())()
			if err != nil {
				return nil, err
			}
			ls, ok := srv.(listServer)
			if !ok {
				return nil, fmt.Errorf("%T serves no list resources", srv)
			}
			return &listRecordingServer{listServer: ls, log: l}, nil
		},
	}
}

// warned is a query check that a warning with this summary was raised, and
// that its detail holds each of want.
func (l *listWarnings) warned(summary string, want ...string) querycheck.QueryResultCheck {
	return listWarningCheck{log: l, summary: summary, want: want}
}

// notWarned is a query check that no warning with this summary was raised.
func (l *listWarnings) notWarned(summary string) querycheck.QueryResultCheck {
	return listWarningCheck{log: l, summary: summary, absent: true}
}

type listWarningCheck struct {
	log     *listWarnings
	summary string
	want    []string
	absent  bool
}

func (c listWarningCheck) CheckQuery(_ context.Context, _ querycheck.CheckQueryRequest, resp *querycheck.CheckQueryResponse) {
	c.log.mu.Lock()
	defer c.log.mu.Unlock()
	detail, ok := c.log.warnings[c.summary]
	switch {
	case c.absent && ok:
		resp.Error = fmt.Errorf("the warning %q was raised, and must not be", c.summary)
	case !c.absent && !ok:
		resp.Error = fmt.Errorf("no warning %q was raised; warnings: %q", c.summary, c.log.warnings)
	}
	for _, w := range c.want {
		if !strings.Contains(detail, w) {
			resp.Error = fmt.Errorf("the warning %q lacks %q:\n%s", c.summary, w, detail)
		}
	}
}

// listServer is a provider server that serves list resources, which the
// protocol keeps apart from the rest for now.
type listServer interface {
	tfprotov6.ProviderServer
	tfprotov6.ListResourceServer
}

// listRecordingServer passes every request through and records the warnings
// on each list result as Terraform reads it.
type listRecordingServer struct {
	listServer
	log *listWarnings
}

func (p *listRecordingServer) ListResource(ctx context.Context, req *tfprotov6.ListResourceRequest) (*tfprotov6.ListResourceServerStream, error) {
	stream, err := p.listServer.ListResource(ctx, req)
	if stream == nil || stream.Results == nil {
		return stream, err
	}
	results := stream.Results
	stream.Results = func(push func(tfprotov6.ListResourceResult) bool) {
		for r := range results {
			p.log.mu.Lock()
			for _, d := range r.Diagnostics {
				if d.Severity == tfprotov6.DiagnosticSeverityWarning {
					p.log.warnings[d.Summary] = d.Detail
				}
			}
			p.log.mu.Unlock()
			if !push(r) {
				return
			}
		}
	}
	return stream, err
}

const listFileDownloadBlocking = "pushsecurity_file_download_blocking.adopted"

// An empty control is left out: adopting it would make Terraform the owner of
// a control nobody has configured.
func TestListControl_empty(t *testing.T) {
	offlineTenant(t)
	queryOnly(t, `
list "pushsecurity_file_download_blocking" "adopted" {
  provider = pushsecurity
}
`, querycheck.ExpectLength(listFileDownloadBlocking, 0))
}

func TestListControl_includeEmpty(t *testing.T) {
	offlineTenant(t)
	queryOnly(t, `
list "pushsecurity_file_download_blocking" "adopted" {
  provider = pushsecurity
  config {
    include_empty = true
  }
}
`,
		querycheck.ExpectLength(listFileDownloadBlocking, 1),
		querycheck.ExpectIdentity(listFileDownloadBlocking, map[string]knownvalue.Check{
			"id": knownvalue.StringExact("default"),
		}),
		querycheck.ExpectResourceDisplayName(listFileDownloadBlocking, nil,
			knownvalue.StringExact("File download blocking (0 rules)")),
	)
}

func TestListControl_rules(t *testing.T) {
	stub := offlineTenant(t)
	stub.seedControl(controlspec.FileDownloadBlocking,
		map[string]any{
			"name": "Block executables", "enabled": true, "mode": "BLOCK",
			"title": "Download blocked", "subtext": "Not permitted on company devices.",
			"criteria": map[string]any{
				"fileExtensions": map[string]any{"matches": []any{".exe", ".msi"}},
			},
		},
		map[string]any{"name": "Monitor the rest", "enabled": true, "mode": "MONITOR"},
	)
	queryOnly(t, `
list "pushsecurity_file_download_blocking" "adopted" {
  provider         = pushsecurity
  include_resource = true
}
`,
		querycheck.ExpectLength(listFileDownloadBlocking, 1),
		querycheck.ExpectResourceDisplayName(listFileDownloadBlocking, nil,
			knownvalue.StringExact("File download blocking (2 rules)")),
		querycheck.ExpectResourceKnownValues(listFileDownloadBlocking,
			queryfilter.ByResourceIdentity(map[string]knownvalue.Check{"id": knownvalue.StringExact("default")}),
			[]querycheck.KnownValueCheck{
				{Path: tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("name"), KnownValue: knownvalue.StringExact("Block executables")},
				{Path: tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("key"), KnownValue: knownvalue.Null()},
				{Path: tfjsonpath.New("rules").AtSliceIndex(1).AtMapKey("mode"), KnownValue: knownvalue.StringExact("MONITOR")},
			}),
	)
}

const listCustomDetection = "pushsecurity_custom_detection.adopted"

// Results come back in order of detection event type, whatever order the
// tenant holds them in, so that the labels Terraform generates are stable; a
// limit keeps the first of them.
func TestListCustomDetection(t *testing.T) {
	stub := offlineTenant(t)
	monitor := map[string]any{"name": "Monitor", "enabled": true, "mode": "MONITOR", "severity": "LOW"}
	stub.seedDetection("Zip download", testDetectionLogic, monitor)
	stub.seedDetection("Archive upload", testDetectionLogic, monitor)
	stub.seedDetection("Magnet link", testDetectionLogic, monitor)

	queryOnly(t, `
list "pushsecurity_custom_detection" "adopted" {
  provider         = pushsecurity
  include_resource = true
  limit            = 2
}
`,
		querycheck.ExpectLength(listCustomDetection, 2),
		querycheck.ExpectResourceDisplayName(listCustomDetection,
			queryfilter.ByResourceIdentity(map[string]knownvalue.Check{
				"detection_event_type": knownvalue.StringExact("CUSTOM_ARCHIVE_UPLOAD"),
			}), knownvalue.StringExact("Archive upload")),
		querycheck.ExpectResourceKnownValues(listCustomDetection,
			queryfilter.ByResourceIdentity(map[string]knownvalue.Check{
				"detection_event_type": knownvalue.StringExact("CUSTOM_MAGNET_LINK"),
			}),
			[]querycheck.KnownValueCheck{
				{Path: tfjsonpath.New("detection_logic"), KnownValue: knownvalue.StringExact(testDetectionLogic)},
				{Path: tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("severity"), KnownValue: knownvalue.StringExact("LOW")},
			}),
	)
}

// TestListControl_storedWarnings: what the first plan will say about the
// configuration a control holds is reported on the result, named after the
// control, and separated into what will fail plan and what will only warn.
// It is reported without include_resource too, which a plain terraform query
// leaves off.
func TestListControl_storedWarnings(t *testing.T) {
	stub := offlineTenant(t)
	stub.seedControl(controlspec.FileDownloadBlocking, map[string]any{
		"name": "Block remote access tools", "enabled": true, "mode": "MONITOR",
		"criteria": map[string]any{
			"urlPatterns": map[string]any{"matches": []any{"*://*.anydesk.com", "*://example.com:443/*"}},
		},
	})
	log := &listWarnings{}
	queryWith(t, log.factories(), `
list "pushsecurity_file_download_blocking" "adopted" {
  provider = pushsecurity
}
`,
		querycheck.ExpectLength(listFileDownloadBlocking, 1),
		log.warned("File download blocking: configuration the first plan will reject",
			`rules[0] "Block remote access tools" (mode MONITOR), url_patterns "*://*.anydesk.com": `,
			"The API adds /* to a URL pattern written without a path"),
		log.warned("File download blocking: configuration that plans with a warning",
			`rules[0] "Block remote access tools" (mode MONITOR), url_patterns "*://example.com:443/*": `),
	)
}

// TestListControl_stateWarnings: a warning raised while building the result's
// state is named after the control too.
func TestListControl_stateWarnings(t *testing.T) {
	stub := offlineTenant(t)
	stub.seedControl(controlspec.FileDownloadBlocking, map[string]any{
		"name": "Monitor", "enabled": true, "mode": "MONITOR",
		"criteria": map[string]any{
			"employeeIds": map[string]any{"matches": []any{"00000000-0000-0000-0000-00000000dead"}},
		},
	})
	log := &listWarnings{}
	queryWith(t, log.factories(), `
list "pushsecurity_file_download_blocking" "adopted" {
  provider         = pushsecurity
  include_resource = true
}
`,
		log.warned("File download blocking: Rule names an employee the tenant no longer holds",
			"00000000-0000-0000-0000-00000000dead"),
		log.notWarned("File download blocking: configuration the first plan will reject"),
	)
}

// TestListCustomDetection_storedWarnings: two detections with the same
// problem get warnings Terraform will not fold into one, because each names
// its detection.
func TestListCustomDetection_storedWarnings(t *testing.T) {
	stub := offlineTenant(t)
	noSeverity := map[string]any{"name": "Monitor", "enabled": true, "mode": "MONITOR"}
	stub.seedDetection("Archive upload", testDetectionLogic, noSeverity)
	stub.seedDetection("Magnet link", testDetectionLogic, noSeverity)
	log := &listWarnings{}
	queryWith(t, log.factories(), `
list "pushsecurity_custom_detection" "adopted" {
  provider         = pushsecurity
  include_resource = true
}
`,
		querycheck.ExpectLength(listCustomDetection, 2),
		log.warned("Archive upload: configuration the first plan will reject",
			`rules[0] "Monitor" (mode MONITOR): `, "severity"),
		log.warned("Magnet link: configuration the first plan will reject",
			`rules[0] "Monitor" (mode MONITOR): `, "severity"),
	)
}

const listBlockedURLs = "pushsecurity_blocked_urls.adopted"

func TestListBlockedURLs_empty(t *testing.T) {
	offlineTenant(t)
	queryOnly(t, `
list "pushsecurity_blocked_urls" "adopted" {
  provider = pushsecurity
}
`, querycheck.ExpectLength(listBlockedURLs, 0))
}

func TestListBlockedURLs(t *testing.T) {
	stub := offlineTenant(t)
	stub.addBlockedURL("*://example.com/*")
	stub.addBlockedURL("*://*.example.org/downloads*")
	queryOnly(t, `
list "pushsecurity_blocked_urls" "adopted" {
  provider         = pushsecurity
  include_resource = true
}
`,
		querycheck.ExpectLength(listBlockedURLs, 1),
		querycheck.ExpectIdentity(listBlockedURLs, map[string]knownvalue.Check{
			"id": knownvalue.StringExact("default"),
		}),
		querycheck.ExpectResourceDisplayName(listBlockedURLs, nil,
			knownvalue.StringExact("Blocked URLs (2 patterns)")),
		querycheck.ExpectResourceKnownValues(listBlockedURLs,
			queryfilter.ByResourceIdentity(map[string]knownvalue.Check{"id": knownvalue.StringExact("default")}),
			[]querycheck.KnownValueCheck{
				// In the form a configuration writes them, which is the form
				// an import reads them back in.
				{Path: tfjsonpath.New("patterns"), KnownValue: knownvalue.SetExact([]knownvalue.Check{
					knownvalue.StringExact("example.com"),
					knownvalue.StringExact("*.example.org/downloads*"),
				})},
			}),
	)
}

const listSettings = "pushsecurity_settings.adopted"

// Every tenant has settings, so there is always a result.
func TestListSettings(t *testing.T) {
	stub := offlineTenant(t)
	stub.seedSettings([]string{"example.com", "example.org"}, false)
	queryOnly(t, `
list "pushsecurity_settings" "adopted" {
  provider         = pushsecurity
  include_resource = true
}
`,
		querycheck.ExpectLength(listSettings, 1),
		querycheck.ExpectResourceDisplayName(listSettings, nil, knownvalue.StringExact("Settings")),
		querycheck.ExpectResourceKnownValues(listSettings,
			queryfilter.ByResourceIdentity(map[string]knownvalue.Check{"id": knownvalue.StringExact("default")}),
			[]querycheck.KnownValueCheck{
				{Path: tfjsonpath.New("monitored_domains"), KnownValue: knownvalue.SetExact([]knownvalue.Check{
					knownvalue.StringExact("example.com"),
					knownvalue.StringExact("example.org"),
				})},
				{Path: tfjsonpath.New("monitor_all_domains"), KnownValue: knownvalue.Bool(false)},
			}),
	)
}

const listEmployee = "pushsecurity_employee.adopted"

// The filters are the employees data source's, and the identity is the
// address lower-cased, as the resource's is.
func TestListEmployee_filtered(t *testing.T) {
	stub := offlineTenant(t)
	stub.addEmployee("Ada@Example.com", "Ada", "Lovelace", true, "Engineering")
	stub.addEmployee("grace@example.com", "Grace", "Hopper", true, "Engineering", "Navy")
	stub.addEmployee("alan@example.com", "Alan", "Turing", true, "Research")
	queryOnly(t, `
list "pushsecurity_employee" "adopted" {
  provider         = pushsecurity
  include_resource = true
  config {
    groups = ["Engineering"]
  }
}
`,
		querycheck.ExpectLength(listEmployee, 2),
		querycheck.ExpectIdentity(listEmployee, map[string]knownvalue.Check{
			"email": knownvalue.StringExact("ada@example.com"),
		}),
		querycheck.ExpectResourceDisplayName(listEmployee,
			queryfilter.ByResourceIdentity(map[string]knownvalue.Check{"email": knownvalue.StringExact("ada@example.com")}),
			knownvalue.StringExact("Ada@Example.com")),
		querycheck.ExpectResourceKnownValues(listEmployee,
			queryfilter.ByResourceIdentity(map[string]knownvalue.Check{"email": knownvalue.StringExact("grace@example.com")}),
			[]querycheck.KnownValueCheck{
				{Path: tfjsonpath.New("first_name"), KnownValue: knownvalue.StringExact("Grace")},
				{Path: tfjsonpath.New("licensed"), KnownValue: knownvalue.Bool(true)},
				{Path: tfjsonpath.New("allow_unlicense"), KnownValue: knownvalue.Bool(false)},
			}),
	)
}

// A limit keeps the first employees by address, and the result says how many
// were left out.
func TestListEmployee_limit(t *testing.T) {
	stub := offlineTenant(t)
	for _, e := range []string{"cat@example.com", "ada@example.com", "bob@example.com"} {
		stub.addEmployee(e, "First", "Last", true)
	}
	log := &listWarnings{}
	queryWith(t, log.factories(), `
list "pushsecurity_employee" "adopted" {
  provider = pushsecurity
  limit    = 2
}
`,
		querycheck.ExpectLength(listEmployee, 2),
		querycheck.ExpectResourceDisplayName(listEmployee,
			queryfilter.ByResourceIdentity(map[string]knownvalue.Check{"email": knownvalue.StringExact("bob@example.com")}),
			knownvalue.StringExact("bob@example.com")),
		log.warned("Employees: 2 of 3 returned", "Narrow the list with email, groups or licensed"),
	)
}

func TestListEmployee_email(t *testing.T) {
	stub := offlineTenant(t)
	stub.addEmployee("jo@example.com", "Jo", "March", true)
	stub.addEmployee("jojo@example.com", "Jojo", "March", true)
	queryOnly(t, `
list "pushsecurity_employee" "adopted" {
  provider = pushsecurity
  config {
    email = "JO@example.com"
  }
}
`,
		querycheck.ExpectLength(listEmployee, 1),
		querycheck.ExpectIdentity(listEmployee, map[string]knownvalue.Check{
			"email": knownvalue.StringExact("jo@example.com"),
		}),
	)
}

func TestControlName(t *testing.T) {
	for spec, want := range map[*controlspec.Spec]string{
		&controlspec.FileDownloadBlocking: "File download blocking",
		&controlspec.MfaEnforcement:       "MFA enforcement",
		&controlspec.AppBannerURLPattern:  "App banner URL pattern",
	} {
		if got := controlName(*spec); got != want {
			t.Errorf("controlName(%s) = %q, want %q", spec.TypeName, got, want)
		}
	}
	for name, want := range map[string]string{
		"File download blocking": "file download blocking",
		"MFA enforcement":        "MFA enforcement",
		"App banner URL pattern": "app banner URL pattern",
	} {
		if got := inSentence(name); got != want {
			t.Errorf("inSentence(%q) = %q, want %q", name, got, want)
		}
	}
	// No acronym is left in lower case in any control's name.
	for _, spec := range controlspec.All {
		for _, w := range strings.Fields(controlName(spec)) {
			if acronyms[w] != "" {
				t.Errorf("controlName(%s) = %q, which spells %q in lower case", spec.TypeName, controlName(spec), w)
			}
		}
	}
}
