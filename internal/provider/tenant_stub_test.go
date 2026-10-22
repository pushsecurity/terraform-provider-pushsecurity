package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/provider/controlspec"
	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/pushapi"
)

// tenantStub is an in-memory Push tenant for the lifecycle tests that run
// without a real one: enough of the API for an actual terraform plan and
// apply to drive the resources through create, read, update, import and
// destroy on every pull request, where the acceptance tests only run on the
// release pull request into main.
//
// It reproduces the behaviours the provider has to reconcile with. The
// acceptance tests remain the proof that the stub and the API agree, and an
// entry says so where they do not reach:
//
//   - A path or method the API does not serve is refused with a 403 naming
//     MissingAuthenticationTokenException, whatever the key. Otherwise a key
//     that is not shaped like a Push API key is rejected with a 401, and a
//     well-formed key the tenant does not hold is refused with a 403 naming
//     AccessDeniedException.
//   - A control configuration is one document per control, replaced whole by
//     PUT. Rules keep the order they were sent in. A rule sent without an
//     identifier is assigned one; a rule sent with one keeps it.
//   - The server fills in what a rule omitted: profileScope ["ALL"] on every
//     control that supports it, action INCLUDE on an excludable condition sent
//     without one, each field's server default, and the enum it derives from
//     a custom content pattern's name. Enum sets come back in a different
//     order from the one sent, and ignoredHosts sorted.
//   - Employees are listed with an email filter that returns every address
//     containing the one asked for, spelled in the same case, exact filters
//     on licence and ChatOps, and a groups filter that keeps only employees
//     in every group named. Creating one is an upsert that licenses them.
//     Unlicensing one deletes the record and answers 200 with a null body. A
//     merge removes the secondaries and answers 200 whether or not it did.
//     The list is served a page at a time, as the app inventory is. Once the
//     tenant's licences are all in use, which limitSeats sets up, a PATCH
//     that licenses an employee, and any create, whatever address it names,
//     is refused with 400 EXCEEDED_MAX_LICENSED_EMPLOYEES. No live test
//     exercises the paging or the seats.
//   - The settings change only the fields a PATCH names, and a PATCH that
//     names neither, or a field the API does not know, is refused. Monitored
//     domains come back lower-cased and de-duplicated. The live twin,
//     TestAccSettings_roundTrip, confirms the read and write shapes, but it
//     writes back both fields as the tenant holds them, so it exercises none
//     of these rules.
//   - A custom detection's identifier is derived from its name on creation:
//     CUSTOM_ and the name upper-cased, spaces to underscores. Its detection
//     logic is stored byte for byte. Its rules keep the order they were sent
//     in and get identifiers the way a control's do, and a rule that omits
//     detectOnInternalHosts holds false. A create whose name derives an
//     identifier already in use is refused with 409, logic opening with a
//     tab is refused because it does not parse as YAML, and logic exactly at
//     the limits is accepted. A create that takes too long is answered with
//     504 and can still land some time later, which timeOutCreates
//     reproduces. No live test exercises the rest: the index lists identity
//     alone; a create refuses rule identifiers, and an update refuses one the
//     detection does not hold, ignores a name, and must name the detection it
//     is sent to if it names one at all; a rule is refused a field its mode
//     does not take or without one it requires; an OFF rule holds
//     detectOnInternalHosts false whatever it was sent, and a condition sent
//     without an action holds INCLUDE; logic over 10 KiB is refused; and
//     deleting a detection that is not there succeeds.
//   - The blocked URL list holds each pattern as *://host/path, with * as the
//     path of a pattern that names none, and DELETE empties it. A pattern is
//     split as the authority and path of a URL would be, so the host keeps
//     its port and the path its query string and fragment. No live test
//     exercises the rest: the list is a set, served in an order of its own,
//     and POST refuses a scheme, an upper-case host and the canonical form
//     itself.
//   - The app inventory is served a page at a time, each page naming a token
//     for the next. No live test pins that or each app's shape: the
//     acceptance tests read whatever the tenant holds, and assert only what
//     is true of any tenant.
type tenantStub struct {
	mu sync.Mutex

	apiKey string // when set, the only key the tenant accepts

	specs    map[string]controlspec.Spec // by endpoint path
	controls map[string]*controlDoc      // by endpoint path
	nextRule int
	puts     map[string]int // PUT requests by control API name

	employees  []pushapi.Employee
	nextEmp    int
	linger     map[string]bool // employees a merge does not remove
	created    int             // POST /v1/employees requests that created a record
	merges     [][]string      // secondary identifiers, one entry per merge request
	seats      int             // licences the tenant holds; 0 means as many as it needs
	mergeCalls int             // merge requests received, refused or not
	refuseAt   int             // the merge request, counted as mergeCalls counts, to refuse

	settings        map[string]any   // GET /v1/settings, as the API serves it
	settingsPatches []map[string]any // PATCH /v1/settings bodies, in order
	settingsRefusal map[string]any   // field errors the next PATCH is refused with

	detections  []map[string]any // custom detections in full, oldest first
	slowCreates *slowCreates     // set when creates time out with a 504
	blockedURLs []string         // canonical patterns, in the order added
	refusedURLs map[string]bool  // canonical patterns POST refuses although valid
	apps        []map[string]any // the app inventory, as GET /v1/apps serves it
}

// controlDoc is the wire shape of a control configuration, kept as raw JSON
// objects rather than the client's types so that the stub cannot share a
// marshalling bug with the code under test.
type controlDoc struct {
	Globals map[string]any   `json:"globals"`
	Rules   []map[string]any `json:"rules"`
}

func newTenantStub() *tenantStub {
	s := &tenantStub{
		specs:    map[string]controlspec.Spec{},
		controls: map[string]*controlDoc{},
		puts:     map[string]int{},
		linger:   map[string]bool{},
		settings: newTenantSettings(),
	}
	for _, spec := range controlspec.All {
		s.specs[spec.Path()] = spec
	}
	return s
}

// offlineTenant starts a stub tenant and points the provider at it for the
// rest of the test, through the same environment variables a practitioner
// uses.
func offlineTenant(t *testing.T) *tenantStub {
	t.Helper()
	stub := newTenantStub()
	stub.apiKey = "offline-test-key"
	srv := httptest.NewServer(stub.handler())
	t.Cleanup(srv.Close)
	t.Setenv(envBaseURL, srv.URL)
	t.Setenv(envAPIKey, stub.apiKey)
	return stub
}

func (s *tenantStub) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")

		// As the API does, the route is checked before the key: a path or
		// method it does not serve is refused whatever the key.
		serve := s.route(r)
		if serve == nil {
			refuse(w, http.StatusForbidden, "MissingAuthenticationTokenException",
				map[string]string{"message": "Missing Authentication Token"})
			return
		}
		if s.apiKey != "" && r.Header.Get("x-api-key") != s.apiKey {
			if wellFormedKey.MatchString(r.Header.Get("x-api-key")) {
				refuse(w, http.StatusForbidden, "AccessDeniedException", map[string]string{
					"Message": "User is not authorized to access this resource with an explicit deny in an identity-based policy",
				})
				return
			}
			refuse(w, http.StatusUnauthorized, "UnauthorizedException",
				map[string]string{"message": "Unauthorized"})
			return
		}
		serve(w, r)
	})
}

// wellFormedKey is the shape of a Push API key. The API rejects a key of any
// other shape with a 401 without looking it up, and refuses a well-formed key
// it does not accept with a 403.
var wellFormedKey = regexp.MustCompile(`^psak_[a-f0-9]{32}$`)

// refuse answers as the API does when it turns a request away before it
// reaches an endpoint, naming the kind of refusal in a header.
func refuse(w http.ResponseWriter, status int, kind string, body map[string]string) {
	w.Header().Set("x-amzn-errortype", kind)
	writeJSON(w, status, body)
}

// route returns the handler for the request's path, or nil for a path the
// stub, like the API, does not serve.
func (s *tenantStub) route(r *http.Request) http.HandlerFunc {
	if spec, ok := s.specs[r.URL.Path]; ok {
		return func(w http.ResponseWriter, r *http.Request) { s.serveControl(w, r, spec) }
	}
	switch {
	case strings.HasPrefix(r.URL.Path, "/v1/employees"):
		return s.serveEmployees
	case r.URL.Path == "/v1/settings":
		return s.serveSettings
	case r.URL.Path == customDetectionsPath && r.Method == http.MethodPost && s.slowCreates != nil:
		return s.serveSlowCreate
	case r.URL.Path == customDetectionsPath || strings.HasPrefix(r.URL.Path, customDetectionsPath+"/"):
		return s.serveCustomDetections
	case r.URL.Path == "/v1/controls/blockedUrls":
		return s.serveBlockedURLs
	case r.URL.Path == "/v1/apps":
		return s.serveApps
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func recordNotFound(w http.ResponseWriter) {
	writeJSON(w, http.StatusNotFound, map[string]string{
		"status": "RECORD_NOT_FOUND", "message": "This record does not exist.",
	})
}

// Controls.

func (s *tenantStub) serveControl(w http.ResponseWriter, r *http.Request, spec controlspec.Spec) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.document(spec))

	case http.MethodPut:
		var doc controlDoc
		if err := json.NewDecoder(r.Body).Decode(&doc); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"status": "VALIDATION_ERROR", "message": err.Error(),
			})
			return
		}
		s.store(spec, &doc)
		s.puts[spec.APIName]++
		writeJSON(w, http.StatusOK, s.document(spec))

	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"status": "METHOD_NOT_ALLOWED"})
	}
}

// document is what GET returns: the stored configuration, or the empty one a
// control starts with.
func (s *tenantStub) document(spec controlspec.Spec) *controlDoc {
	if doc, ok := s.controls[spec.Path()]; ok {
		return doc
	}
	return &controlDoc{Globals: map[string]any{}, Rules: []map[string]any{}}
}

// store replaces a control's configuration the way the API does, filling in
// everything the server materialises on write.
func (s *tenantStub) store(spec controlspec.Spec, doc *controlDoc) {
	if doc.Rules == nil {
		doc.Rules = []map[string]any{}
	}
	for _, rule := range doc.Rules {
		if id, _ := rule["id"].(string); id == "" {
			s.nextRule++
			rule["id"] = fmt.Sprintf("rule-%d", s.nextRule)
		}

		crit, _ := rule["criteria"].(map[string]any)
		if crit == nil {
			crit = map[string]any{}
		}
		for _, c := range spec.Criteria {
			cond, present := crit[c.APIName].(map[string]any)
			switch {
			case !present && c.Single && c.ServerDefault != "":
				crit[c.APIName] = map[string]any{"matches": []any{c.ServerDefault}}
			case present && c.Excludable:
				if action, _ := cond["action"].(string); action == "" {
					cond["action"] = "INCLUDE"
				}
			}
		}
		rule["criteria"] = crit

		for _, f := range spec.Fields {
			v, present := rule[f.APIName]
			switch {
			case !present && f.ServerDefault != nil:
				rule[f.APIName] = f.ServerDefault
			case present && f.Type == controlspec.TypeEnumSet:
				// The API does not promise to preserve the order of a set,
				// and a stub that happened to would let a list sneak through.
				if items, ok := v.([]any); ok {
					reversed := make([]any, 0, len(items))
					for i := len(items) - 1; i >= 0; i-- {
						reversed = append(reversed, items[i])
					}
					rule[f.APIName] = reversed
				}
			}
		}
	}

	if doc.Globals == nil {
		doc.Globals = map[string]any{}
	}
	for _, g := range spec.Globals {
		switch g.Type {
		case controlspec.GlobalObjectList:
			items, _ := doc.Globals[g.APIName].([]any)
			out := make([]any, 0, len(items))
			for _, it := range items {
				item, ok := it.(map[string]any)
				if !ok {
					continue
				}
				for _, f := range g.Attributes {
					if f.Computed {
						// The one computed attribute there is: a custom
						// content pattern's enum, derived from its name.
						name, _ := item["name"].(string)
						item[f.APIName] = derivedPatternEnum(name)
					}
				}
				out = append(out, item)
			}
			doc.Globals[g.APIName] = out

		default:
			items, _ := doc.Globals[g.APIName].([]any)
			vals := make([]string, 0, len(items))
			for _, it := range items {
				if sv, ok := it.(string); ok {
					vals = append(vals, sv)
				}
			}
			sort.Strings(vals)
			doc.Globals[g.APIName] = vals
		}
	}

	s.controls[spec.Path()] = doc
}

// seedControl writes rules straight into the tenant, without Terraform, and
// returns the identifiers assigned to them. It is the stand-in for a control
// configured in the console, which is what the adoption path imports.
func (s *tenantStub) seedControl(spec controlspec.Spec, rules ...map[string]any) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.store(spec, &controlDoc{Rules: rules})
	ids := make([]string, 0, len(rules))
	for _, r := range s.controls[spec.Path()].Rules {
		ids = append(ids, r["id"].(string))
	}
	return ids
}

// rules returns a control's stored rules, as the API would serve them.
func (s *tenantStub) rules(spec controlspec.Spec) []map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.document(spec).Rules
}

// Custom detections.
//
// The rules below are the API's, written out separately rather than shared
// with the provider's validation and derivation, which are part of what the
// tests check.

const customDetectionsPath = "/v1/controls/customDetections"

// maxDetectionLogicBytes is the most detection logic the API accepts.
const maxDetectionLogicBytes = 10 * 1024

// detectionTypeOf is the identifier the API derives from a detection's name.
func detectionTypeOf(name string) string {
	return "CUSTOM_" + strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(name), " ", "_"))
}

// detectionTypeForm is what an identifier derived from a name must look like
// for the API to accept the name.
var detectionTypeForm = regexp.MustCompile(`^CUSTOM_[A-Z0-9_]+$`)

// detectionRuleKeys are the keys a custom detection rule takes, and
// detectionConditions the conditions its criteria take. The API refuses any
// other.
var (
	detectionRuleKeys = []string{
		"id", "name", "enabled", "mode", "severity", "title", "subtext", "buttonText",
		"detectOnInternalHosts", "criteria",
	}
	detectionConditions = []string{"employeeIds", "employeeGroups"}
)

// detectionModeFields lists, for each mode, the mode-dependent fields a rule
// must carry. It may carry none of the others.
var (
	detectionModeDependent = []string{"severity", "title", "subtext", "buttonText"}
	detectionModeFields    = map[string][]string{
		"OFF":     {},
		"MONITOR": {"severity"},
		"WARN":    {"severity", "title", "subtext", "buttonText"},
		"BLOCK":   {"severity", "title", "subtext"},
	}
)

func (s *tenantStub) serveCustomDetections(w http.ResponseWriter, r *http.Request) {
	eventType := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, customDetectionsPath), "/")

	switch {
	case eventType == "" && r.Method == http.MethodGet:
		index := make([]map[string]any, 0, len(s.detections))
		for _, d := range s.detections {
			index = append(index, map[string]any{
				"detectionEventType": d["detectionEventType"],
				"detectionEventName": d["detectionEventName"],
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{"result": index})

	case eventType == "" && r.Method == http.MethodPost:
		var body struct {
			Name  *string          `json:"detectionEventName"`
			Logic *string          `json:"detectionLogic"`
			Rules []map[string]any `json:"rules"`
		}
		if !decodeBody(w, r, &body) {
			return
		}
		errs := map[string]any{}
		var name string
		if body.Name != nil {
			name = strings.TrimSpace(*body.Name)
		}
		eventType = detectionTypeOf(name)
		switch {
		case body.Name == nil:
			errs["detectionEventName"] = []string{"Field required"}
		case name == "":
			errs["detectionEventName"] = []string{"Detection event name cannot be empty."}
		case !detectionTypeForm.MatchString(eventType):
			errs["detectionEventName"] = []string{"Invalid characters: detection event names " +
				"may only contain letters, numbers, spaces and underscores."}
		}
		checkDetectionLogic(errs, body.Logic)
		if len(body.Rules) == 0 {
			errs["rules"] = []string{"List should have at least 1 item after validation, not 0"}
		}
		for i, rule := range body.Rules {
			checkDetectionRule(errs, i, rule)
			if rule["id"] != nil {
				fieldError(errs, "rule ids cannot be supplied when creating a custom detection.",
					"rules", strconv.Itoa(i), "id")
			}
		}
		if len(errs) > 0 {
			invalidInput(w, errs)
			return
		}
		if s.detectionIndex(eventType) >= 0 {
			writeJSON(w, http.StatusConflict, map[string]string{
				"status": "CUSTOM_DETECTION_ALREADY_EXISTS",
				"message": "A custom detection with detection event type " + eventType +
					" already exists.",
			})
			return
		}
		d := map[string]any{
			"detectionEventType": eventType,
			"detectionEventName": name,
			"detectionLogic":     *body.Logic,
			"rules":              s.storeDetectionRules(body.Rules),
		}
		s.detections = append(s.detections, d)
		writeJSON(w, http.StatusOK, d)

	case r.Method == http.MethodGet:
		s.settleSlowCreate(eventType)
		i := s.detectionIndex(eventType)
		if i < 0 {
			recordNotFound(w)
			return
		}
		writeJSON(w, http.StatusOK, s.detections[i])

	case r.Method == http.MethodPut:
		var body struct {
			EventType *string `json:"detectionEventType"`
			// Accepted and ignored: a detection cannot be renamed.
			Name  *string          `json:"detectionEventName"`
			Logic *string          `json:"detectionLogic"`
			Rules []map[string]any `json:"rules"`
		}
		if !decodeBody(w, r, &body) {
			return
		}
		i := s.detectionIndex(eventType)
		if i < 0 {
			recordNotFound(w)
			return
		}
		errs := map[string]any{}
		if body.EventType != nil && *body.EventType != eventType {
			errs["detectionEventType"] = []string{"detectionEventType must equal the detection " +
				"event type in the path (" + eventType + ") when present."}
		}
		checkDetectionLogic(errs, body.Logic)
		if body.Rules == nil {
			errs["rules"] = []string{"Field required"}
		}
		held := map[string]bool{}
		for _, rule := range s.detections[i]["rules"].([]any) {
			held[rule.(map[string]any)["id"].(string)] = true
		}
		for j, rule := range body.Rules {
			checkDetectionRule(errs, j, rule)
			if id, _ := rule["id"].(string); id != "" && !held[id] {
				fieldError(errs, "No existing control rule with id "+id+". To create a new rule, "+
					"omit the id field.", "rules", strconv.Itoa(j), "id")
			}
		}
		if len(errs) > 0 {
			invalidInput(w, errs)
			return
		}
		s.detections[i]["detectionLogic"] = *body.Logic
		s.detections[i]["rules"] = s.storeDetectionRules(body.Rules)
		writeJSON(w, http.StatusOK, s.detections[i])

	case r.Method == http.MethodDelete:
		if i := s.detectionIndex(eventType); i >= 0 {
			s.detections = append(s.detections[:i], s.detections[i+1:]...)
		}
		writeJSON(w, http.StatusOK, map[string]any{})

	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"status": "METHOD_NOT_ALLOWED"})
	}
}

func checkDetectionLogic(errs map[string]any, logic *string) {
	switch {
	case logic == nil:
		errs["detectionLogic"] = []string{"Field required"}
	case len(*logic) > maxDetectionLogicBytes:
		errs["detectionLogic"] = []string{fmt.Sprintf(
			"The detection logic is %d bytes; at most %d bytes are allowed.",
			len(*logic), maxDetectionLogicBytes)}
	case strings.HasPrefix(*logic, "\t"):
		// The one way logic fails to parse that the stub models.
		errs["detectionLogic"] = []string{"The detection logic is not valid YAML: " +
			"found character '\\t' that cannot start any token (line 1)"}
	}
}

// checkDetectionRule refuses keys a rule does not take and fields its mode
// does not allow. A field sent as null counts as one not sent.
func checkDetectionRule(errs map[string]any, i int, rule map[string]any) {
	at := strconv.Itoa(i)
	for k := range rule {
		if !slices.Contains(detectionRuleKeys, k) {
			fieldError(errs, "Extra inputs are not permitted", "rules", at, k)
		}
	}
	crit, _ := rule["criteria"].(map[string]any)
	for k := range crit {
		if !slices.Contains(detectionConditions, k) {
			fieldError(errs, "Extra inputs are not permitted", "rules", at, "criteria", k)
		}
	}
	mode, _ := rule["mode"].(string)
	required, ok := detectionModeFields[mode]
	if !ok {
		fieldError(errs, "Input should be 'MONITOR', 'WARN', 'BLOCK' or 'OFF'", "rules", at, "mode")
		return
	}
	for _, f := range detectionModeDependent {
		switch sent, want := rule[f] != nil, slices.Contains(required, f); {
		case sent && !want:
			fieldError(errs, f+" must not be provided when mode is "+mode, "rules", at, "_schema")
		case !sent && want:
			fieldError(errs, f+" is required for mode "+mode, "rules", at, "_schema")
		}
	}
}

// storeDetectionRules returns rules as the API holds them once written: with
// an identifier for each one sent without, detectOnInternalHosts false where
// a rule omits it or is OFF, and INCLUDE on a condition sent without an
// action. The API serves no nulls, so a field sent as null is dropped.
func (s *tenantStub) storeDetectionRules(rules []map[string]any) []any {
	out := make([]any, 0, len(rules))
	for _, sent := range rules {
		rule := map[string]any{}
		for k, v := range sent {
			if v != nil {
				rule[k] = v
			}
		}
		if _, ok := rule["id"]; !ok {
			s.nextRule++
			rule["id"] = fmt.Sprintf("rule-%d", s.nextRule)
		}
		if on, _ := rule["detectOnInternalHosts"].(bool); !on || rule["mode"] == "OFF" {
			rule["detectOnInternalHosts"] = false
		}
		crit := map[string]any{}
		sentCrit, _ := rule["criteria"].(map[string]any)
		for k, c := range sentCrit {
			cond, ok := c.(map[string]any)
			if !ok {
				continue
			}
			if action, _ := cond["action"].(string); action == "" {
				cond["action"] = "INCLUDE"
			}
			crit[k] = cond
		}
		rule["criteria"] = crit
		out = append(out, rule)
	}
	return out
}

// slowCreates is how creates behave once they take longer than the API waits
// before answering 504, while the create carries on. lands says whether a
// create the API would have accepted is stored all the same, as it is when
// only the response timed out, and misses how many reads of it miss before it
// appears. pending holds the creates still to appear, by identifier.
type slowCreates struct {
	lands   bool
	misses  int
	pending map[string]*pendingDetection
}

type pendingDetection struct {
	detection map[string]any
	misses    int
}

// timeOutCreates makes every create from now on time out with a 504. With
// lands false a create is never stored, as when it fails after the 504.
func (s *tenantStub) timeOutCreates(lands bool, misses int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.slowCreates = &slowCreates{lands: lands, misses: misses, pending: map[string]*pendingDetection{}}
}

// answerCreatesInTime undoes timeOutCreates. A create still pending never
// lands.
func (s *tenantStub) answerCreatesInTime() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.slowCreates = nil
}

// serveSlowCreate runs a create as usual, but its answer goes nowhere: the
// client gets a 504 instead, and a detection the create stored is held back
// until enough reads have missed it. Called with the lock held.
func (s *tenantStub) serveSlowCreate(w http.ResponseWriter, r *http.Request) {
	rec := httptest.NewRecorder()
	s.serveCustomDetections(rec, r)
	if rec.Code == http.StatusOK {
		d := s.detections[len(s.detections)-1]
		s.detections = s.detections[:len(s.detections)-1]
		if s.slowCreates.lands {
			s.slowCreates.pending[d["detectionEventType"].(string)] = &pendingDetection{
				detection: d, misses: s.slowCreates.misses,
			}
		}
	}
	writeJSON(w, http.StatusGatewayTimeout, map[string]string{"message": "Request timed out"})
}

// settleSlowCreate counts a read of a detection whose create is still
// pending, and stores it once enough reads have missed it. Called with the
// lock held.
func (s *tenantStub) settleSlowCreate(eventType string) {
	if s.slowCreates == nil {
		return
	}
	p, ok := s.slowCreates.pending[eventType]
	if !ok {
		return
	}
	if p.misses > 0 {
		p.misses--
		return
	}
	delete(s.slowCreates.pending, eventType)
	s.detections = append(s.detections, p.detection)
}

// seedDetection creates a custom detection straight in the tenant, without
// Terraform, and returns its identifier: the stand-in for one created in the
// console.
func (s *tenantStub) seedDetection(name, logic string, rules ...map[string]any) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	eventType := detectionTypeOf(name)
	s.detections = append(s.detections, map[string]any{
		"detectionEventType": eventType,
		"detectionEventName": name,
		"detectionLogic":     logic,
		"rules":              s.storeDetectionRules(rules),
	})
	return eventType
}

// removeDetection deletes a custom detection behind Terraform's back.
func (s *tenantStub) removeDetection(eventType string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if i := s.detectionIndex(eventType); i >= 0 {
		s.detections = append(s.detections[:i], s.detections[i+1:]...)
	}
}

// detectionIndex is called with the lock held.
func (s *tenantStub) detectionIndex(eventType string) int {
	for i, d := range s.detections {
		if d["detectionEventType"] == eventType {
			return i
		}
	}
	return -1
}

// Blocked URLs.

func (s *tenantStub) serveBlockedURLs(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// A set to the API, served in an order of its own: reversed here, so
		// that a provider relying on insertion order would fail.
		served := make([]string, 0, len(s.blockedURLs))
		for i := len(s.blockedURLs) - 1; i >= 0; i-- {
			served = append(served, s.blockedURLs[i])
		}
		writeJSON(w, http.StatusOK, map[string]any{"result": served})

	case http.MethodPost:
		// The API also takes {host, path}. The provider sends only {url}, so
		// the stub refuses the other form rather than modelling it.
		var body struct {
			URL *string `json:"url"`
		}
		if !decodeBody(w, r, &body) {
			return
		}
		if body.URL == nil {
			invalidInput(w, map[string]any{"url": []string{`Either "host" or "url" must be provided.`}})
			return
		}
		stored, problem := storedBlockedURL(*body.URL)
		if problem == "" && s.refusedURLs[stored] {
			problem = "Refused by the test."
		}
		if problem != "" {
			invalidInput(w, map[string]any{"url": []string{
				fmt.Sprintf("Invalid url pattern %q. %s", *body.URL, problem)}})
			return
		}
		if !slices.Contains(s.blockedURLs, stored) {
			s.blockedURLs = append(s.blockedURLs, stored)
		}
		writeJSON(w, http.StatusOK, map[string]any{"result": stored})

	case http.MethodDelete:
		s.blockedURLs = nil
		writeJSON(w, http.StatusOK, map[string]any{})

	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"status": "METHOD_NOT_ALLOWED"})
	}
}

// The API's rules for the host and path of a blocked URL pattern, written out
// like the custom detection rules above. The host is lower-case labels with at
// least one letter among them, or an IPv4 address, and may carry a port.
var (
	blockedHostLabel  = `[a-z0-9*]([a-z0-9*-]*[a-z0-9*])?`
	blockedHostLabels = regexp.MustCompile(`^` + blockedHostLabel + `(\.` + blockedHostLabel + `)*$`)
	blockedHostIPv4   = regexp.MustCompile(`^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}` +
		`(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`)
	blockedHostPort     = regexp.MustCompile(`^[0-9]{1,5}$`)
	blockedPathChars    = regexp.MustCompile(`^[A-Za-z0-9_,;=:/@%!'.~$&()*+?#-]+$`)
	blockedSchemePrefix = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*://`)
)

// storedBlockedURL is what the API stores for a pattern POSTed as {url}, or
// why it refuses it. The API reads the pattern as the authority and path of a
// URL: the host runs to the first /, ? or # and keeps its port, and the path
// loses its leading slashes and keeps any query string and fragment. A
// pattern that names no path blocks every path.
func storedBlockedURL(pattern string) (stored, problem string) {
	if blockedSchemePrefix.MatchString(pattern) {
		return "", `A scheme (such as "https://") must not be provided.`
	}
	host, rest := pattern, ""
	if i := strings.IndexAny(pattern, "/?#"); i >= 0 {
		host, rest = pattern[:i], pattern[i:]
	}
	path, fragment, _ := strings.Cut(rest, "#")
	path, query, _ := strings.Cut(path, "?")
	path = strings.TrimLeft(path, "/")
	if query != "" {
		path += "?" + query
	}
	if fragment != "" {
		path += "#" + fragment
	}
	if path == "" {
		path = "*"
	}

	name, port, hasPort := strings.Cut(host, ":")
	labels := blockedHostLabels.MatchString(name) && strings.ContainsAny(name, "abcdefghijklmnopqrstuvwxyz")
	if len(host) > 75 || !labels && !blockedHostIPv4.MatchString(name) ||
		hasPort && !blockedHostPort.MatchString(port) {
		return "", `The "host" part of your URL is invalid.`
	}
	if len(path) > 256 || !blockedPathChars.MatchString(path) {
		return "", `The "path" part of your URL is invalid.`
	}
	return "*://" + host + "/" + path, ""
}

// addBlockedURL adds a canonical pattern straight to the tenant, without
// Terraform: the stand-in for one added in the console.
func (s *tenantStub) addBlockedURL(canonical string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blockedURLs = append(s.blockedURLs, canonical)
}

// refuseBlockedURL makes POST refuse a valid pattern, the stand-in for a
// write that fails partway through for a reason the provider could not check
// during plan. Called with refuse false, it lifts the refusal.
func (s *tenantStub) refuseBlockedURL(canonical string, refuse bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.refusedURLs == nil {
		s.refusedURLs = map[string]bool{}
	}
	s.refusedURLs[canonical] = refuse
}

// Apps.

// pageSize is far below the API's page sizes, so that a handful of apps or
// employees spans several pages.
const pageSize = 2

// pageTokenPrefix makes a page token a UUID, as the API's are, that carries
// the offset of the page it leads to.
const pageTokenPrefix = "00000000-0000-4000-8000-"

func (s *tenantStub) serveApps(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"status": "METHOD_NOT_ALLOWED"})
		return
	}
	writePage(w, r, s.apps)
}

// writePage answers a list request with the page of items its nextToken asks
// for, the first page when it names none, and the token for the page after
// it while there is one.
func writePage[T any](w http.ResponseWriter, r *http.Request, items []T) {
	start := 0
	if token := r.URL.Query().Get("nextToken"); token != "" {
		offset, ok := strings.CutPrefix(token, pageTokenPrefix)
		n, err := strconv.Atoi(offset)
		if !ok || len(offset) != 12 || err != nil {
			invalidInput(w, map[string]any{"nextToken": []string{"Not a valid UUID."}})
			return
		}
		start = min(n, len(items))
	}
	end := min(start+pageSize, len(items))
	paging := map[string]any{"moreResults": false, "next": nil, "nextToken": nil}
	if end < len(items) {
		paging = map[string]any{
			"moreResults": true, "next": end, "nextToken": fmt.Sprintf("%s%012d", pageTokenPrefix, end),
		}
	}
	page := append([]T{}, items[start:end]...)
	writeJSON(w, http.StatusOK, map[string]any{"result": page, "paging": paging})
}

// seedApps adds apps to the inventory, each written as the JSON the API
// serves.
func (s *tenantStub) seedApps(apps ...map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.apps = append(s.apps, apps...)
}

// Validation.

// decodeBody decodes a request body the way the API's schemas do, refusing
// keys they do not know. When the body does not decode it answers the request
// itself, and reports that it did not.
func decodeBody(w http.ResponseWriter, r *http.Request, into any) bool {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		invalidInput(w, map[string]any{"_schema": []string{err.Error()}})
		return false
	}
	return true
}

// invalidInput answers the way the API does when validation fails: the field
// errors are a JSON document inside the message.
func invalidInput(w http.ResponseWriter, errs map[string]any) {
	msg, _ := json.Marshal(errs)
	writeJSON(w, http.StatusBadRequest, map[string]string{
		"status": "INVALID_INPUT_PROVIDED", "message": string(msg),
	})
}

// fieldError adds a message to a validation document at a path of keys, the
// shape the API nests its field errors in: {"rules": {"0": {"id": [...]}}}.
func fieldError(errs map[string]any, msg string, path ...string) {
	node := errs
	for _, k := range path[:len(path)-1] {
		child, ok := node[k].(map[string]any)
		if !ok {
			child = map[string]any{}
			node[k] = child
		}
		node = child
	}
	last := path[len(path)-1]
	msgs, _ := node[last].([]string)
	node[last] = append(msgs, msg)
}

// Employees.

func (s *tenantStub) serveEmployees(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/v1/employees")
	rest = strings.TrimPrefix(rest, "/")

	switch {
	case rest == "" && r.Method == http.MethodGet:
		q := r.URL.Query()
		out := make([]pushapi.Employee, 0, len(s.employees))
		for _, e := range s.employees {
			if listed(e, q) {
				out = append(out, e)
			}
		}
		writePage(w, r, out)

	case rest == "" && r.Method == http.MethodPost:
		var body pushapi.NewEmployee
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"status": "VALIDATION_ERROR", "message": err.Error()})
			return
		}
		// The seats are checked before the address is looked at.
		if !s.seatFree() {
			noSeats(w)
			return
		}
		// An upsert: an address that already exists comes back with its
		// existing record rather than an error.
		if e, ok := s.find(body.Email); ok {
			writeJSON(w, http.StatusOK, e)
			return
		}
		e := s.add(body.Email, body.FirstName, body.LastName, true)
		s.created++
		writeJSON(w, http.StatusOK, e)

	case strings.HasSuffix(rest, "/merge") && r.Method == http.MethodPost:
		primary := strings.TrimSuffix(rest, "/merge")
		p, ok := s.byID(primary)
		if !ok {
			recordNotFound(w)
			return
		}
		var body struct {
			SecondaryEmployeeIDs []string `json:"secondaryEmployeeIds"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if s.mergeCalls++; s.mergeCalls == s.refuseAt {
			invalidInput(w, map[string]any{"secondaryEmployeeIds": []string{"Refused by the test."}})
			return
		}
		s.merges = append(s.merges, body.SecondaryEmployeeIDs)
		for _, id := range body.SecondaryEmployeeIDs {
			if !s.linger[id] {
				s.remove(id)
			}
		}
		writeJSON(w, http.StatusOK, p)

	case r.Method == http.MethodGet:
		e, ok := s.byID(rest)
		if !ok {
			recordNotFound(w)
			return
		}
		writeJSON(w, http.StatusOK, e)

	case r.Method == http.MethodPatch:
		i := s.index(rest)
		if i < 0 {
			recordNotFound(w)
			return
		}
		var body pushapi.EmployeeUpdate
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"status": "VALIDATION_ERROR", "message": err.Error()})
			return
		}
		e := &s.employees[i]
		if body.FirstName != nil {
			e.FirstName = *body.FirstName
		}
		if body.LastName != nil {
			e.LastName = *body.LastName
		}
		if body.Licensed != nil && *body.Licensed && !e.Licensed && !s.seatFree() {
			noSeats(w)
			return
		}
		if body.Licensed != nil {
			e.Licensed = *body.Licensed
			if !e.Licensed {
				// Unlicensing deletes the record outright, and the API says so
				// with a null body.
				s.remove(e.ID)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("null"))
				return
			}
		}
		writeJSON(w, http.StatusOK, *e)

	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"status": "METHOD_NOT_ALLOWED"})
	}
}

// addEmployee seeds one employee and returns the identifier assigned.
func (s *tenantStub) addEmployee(email, firstName, lastName string, licensed bool, groups ...string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.add(email, firstName, lastName, licensed)
	s.employees[len(s.employees)-1].Groups = groups
	return e.ID
}

// editEmployee changes a seeded employee in place, for the attributes
// addEmployee does not take.
func (s *tenantStub) editEmployee(id string, edit func(*pushapi.Employee)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	edit(&s.employees[s.index(id)])
}

// survivesMerge makes merge requests leave this employee in place. The real
// API has not been seen to do that; the provider checks for it because the
// response could not tell the difference.
func (s *tenantStub) survivesMerge(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.linger[id] = true
}

// limitSeats gives the tenant this many licences, so that licensing an
// employee once they are all in use is refused.
func (s *tenantStub) limitSeats(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seats = n
}

// refuseMergeAfter lets n more merge requests through and refuses the one
// after them whole, merging none of its secondaries: the stand-in for a
// batch of merges that fails partway through.
func (s *tenantStub) refuseMergeAfter(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refuseAt = s.mergeCalls + n + 1
}

// employee looks an address up the way a test asserts on the tenant: exactly,
// ignoring case.
func (s *tenantStub) employee(email string) (pushapi.Employee, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.find(email)
}

// mergeRequests returns the secondary identifiers of every merge request so
// far, one entry per request.
func (s *tenantStub) mergeRequests() [][]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([][]string(nil), s.merges...)
}

// employeesCreated counts the records POST /v1/employees created, as opposed
// to the ones it found already there.
func (s *tenantStub) employeesCreated() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.created
}

// The helpers below are called with the lock held.

// seatFree reports whether the tenant has a licence left for one more
// employee.
func (s *tenantStub) seatFree() bool {
	if s.seats == 0 {
		return true
	}
	licensed := 0
	for _, e := range s.employees {
		if e.Licensed {
			licensed++
		}
	}
	return licensed < s.seats
}

// noSeats answers as the API does once every licence is in use.
func noSeats(w http.ResponseWriter) {
	writeJSON(w, http.StatusBadRequest, map[string]string{
		"status":  "EXCEEDED_MAX_LICENSED_EMPLOYEES",
		"message": "Every licence the tenant holds is in use.",
	})
}

func (s *tenantStub) add(email, firstName, lastName string, licensed bool) pushapi.Employee {
	s.nextEmp++
	e := pushapi.Employee{
		ID: fmt.Sprintf("emp-%d", s.nextEmp), Email: email,
		FirstName: firstName, LastName: lastName, Licensed: licensed,
	}
	s.employees = append(s.employees, e)
	return e
}

func (s *tenantStub) find(email string) (pushapi.Employee, bool) {
	for _, e := range s.employees {
		if strings.EqualFold(e.Email, email) {
			return e, true
		}
	}
	return pushapi.Employee{}, false
}

func (s *tenantStub) index(id string) int {
	for i, e := range s.employees {
		if e.ID == id {
			return i
		}
	}
	return -1
}

func (s *tenantStub) byID(id string) (pushapi.Employee, bool) {
	if i := s.index(id); i >= 0 {
		return s.employees[i], true
	}
	return pushapi.Employee{}, false
}

func (s *tenantStub) remove(id string) {
	if i := s.index(id); i >= 0 {
		s.employees = append(s.employees[:i], s.employees[i+1:]...)
	}
}

// listed applies the filters GET /v1/employees takes to one employee.
func listed(e pushapi.Employee, q url.Values) bool {
	// The API's email filter returns every address that contains the one
	// asked for, spelled in the same case, which is why the resolver compares
	// whole addresses itself.
	if !strings.Contains(e.Email, q.Get("email")) {
		return false
	}
	if q.Has("licensed") && q.Get("licensed") != strconv.FormatBool(e.Licensed) {
		return false
	}
	if q.Has("chatopsEnabled") && q.Get("chatopsEnabled") != strconv.FormatBool(e.ChatopsEnabled) {
		return false
	}
	for _, g := range q["groups"] {
		if !slices.Contains(e.Groups, g) {
			return false
		}
	}
	return true
}

// Diagnostics.

// diagnosticLog collects the warnings the provider raised over a test, which
// are otherwise invisible: terraform-plugin-testing treats a step that
// succeeded with a warning exactly like one that succeeded without, and
// several of this provider's guarantees are warnings — that an employee was
// created rather than adopted, that a destroy left somebody licensed, that
// unkeyed rules are matched by position.
type diagnosticLog struct {
	mu       sync.Mutex
	warnings []string // summaries, in the order raised
}

// factories wires the provider into the test framework behind a server that
// records every diagnostic it answers with.
func (l *diagnosticLog) factories() map[string]func() (tfprotov6.ProviderServer, error) {
	return map[string]func() (tfprotov6.ProviderServer, error){
		"pushsecurity": func() (tfprotov6.ProviderServer, error) {
			srv, err := providerserver.NewProtocol6WithError(New("test")())()
			if err != nil {
				return nil, err
			}
			return &recordingProviderServer{ProviderServer: srv, log: l}, nil
		},
	}
}

func (l *diagnosticLog) record(diags []*tfprotov6.Diagnostic) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, d := range diags {
		if d != nil && d.Severity == tfprotov6.DiagnosticSeverityWarning {
			l.warnings = append(l.warnings, d.Summary)
		}
	}
}

func (l *diagnosticLog) warned(summary string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, w := range l.warnings {
		if w == summary {
			return true
		}
	}
	return false
}

// checkWarned asserts a warning with this summary has been raised at some
// point in the test so far.
func checkWarned(log *diagnosticLog, summary string) resource.TestCheckFunc {
	return func(*terraform.State) error {
		if !log.warned(summary) {
			return fmt.Errorf("no warning %q was raised; warnings so far: %q", summary, log.warnings)
		}
		return nil
	}
}

// checkNotWarned asserts a warning with this summary has not been raised at
// any point in the test so far.
func checkNotWarned(log *diagnosticLog, summary string) resource.TestCheckFunc {
	return func(*terraform.State) error {
		if log.warned(summary) {
			return fmt.Errorf("the warning %q was raised, and must not be", summary)
		}
		return nil
	}
}

// recordingProviderServer passes every request through and keeps the
// diagnostics of the ones that can carry a warning worth asserting on.
type recordingProviderServer struct {
	tfprotov6.ProviderServer
	log *diagnosticLog
}

func (p *recordingProviderServer) ValidateResourceConfig(ctx context.Context, req *tfprotov6.ValidateResourceConfigRequest) (*tfprotov6.ValidateResourceConfigResponse, error) {
	resp, err := p.ProviderServer.ValidateResourceConfig(ctx, req)
	if resp != nil {
		p.log.record(resp.Diagnostics)
	}
	return resp, err
}

func (p *recordingProviderServer) PlanResourceChange(ctx context.Context, req *tfprotov6.PlanResourceChangeRequest) (*tfprotov6.PlanResourceChangeResponse, error) {
	resp, err := p.ProviderServer.PlanResourceChange(ctx, req)
	if resp != nil {
		p.log.record(resp.Diagnostics)
	}
	return resp, err
}

func (p *recordingProviderServer) ApplyResourceChange(ctx context.Context, req *tfprotov6.ApplyResourceChangeRequest) (*tfprotov6.ApplyResourceChangeResponse, error) {
	resp, err := p.ProviderServer.ApplyResourceChange(ctx, req)
	if resp != nil {
		p.log.record(resp.Diagnostics)
	}
	return resp, err
}

func (p *recordingProviderServer) ReadResource(ctx context.Context, req *tfprotov6.ReadResourceRequest) (*tfprotov6.ReadResourceResponse, error) {
	resp, err := p.ProviderServer.ReadResource(ctx, req)
	if resp != nil {
		p.log.record(resp.Diagnostics)
	}
	return resp, err
}

func (p *recordingProviderServer) ReadDataSource(ctx context.Context, req *tfprotov6.ReadDataSourceRequest) (*tfprotov6.ReadDataSourceResponse, error) {
	resp, err := p.ProviderServer.ReadDataSource(ctx, req)
	if resp != nil {
		p.log.record(resp.Diagnostics)
	}
	return resp, err
}

func (p *recordingProviderServer) ImportResourceState(ctx context.Context, req *tfprotov6.ImportResourceStateRequest) (*tfprotov6.ImportResourceStateResponse, error) {
	resp, err := p.ProviderServer.ImportResourceState(ctx, req)
	if resp != nil {
		p.log.record(resp.Diagnostics)
	}
	return resp, err
}
