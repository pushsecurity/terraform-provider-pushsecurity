package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	fwschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/pushapi"
)

// emptyTenant answers every employee read with "nobody here" and fails the
// test on any write. It is the tenant an unlicensed, absent employee must be
// managed against without a single request that changes anything.
func emptyTenant(t *testing.T) *employeeResource {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && strings.TrimSuffix(r.URL.Path, "/") == "/v1/employees":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"result": []any{},
				"paging": map[string]any{"moreResults": false, "nextToken": nil},
			})
		case r.Method == http.MethodGet:
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"status": "RECORD_NOT_FOUND", "message": "This record does not exist.",
			})
		default:
			t.Errorf("unexpected %s %s: nothing may be written for an absent unlicensed employee", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)
	client, err := pushapi.New(srv.URL, "k", pushapi.WithMaxRetries(0))
	if err != nil {
		t.Fatalf("pushapi.New: %v", err)
	}
	return &employeeResource{client: client, resolver: newEmployeeResolver(client)}
}

func employeeSchema(t *testing.T, r *employeeResource) fwschema.Schema {
	t.Helper()
	var resp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("schema: %v", resp.Diagnostics)
	}
	return resp.Schema
}

// employeeValue builds the raw object the framework hands a resource, with
// every attribute not named left unknown, as a plan leaves computed ones.
func employeeValue(s fwschema.Schema, known map[string]tftypes.Value) tftypes.Value {
	objType := s.Type().TerraformType(context.Background()).(tftypes.Object)
	vals := map[string]tftypes.Value{}
	for name, typ := range objType.AttributeTypes {
		if v, ok := known[name]; ok {
			vals[name] = v
			continue
		}
		vals[name] = tftypes.NewValue(typ, tftypes.UnknownValue)
	}
	return tftypes.NewValue(objType, vals)
}

func str(s string) tftypes.Value { return tftypes.NewValue(tftypes.String, s) }
func nullStr() tftypes.Value     { return tftypes.NewValue(tftypes.String, nil) }
func boolean(b bool) tftypes.Value {
	return tftypes.NewValue(tftypes.Bool, b)
}
func emptyGroups() tftypes.Value {
	return tftypes.NewValue(tftypes.Set{ElementType: tftypes.String}, []tftypes.Value{})
}

func TestEmployeeCreateLeavesAbsentUnlicensedEmployeeAlone(t *testing.T) {
	// The plan says the employee should not hold a licence and the tenant does
	// not hold the employee. Creating them would license them (the API does
	// that automatically) only for the unlicensing PATCH to delete them again,
	// and an apply-on-merge pipeline would do that on every merge.
	r := emptyTenant(t)
	s := employeeSchema(t, r)
	ctx := context.Background()

	req := resource.CreateRequest{Plan: tfsdk.Plan{Schema: s, Raw: employeeValue(s, map[string]tftypes.Value{
		"email":           str("nobody@example.com"),
		"first_name":      nullStr(),
		"last_name":       nullStr(),
		"licensed":        boolean(false),
		"allow_unlicense": boolean(true),
	})}}
	resp := resource.CreateResponse{State: tfsdk.State{Schema: s, Raw: tftypes.NewValue(s.Type().TerraformType(ctx), nil)}}
	r.Create(ctx, req, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Create: %v", resp.Diagnostics.Errors())
	}

	var got employeeModel
	if d := resp.State.Get(ctx, &got); d.HasError() {
		t.Fatalf("state: %v", d)
	}
	if !got.EmployeeID.IsNull() {
		t.Errorf("employee_id = %v, want null: there is no record to identify", got.EmployeeID)
	}
	if !got.Licensed.Equal(types.BoolValue(false)) {
		t.Errorf("licensed = %v, want false", got.Licensed)
	}
	if got.Groups.IsUnknown() || len(got.Groups.Elements()) != 0 {
		t.Errorf("groups = %v, want an empty set", got.Groups)
	}
	if got.FirstName.IsUnknown() || got.LastName.IsUnknown() {
		t.Errorf("names must be known after apply: %v %v", got.FirstName, got.LastName)
	}

	var warned bool
	for _, d := range resp.Diagnostics.Warnings() {
		if strings.Contains(d.Summary(), "does not exist") && strings.Contains(d.Detail(), "can be removed") {
			warned = true
		}
	}
	if !warned {
		t.Errorf("expected a warning saying the employee does not exist and the block can be removed, got %v", resp.Diagnostics)
	}
}

func TestEmployeeReadKeepsAbsentUnlicensedEmployee(t *testing.T) {
	// Once the resource records the employee as unlicensed, a tenant that no
	// longer holds them is the outcome the configuration asked for, not drift.
	// Removing the resource would make the next plan propose a create.
	r := emptyTenant(t)
	s := employeeSchema(t, r)
	ctx := context.Background()

	for name, id := range map[string]tftypes.Value{
		// The identifier the unlicensing apply recorded, now stale: the API
		// deleted the record with the licence.
		"stale identifier": str("id-gone"),
		// A later refresh has already dropped it.
		"no identifier": nullStr(),
	} {
		t.Run(name, func(t *testing.T) {
			prior := employeeValue(s, map[string]tftypes.Value{
				"email":           str("nobody@example.com"),
				"first_name":      str("No"),
				"last_name":       str("Body"),
				"licensed":        boolean(false),
				"allow_unlicense": boolean(true),
				"employee_id":     id,
				"groups":          emptyGroups(),
			})
			req := resource.ReadRequest{State: tfsdk.State{Schema: s, Raw: prior}}
			resp := resource.ReadResponse{State: tfsdk.State{Schema: s, Raw: prior}}
			r.Read(ctx, req, &resp)
			if resp.Diagnostics.HasError() {
				t.Fatalf("Read: %v", resp.Diagnostics.Errors())
			}
			if resp.State.Raw.IsNull() {
				t.Fatal("Read removed the resource; an absent unlicensed employee is satisfied, not gone")
			}
			var got employeeModel
			if d := resp.State.Get(ctx, &got); d.HasError() {
				t.Fatalf("state: %v", d)
			}
			if !got.EmployeeID.IsNull() {
				t.Errorf("employee_id = %v, want null", got.EmployeeID)
			}
			if !got.Licensed.Equal(types.BoolValue(false)) {
				t.Errorf("licensed = %v, want false", got.Licensed)
			}
			if got.FirstName.ValueString() != "No" || got.LastName.ValueString() != "Body" {
				t.Errorf("names changed: %v %v", got.FirstName, got.LastName)
			}
		})
	}
}

func TestEmployeeReadRemovesAbsentEmployeeNotKnownUnlicensed(t *testing.T) {
	// The contrast: an employee the state last saw licensed, or never saw at
	// all (an import), who is not in the tenant has gone for some reason this
	// resource was not told about, and the resource goes with them.
	r := emptyTenant(t)
	s := employeeSchema(t, r)
	ctx := context.Background()

	for name, licensed := range map[string]tftypes.Value{
		"licensed": boolean(true),
		"imported": tftypes.NewValue(tftypes.Bool, nil),
	} {
		t.Run(name, func(t *testing.T) {
			prior := employeeValue(s, map[string]tftypes.Value{
				"email":           str("nobody@example.com"),
				"first_name":      nullStr(),
				"last_name":       nullStr(),
				"licensed":        licensed,
				"allow_unlicense": boolean(false),
				"employee_id":     nullStr(),
				"groups":          tftypes.NewValue(tftypes.Set{ElementType: tftypes.String}, nil),
			})
			req := resource.ReadRequest{State: tfsdk.State{Schema: s, Raw: prior}}
			resp := resource.ReadResponse{State: tfsdk.State{Schema: s, Raw: prior}}
			r.Read(ctx, req, &resp)
			if resp.Diagnostics.HasError() {
				t.Fatalf("Read: %v", resp.Diagnostics.Errors())
			}
			if !resp.State.Raw.IsNull() {
				t.Error("Read kept a resource for an employee who is gone and was not recorded as unlicensed")
			}
		})
	}
}

func TestWantsUnlicensed(t *testing.T) {
	for name, tc := range map[string]struct {
		licensed types.Bool
		want     bool
	}{
		"false":   {types.BoolValue(false), true},
		"true":    {types.BoolValue(true), false},
		"unset":   {types.BoolNull(), false},
		"unknown": {types.BoolUnknown(), false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := wantsUnlicensed(employeeModel{Licensed: tc.licensed}); got != tc.want {
				t.Errorf("wantsUnlicensed(licensed=%v) = %v, want %v", tc.licensed, got, tc.want)
			}
		})
	}
}

// licensedTenant holds one licensed employee and records what a PATCH to them
// carries. Unlicensing deletes the record, as the API does, so the read-back
// after it is a 404.
type licensedTenant struct {
	mu      sync.Mutex
	gone    bool
	patches []map[string]any
}

func (s *licensedTenant) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path != "/v1/employees/id-1":
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		case r.Method == http.MethodPatch:
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			s.patches = append(s.patches, body)
			if v, ok := body["licensed"].(bool); ok && !v {
				s.gone = true
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("null"))
		case r.Method == http.MethodGet && s.gone:
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"status": "RECORD_NOT_FOUND", "message": "This record does not exist.",
			})
		case r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(pushapi.Employee{
				ID: "id-1", Email: "somebody@example.com", FirstName: "Some", LastName: "Body", Licensed: true,
			})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	})
}

func TestEmployeeUnlicensePatchCarriesNothingElse(t *testing.T) {
	// The API applies nothing else from a body that carries licensed = false:
	// it deletes the record and returns. A name change in the same plan must
	// not be sent with it, where it would be dropped.
	tenant := &licensedTenant{}
	srv := httptest.NewServer(tenant.handler(t))
	t.Cleanup(srv.Close)
	client, err := pushapi.New(srv.URL, "k", pushapi.WithMaxRetries(0))
	if err != nil {
		t.Fatalf("pushapi.New: %v", err)
	}
	r := &employeeResource{client: client, resolver: newEmployeeResolver(client)}
	s := employeeSchema(t, r)
	ctx := context.Background()

	prior := employeeValue(s, map[string]tftypes.Value{
		"email":           str("somebody@example.com"),
		"first_name":      str("Some"),
		"last_name":       str("Body"),
		"licensed":        boolean(true),
		"allow_unlicense": boolean(false),
		"employee_id":     str("id-1"),
		"groups":          emptyGroups(),
	})
	plan := employeeValue(s, map[string]tftypes.Value{
		"email":           str("somebody@example.com"),
		"first_name":      str("Someone"),
		"last_name":       str("Body"),
		"licensed":        boolean(false),
		"allow_unlicense": boolean(true),
		"employee_id":     str("id-1"),
		"groups":          emptyGroups(),
	})
	config := employeeValue(s, map[string]tftypes.Value{
		"email":           str("somebody@example.com"),
		"first_name":      str("Someone"),
		"last_name":       str("Body"),
		"licensed":        boolean(false),
		"allow_unlicense": boolean(true),
		"employee_id":     nullStr(),
		"groups":          tftypes.NewValue(tftypes.Set{ElementType: tftypes.String}, nil),
	})
	req := resource.UpdateRequest{
		Config: tfsdk.Config{Schema: s, Raw: config},
		Plan:   tfsdk.Plan{Schema: s, Raw: plan},
		State:  tfsdk.State{Schema: s, Raw: prior},
	}
	resp := resource.UpdateResponse{State: tfsdk.State{Schema: s, Raw: prior}}
	r.Update(ctx, req, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Update: %v", resp.Diagnostics.Errors())
	}

	tenant.mu.Lock()
	patches := tenant.patches
	tenant.mu.Unlock()
	if len(patches) != 1 {
		t.Fatalf("got %d PATCH requests, want 1: %v", len(patches), patches)
	}
	if len(patches[0]) != 1 || patches[0]["licensed"] != false {
		t.Errorf("unlicensing PATCH body = %v, want exactly {licensed: false}", patches[0])
	}

	var got employeeModel
	if d := resp.State.Get(ctx, &got); d.HasError() {
		t.Fatalf("state: %v", d)
	}
	if !got.Licensed.Equal(types.BoolValue(false)) || got.EmployeeID.ValueString() != "id-1" {
		t.Errorf("state after unlicensing = licensed %v, employee_id %v; want false and the planned identifier", got.Licensed, got.EmployeeID)
	}
}
