package pushapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"testing"
)

func TestGetSettingsParses(t *testing.T) {
	var gotMethod, gotPath string
	c := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"monitoredDomains":["example.com","example.org"],"monitorAllDomains":true}`))
	}))

	s, err := c.GetSettings(context.Background())
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	if gotMethod != http.MethodGet || gotPath != "/v1/settings" {
		t.Errorf("request = %s %s, want GET /v1/settings", gotMethod, gotPath)
	}
	if want := []string{"example.com", "example.org"}; !reflect.DeepEqual(s.MonitoredDomains, want) {
		t.Errorf("MonitoredDomains = %q, want %q", s.MonitoredDomains, want)
	}
	if !s.MonitorAllDomains {
		t.Error("MonitorAllDomains = false, want true")
	}
}

func TestGetSettingsNullDomainsIsEmpty(t *testing.T) {
	c := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"monitoredDomains":null,"monitorAllDomains":false}`))
	}))
	s, err := c.GetSettings(context.Background())
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	if s.MonitoredDomains == nil || len(s.MonitoredDomains) != 0 {
		t.Errorf("MonitoredDomains = %#v, want an empty, non-nil slice", s.MonitoredDomains)
	}
}

// TestUpdateSettingsSendsOnlyNamedFields: the API changes only what a PATCH
// names, so a field left nil must not appear in the body at all, and an empty
// list must go as [] rather than be dropped or sent as null.
func TestUpdateSettingsSendsOnlyNamedFields(t *testing.T) {
	off := false
	cases := []struct {
		name string
		in   SettingsUpdate
		want map[string]any
	}{
		{
			name: "toggle only",
			in:   SettingsUpdate{MonitorAllDomains: &off},
			want: map[string]any{"monitorAllDomains": false},
		},
		{
			name: "domains only",
			in:   SettingsUpdate{MonitoredDomains: &[]string{"example.com"}},
			want: map[string]any{"monitoredDomains": []any{"example.com"}},
		},
		{
			name: "empty list clears",
			in:   SettingsUpdate{MonitoredDomains: &[]string{}},
			want: map[string]any{"monitoredDomains": []any{}},
		},
		{
			name: "nil list clears too",
			in:   SettingsUpdate{MonitoredDomains: new([]string)},
			want: map[string]any{"monitoredDomains": []any{}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got map[string]any
			var gotMethod string
			c := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotMethod = r.Method
				raw, _ := io.ReadAll(r.Body)
				if err := json.Unmarshal(raw, &got); err != nil {
					t.Errorf("body %q is not a JSON object: %v", raw, err)
				}
				_, _ = w.Write([]byte(`{"monitoredDomains":[],"monitorAllDomains":false}`))
			}))
			if _, err := c.UpdateSettings(context.Background(), tc.in); err != nil {
				t.Fatalf("UpdateSettings: %v", err)
			}
			if gotMethod != http.MethodPatch {
				t.Errorf("method = %s, want PATCH", gotMethod)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("body = %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestUpdateSettingsRefusesAnEmptyUpdate(t *testing.T) {
	c := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("an empty update reached the API")
		w.WriteHeader(http.StatusBadRequest)
	}))
	if _, err := c.UpdateSettings(context.Background(), SettingsUpdate{}); err == nil {
		t.Error("UpdateSettings with nothing set: want an error")
	}
}

func TestUpdateSettingsValidationErrorNamesTheField(t *testing.T) {
	c := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"status":"INVALID_INPUT_PROVIDED",` +
			`"message":"{\"monitoredDomains\": [\"Invalid domain(s) provided: example\"]}"}`))
	}))
	_, err := c.UpdateSettings(context.Background(), SettingsUpdate{MonitoredDomains: &[]string{"example"}})
	fields, ok := Validation(err)
	if !ok {
		t.Fatalf("err = %v, want a validation error", err)
	}
	if len(fields) != 1 || fields[0].Field != "monitoredDomains" {
		t.Errorf("field errors = %+v, want one against monitoredDomains", fields)
	}
}
