package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/provider/controlspec"
	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/pushapi"
)

// The helpers in this file read and write a control's configuration directly,
// as plain JSON, on whichever tenant the provider under test is pointed at:
// tenantStub offline, a real tenant in the acceptance tests. They share
// nothing with the provider's read path, the client's types included.
//
// That is the point of them. Terraform state is built by the provider's own
// GET and conversion code, so a mistake made the same way on write and on read
// passes every state check and leaves the plan empty. The read path also
// smooths over what the API returned in places: it reads an omitted
// profileScope as ALL, an excludable condition without an action as INCLUDE,
// and drops an action on a condition that does not take one. A check made here
// sees the document as the API holds it.

// storedRules returns a control's rules as the tenant holds them.
func storedRules(spec controlspec.Spec) ([]map[string]any, error) {
	var doc struct {
		Rules []map[string]any `json:"rules"`
	}
	if err := tenantRequest(http.MethodGet, spec.Path(), nil, &doc); err != nil {
		return nil, err
	}
	return doc.Rules, nil
}

// checkStoredRules asserts that the tenant holds exactly these rules for a
// control, in this order. Each is written as the JSON the API should serve,
// without its id. Values within a set may come back in any order; everything
// else must match, so a field or criterion the API holds and the test did not
// expect fails the check as surely as one that is missing.
//
// With no rules it asserts the control is empty, which is what destroy
// leaves.
func checkStoredRules(spec controlspec.Spec, want ...map[string]any) resource.TestCheckFunc {
	return func(*terraform.State) error {
		rules, err := storedRules(spec)
		if err != nil {
			return err
		}
		if len(rules) != len(want) {
			return fmt.Errorf("the tenant holds %d %s rules, want %d", len(rules), spec.APIName, len(want))
		}
		if diffs := ruleDiffs(rules, want); len(diffs) > 0 {
			return fmt.Errorf("%s rules as stored differ from what was intended:\n  %s",
				spec.APIName, strings.Join(diffs, "\n  "))
		}
		return nil
	}
}

// ruleDiffs lists every way stored rules differ from the intended ones,
// position by position and ignoring their ids. The two must be the same
// length.
func ruleDiffs(stored, want []map[string]any) []string {
	var diffs []string
	for i := range want {
		got := map[string]any{}
		for k, v := range stored[i] {
			if k != "id" {
				got[k] = v
			}
		}
		for _, d := range diffJSON("", normaliseJSON(got), normaliseJSON(want[i])) {
			diffs = append(diffs, fmt.Sprintf("rule %d: %s", i, d))
		}
	}
	return diffs
}

// seedStoredRules writes rules straight to the tenant, without Terraform, and
// returns the identifiers it assigned them. It stands in for a control
// configured in the console, which is what the adoption path imports.
func seedStoredRules(t *testing.T, spec controlspec.Spec, rules ...map[string]any) []string {
	t.Helper()
	doc := map[string]any{"globals": map[string]any{}, "rules": rules}
	if err := tenantRequest(http.MethodPut, spec.Path(), doc, nil); err != nil {
		t.Fatalf("seeding %s: %v", spec.APIName, err)
	}
	stored, err := storedRules(spec)
	if err != nil {
		t.Fatalf("reading back %s: %v", spec.APIName, err)
	}
	if len(stored) != len(rules) {
		t.Fatalf("seeded %d %s rules, the tenant holds %d", len(rules), spec.APIName, len(stored))
	}
	ids := make([]string, 0, len(stored))
	for _, r := range stored {
		id, _ := r["id"].(string)
		ids = append(ids, id)
	}
	return ids
}

// tenantRequest makes a request to the tenant the provider is configured
// for, through the same environment variables, and decodes the response into
// out when out is non-nil.
//
// Only GET and PUT go through it, and both are idempotent, so it retries what
// the client retries: 409 from configuration writes the API serialises, 429
// and server errors.
func tenantRequest(method, path string, body, out any) error {
	base := strings.TrimRight(firstNonEmpty(os.Getenv(envBaseURL), pushapi.DefaultBaseURL), "/")
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return err
		}
	}
	client := &http.Client{Timeout: 30 * time.Second}

	for attempt := 1; ; attempt++ {
		req, err := http.NewRequestWithContext(context.Background(), method, base+path, bytes.NewReader(payload))
		if err != nil {
			return err
		}
		req.Header.Set("x-api-key", os.Getenv(envAPIKey))
		req.Header.Set("Accept", "application/json")
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("%s %s: %w", method, path, err)
		}
		raw, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return fmt.Errorf("%s %s: reading response: %w", method, path, err)
		}

		retryable := resp.StatusCode == http.StatusConflict ||
			resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
		switch {
		case retryable && attempt < 5:
			time.Sleep(time.Duration(attempt) * time.Second)
			continue
		case resp.StatusCode < 200 || resp.StatusCode > 299:
			return fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, raw)
		case out == nil:
			return nil
		}
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("%s %s: decoding response: %w", method, path, err)
		}
		return nil
	}
}

// normaliseJSON gives a value the shape encoding/json decodes to, so that
// expectations can be written with any Go types, and sorts every list of
// strings. Within a rule every such list is a set: the API does not promise
// their order, and the provider does not keep it.
func normaliseJSON(v any) any {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	var out any
	if err := json.Unmarshal(raw, &out); err != nil {
		panic(err)
	}
	return sortStringLists(out)
}

func sortStringLists(v any) any {
	switch v := v.(type) {
	case map[string]any:
		for k, e := range v {
			v[k] = sortStringLists(e)
		}
	case []any:
		strs := make([]string, 0, len(v))
		for _, e := range v {
			s, ok := e.(string)
			if !ok {
				for i := range v {
					v[i] = sortStringLists(v[i])
				}
				return v
			}
			strs = append(strs, s)
		}
		slices.Sort(strs)
		for i, s := range strs {
			v[i] = s
		}
	}
	return v
}

// diffJSON lists every place got differs from want, by dotted path from at.
func diffJSON(at string, got, want any) []string {
	w, ok := want.(map[string]any)
	if !ok {
		if reflect.DeepEqual(got, want) {
			return nil
		}
		return []string{fmt.Sprintf("%s is %s, want %s", at, compactJSON(got), compactJSON(want))}
	}
	g, ok := got.(map[string]any)
	if !ok {
		return []string{fmt.Sprintf("%s is %s, want an object", at, compactJSON(got))}
	}

	var keys []string
	for k := range g {
		keys = append(keys, k)
	}
	for k := range w {
		if _, ok := g[k]; !ok {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)

	var out []string
	for _, k := range keys {
		p := k
		if at != "" {
			p = at + "." + k
		}
		gv, inGot := g[k]
		wv, inWant := w[k]
		switch {
		case !inWant:
			out = append(out, fmt.Sprintf("%s is %s, want it absent", p, compactJSON(gv)))
		case !inGot:
			out = append(out, fmt.Sprintf("%s is absent, want %s", p, compactJSON(wv)))
		default:
			out = append(out, diffJSON(p, gv, wv)...)
		}
	}
	return out
}

func compactJSON(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(raw)
}
