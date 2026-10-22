package controlspec

import (
	"slices"
	"strings"
	"testing"
)

// TestSpecsAreInternallyConsistent checks each spec against itself: that every
// constraint names a field and modes that actually exist, that names do not
// collide, and that the API and Terraform naming conventions hold.
//
// The specs are sixteen blocks of hand-transcribed data, so the realistic
// failure is a typo that disables a validator without any error rather than
// one that fails to compile.
func TestSpecsAreInternallyConsistent(t *testing.T) {
	for _, s := range All {
		t.Run(s.TypeName, func(t *testing.T) {
			if s.TypeName == "" || s.APIName == "" {
				t.Fatal("TypeName and APIName are both required")
			}
			if len(s.Modes) == 0 {
				t.Error("a control with no modes cannot have a valid rule")
			}
			if s.Description == "" {
				t.Error("Description is required; it becomes the resource documentation")
			}

			fields := map[string]Field{}
			for _, f := range s.Fields {
				if _, dup := fields[f.Name]; dup {
					t.Errorf("duplicate field %q", f.Name)
				}
				fields[f.Name] = f

				if f.APIName == "" {
					t.Errorf("field %q has no APIName", f.Name)
				}
				if f.Description == "" {
					t.Errorf("field %q has no Description", f.Name)
				}
				if f.Name != snake(f.APIName) {
					t.Errorf("field %q: Terraform name should be the snake_case of APIName %q, i.e. %q",
						f.Name, f.APIName, snake(f.APIName))
				}
				if (f.Type == TypeEnum || f.Type == TypeEnumSet) && len(f.Enum) == 0 {
					t.Errorf("field %q is an enum type with no values", f.Name)
				}
				switch d := f.ServerDefault.(type) {
				case nil:
				case bool:
					if f.Type != TypeBool {
						t.Errorf("field %q has a bool ServerDefault but is not a bool field", f.Name)
					}
				case string:
					if f.Type == TypeBool {
						t.Errorf("field %q has a string ServerDefault but is a bool field", f.Name)
					}
					if f.Type == TypeEnum && !slices.Contains(f.Enum, d) {
						t.Errorf("field %q has ServerDefault %q, not among its values %v",
							f.Name, d, f.Enum)
					}
				default:
					t.Errorf("field %q has a ServerDefault of unsupported type %T", f.Name, d)
				}
				if f.Required && f.Computed {
					t.Errorf("field %q cannot be both Required and Computed", f.Name)
				}
			}

			criteria := map[string]Criterion{}
			for _, c := range s.Criteria {
				if _, dup := criteria[c.Name]; dup {
					t.Errorf("duplicate criterion %q", c.Name)
				}
				criteria[c.Name] = c

				if c.APIName == "" {
					t.Errorf("criterion %q has no APIName", c.Name)
				}
				if c.Description == "" {
					t.Errorf("criterion %q has no Description", c.Name)
				}
				if c.Name != snake(c.APIName) {
					t.Errorf("criterion %q: should be the snake_case of APIName %q, i.e. %q",
						c.Name, c.APIName, snake(c.APIName))
				}
				// A single-valued criterion is flattened to a string, so an
				// action would have nowhere to live.
				if c.Single && c.Excludable {
					t.Errorf("criterion %q cannot be both Single and Excludable", c.Name)
				}
				if c.ServerDefault != "" && !c.Single {
					t.Errorf("criterion %q has a ServerDefault but is not Single; only the "+
						"flattened form supports one", c.Name)
				}
				if c.MaxMatches < 0 || (c.Single && c.MaxMatches != 0) {
					t.Errorf("criterion %q has MaxMatches %d; it must not be negative, and a "+
						"single-valued criterion holds one value by construction",
						c.Name, c.MaxMatches)
				}
				if c.ServerDefault != "" && !slices.Contains(c.Enum, c.ServerDefault) {
					t.Errorf("criterion %q has ServerDefault %q, not among its values %v",
						c.Name, c.ServerDefault, c.Enum)
				}
				// A required criterion is never absent, so there is nothing for
				// a default to stand in for. And it cannot live in a criteria
				// block that may be omitted.
				if c.Required && c.ServerDefault != "" {
					t.Errorf("criterion %q cannot be both Required and have a ServerDefault", c.Name)
				}
				if c.Required && !s.CriteriaRequired {
					t.Errorf("criterion %q is Required, so the control must set CriteriaRequired",
						c.Name)
				}
			}

			// A rule field and a criterion must not share a name on the same
			// control.
			for name := range fields {
				if _, clash := criteria[name]; clash {
					t.Errorf("%q is both a rule field and a criterion on the same control", name)
				}
			}

			for i, c := range s.Constraints {
				checkConstraintRefs(t, i, c, s, fields, criteria)
			}

			for _, g := range s.Globals {
				if g.Name != snake(g.APIName) {
					t.Errorf("global %q: should be the snake_case of APIName %q, i.e. %q",
						g.Name, g.APIName, snake(g.APIName))
				}
				if g.Description == "" {
					t.Errorf("global %q has no Description", g.Name)
				}
				if g.Type == GlobalObjectList && len(g.Attributes) == 0 {
					t.Errorf("global %q is an object list with no attributes", g.Name)
				}
				for _, a := range g.Attributes {
					if a.Name != snake(a.APIName) {
						t.Errorf("global %q attribute %q: should be %q",
							g.Name, a.Name, snake(a.APIName))
					}
				}
			}
		})
	}
}

func checkConstraintRefs(t *testing.T, i int, c Constraint, s Spec, fields map[string]Field, criteria map[string]Criterion) {
	t.Helper()

	if c.Kind == AtLeastOneCriterion {
		if len(c.Others) < 2 {
			t.Errorf("constraint %d: AtLeastOneCriterion needs at least two criteria", i)
		}
		for _, name := range c.Others {
			if _, ok := criteria[name]; !ok {
				t.Errorf("constraint %d references unknown criterion %q", i, name)
			}
		}
		return
	}

	if c.Kind == CriterionRequiredForValues {
		checkCriterionValueRefs(t, i, c, criteria)
		return
	}

	if _, ok := fields[c.Field]; !ok {
		t.Errorf("constraint %d references unknown field %q", i, c.Field)
	}
	for _, m := range c.Modes {
		if !slices.Contains(s.Modes, m) {
			t.Errorf("constraint %d on %q references mode %q, which this control does not "+
				"have (has %v)", i, c.Field, m, s.Modes)
		}
	}

	switch c.Kind {
	case ForbiddenTrueForModes:
		if f := fields[c.Field]; f.Type != TypeBool {
			t.Errorf("constraint %d: ForbiddenTrueForModes needs a boolean, but %q is not one",
				i, c.Field)
		}
	case RequiredWhenFieldTrue, ForbiddenWhenFieldFalse, DiscardedWhenFieldFalse:
		other, ok := fields[c.Other]
		if !ok {
			t.Errorf("constraint %d references unknown field %q in Other", i, c.Other)
			return
		}
		if other.Type != TypeBool {
			t.Errorf("constraint %d: a constraint on a field being true or false needs a "+
				"boolean, but %q is not one", i, c.Other)
		}
	case RequiredWhenCriterionSet, RequiredWhenCriterionAbsent:
		if _, ok := criteria[c.Other]; !ok {
			t.Errorf("constraint %d references unknown criterion %q in Other", i, c.Other)
		}
	}
}

// checkCriterionValueRefs checks a constraint between two criteria: both must
// exist, the one it keys on must hold a single value from a known set, and the
// values must be among them. A typo in any of these disables it without any
// error.
func checkCriterionValueRefs(t *testing.T, i int, c Constraint, criteria map[string]Criterion) {
	t.Helper()

	if c.Field != "" || len(c.Modes) != 0 {
		t.Errorf("constraint %d: CriterionRequiredForValues takes Criterion, not Field or Modes", i)
	}
	subject, ok := criteria[c.Criterion]
	if !ok {
		t.Errorf("constraint %d references unknown criterion %q", i, c.Criterion)
	}
	// A criterion required on every rule cannot also be forbidden for some.
	if subject.Required {
		t.Errorf("constraint %d: %q is Required, so it cannot depend on %q", i, c.Criterion, c.Other)
	}
	other, ok := criteria[c.Other]
	if !ok {
		t.Errorf("constraint %d references unknown criterion %q in Other", i, c.Other)
		return
	}
	if !other.Single || len(other.Enum) == 0 {
		t.Errorf("constraint %d: %q must be single-valued with an enum to key a "+
			"constraint on its value", i, c.Other)
	}
	if len(c.Values) == 0 {
		t.Errorf("constraint %d: CriterionRequiredForValues needs Values", i)
	}
	for _, v := range c.Values {
		if !slices.Contains(other.Enum, v) {
			t.Errorf("constraint %d: %q is not a value of %q (has %v)", i, v, c.Other, other.Enum)
		}
	}
}

// TestNoDuplicateResourceNames guards against two specs claiming the same
// Terraform type or the same endpoint.
func TestNoDuplicateResourceNames(t *testing.T) {
	types := map[string]bool{}
	paths := map[string]bool{}
	for _, s := range All {
		if types[s.ResourceName()] {
			t.Errorf("duplicate resource name %q", s.ResourceName())
		}
		types[s.ResourceName()] = true

		if paths[s.Path()] {
			t.Errorf("duplicate endpoint %q", s.Path())
		}
		paths[s.Path()] = true
	}
}

// TestAllCoversEveryEndpoint pins the count, so that adding an endpoint without
// a spec — or a spec without an endpoint — fails here rather than going
// unnoticed. Sixteen endpoints share the configuration shape: fourteen controls
// and two telemetry configurations. blockedUrls and customDetections have
// different shapes and their own resources; stolenCredentials is deliberately
// not implemented.
func TestAllCoversEveryEndpoint(t *testing.T) {
	if len(All) != 16 {
		t.Errorf("All has %d specs, want 16", len(All))
	}
	var controls, telemetry int
	for _, s := range All {
		switch s.Endpoint {
		case Telemetry:
			telemetry++
		default:
			controls++
		}
	}
	if controls != 14 {
		t.Errorf("%d control specs, want 14", controls)
	}
	if telemetry != 2 {
		t.Errorf("%d telemetry specs, want 2", telemetry)
	}
}

func TestPath(t *testing.T) {
	if got := FileDownloadBlocking.Path(); got != "/v1/controls/fileDownloadBlocking/configuration" {
		t.Errorf("control path = %q", got)
	}
	if got := FileDownloadTelemetry.Path(); got != "/v1/telemetry/fileDownload/configuration" {
		t.Errorf("telemetry path = %q", got)
	}
}

// snake converts an API camelCase name to the Terraform convention, so the
// mapping can be checked rather than trusted.
func snake(s string) string {
	var b strings.Builder
	for i, r := range s {
		if r >= 'A' && r <= 'Z' {
			if i > 0 {
				b.WriteByte('_')
			}
			b.WriteRune(r - 'A' + 'a')
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// TestSizeLimitsMatchTheAPI pins each size limit to the number the API
// enforces, keyed by wire name so that a criterion shared by several controls
// is checked everywhere it appears.
func TestSizeLimitsMatchTheAPI(t *testing.T) {
	matches := map[string]int{
		"fileExtensions":          200,
		"regexPatterns":           250,
		"browserExtensions":       300,
		"browserExtensionProfile": 1,
	}
	globals := map[string]int{
		"ignoredHosts":          100,
		"excludedExtensions":    100,
		"customContentPatterns": 250,
	}
	for _, s := range append(All, CustomDetectionRules) {
		for _, c := range s.Criteria {
			if c.Single {
				continue
			}
			want, ok := matches[c.APIName]
			if !ok {
				want = 50
			}
			if got := c.MatchesLimit(); got != want {
				t.Errorf("%s criterion %s: MatchesLimit() = %d, want %d",
					s.TypeName, c.Name, got, want)
			}
		}
		for _, g := range s.Globals {
			if want := globals[g.APIName]; g.MaxItems != want {
				t.Errorf("%s global %s: MaxItems = %d, want %d", s.TypeName, g.Name, g.MaxItems, want)
			}
		}
	}
}
