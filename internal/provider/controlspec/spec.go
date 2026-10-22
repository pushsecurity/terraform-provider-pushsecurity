// Package controlspec describes the rule-based control endpoints declaratively.
//
// Sixteen endpoints — fourteen controls and two telemetry configurations —
// share one wire shape and differ only in which modes, rule fields and criteria
// keys they accept. A Spec captures those differences so that one resource
// implementation covers all of them and adding a control is a data change.
package controlspec

// The API's size limits. Each is a 400 at apply when exceeded, so the schema
// checks them during plan, and push-tf-bootstrap reports a tenant that is
// already past one.
const (
	// MaxRules is the most rules one control or custom detection may hold.
	MaxRules = 50
	// MaxRuleNameLength is the longest rule name the API accepts.
	MaxRuleNameLength = 250
	// DefaultMaxMatches is the most values one condition may hold, unless the
	// criterion sets MaxMatches.
	DefaultMaxMatches = 50
	// MaxBlockedURLs is the most entries the blocked URL list may hold.
	MaxBlockedURLs = 2000
)

// Endpoint is which family of configuration endpoints a Spec is served from.
// The two differ only in their path.
type Endpoint int

const (
	// Control is /v1/controls/<name>/configuration.
	Control Endpoint = iota
	// Telemetry is /v1/telemetry/<name>/configuration.
	Telemetry
)

// Spec describes one control configuration endpoint.
type Spec struct {
	// TypeName is the Terraform resource type without the provider prefix,
	// e.g. "file_download_blocking" for pushsecurity_file_download_blocking.
	TypeName string

	// APIName is the endpoint's path segment, e.g. "fileDownloadBlocking".
	APIName string

	Endpoint    Endpoint
	Description string

	// Modes are the permitted values of a rule's mode, in the order the API
	// documents them.
	Modes []string

	Globals []Global

	// Fields are the rule attributes beyond the universal name, enabled, mode
	// and criteria.
	Fields []Field

	Criteria []Criterion

	// CriteriaRequired is true where the API rejects a rule without criteria:
	// clipboardBlocking, and any control with a Required criterion.
	CriteriaRequired bool

	// Constraints are the API's cross-field rules, mirrored client-side so that
	// they fail during plan rather than as a 400 at apply. There is no dry-run
	// endpoint, so without these a rejected configuration is only discovered
	// after the pull request has merged.
	Constraints []Constraint
}

// FieldType is the shape of a rule field's value, which decides its schema
// attribute and how it converts to and from the wire.
type FieldType int

const (
	// TypeString is free text.
	TypeString FieldType = iota
	// TypeBool is a boolean.
	TypeBool
	// TypeEnum is one of the values in Enum.
	TypeEnum
	// TypeEnumSet is a set rather than a list because the API does not promise
	// to preserve order.
	TypeEnumSet
)

// Field is one rule attribute beyond the universal ones.
type Field struct {
	// Name is the Terraform attribute name, e.g. "button_text"; APIName is the
	// wire name, e.g. "buttonText".
	Name    string
	APIName string

	Type FieldType

	// Enum lists the permitted values for TypeEnum and TypeEnumSet.
	Enum []string

	// MaxLength, when non-zero, is the API's limit on a string field.
	MaxLength int

	// MinLength, when non-zero, is the shortest string the API accepts. Most
	// controls store an empty string as sent; account condition enforcement
	// rejects one.
	MinLength int

	// NoWhitespace marks a string field the API rejects if it contains any
	// whitespace at all.
	NoWhitespace bool

	// Required marks a field the API demands on every rule regardless of mode.
	// Mode-dependent requirements belong in Constraints instead.
	Required bool

	// Computed marks a value the server derives when it is absent. The
	// attribute is optional and computed: the practitioner may leave it out
	// and have the server derive it, or set it to the value the server would
	// derive. Only the clipboard custom content pattern `enum` is like this.
	Computed bool

	// ServerDefault, when non-nil, is the value the server substitutes when the
	// field is absent: a string for TypeString and TypeEnum, a bool for
	// TypeBool. The attribute becomes optional-and-computed with this default,
	// so that an omitted field plans to what the server will actually return.
	//
	// The OpenAPI description does not document these. The smoke test applies
	// every control with any such field it leaves out planned to its default,
	// and checks both the plan that follows and what the API then holds.
	ServerDefault any

	Description string
}

// GlobalType is the shape of a control-wide setting's value.
type GlobalType int

const (
	// GlobalStringList is a list of plain strings, e.g. ignoredHosts.
	GlobalStringList GlobalType = iota
	// GlobalObjectList is a list of objects, e.g. excludedExtensions and
	// customContentPatterns.
	GlobalObjectList
)

// Global is one control-wide setting, living under the resource's `globals`
// attribute. Most controls have none; the API still requires the object to be
// present, which the client handles.
type Global struct {
	// Name is the Terraform attribute name, e.g. "ignored_hosts"; APIName is
	// the wire name, e.g. "ignoredHosts".
	Name    string
	APIName string

	Type GlobalType

	// MaxItems, when non-zero, is the API's limit on the list length.
	MaxItems int

	// Attributes describes the object for GlobalObjectList.
	Attributes []Field

	Description string
}

// Criterion is one permitted criteria key.
type Criterion struct {
	// Name is the Terraform attribute name, e.g. "employee_groups"; APIName is
	// the wire name, e.g. "employeeGroups".
	Name    string
	APIName string

	// Excludable is true where the condition accepts an action of INCLUDE or
	// EXCLUDE. Include-only conditions reject the field entirely, so it is not
	// present in their schema.
	//
	// The server echoes action: INCLUDE when it is omitted on an excludable
	// condition, so the attribute is optional and computed with a default of
	// INCLUDE. Without that, every plan after an apply would show a diff.
	Excludable bool

	// Enum, when non-empty, constrains the values in matches.
	Enum []string

	// MaxMatches, when non-zero, is the API's limit on the number of values
	// in matches where it differs from DefaultMaxMatches.
	MaxMatches int

	// Required marks a criterion the API demands on every rule. The spec
	// must then set CriteriaRequired as well, since a rule without criteria
	// cannot hold it.
	Required bool

	// Single collapses the wire's one-element array to a plain string in HCL.
	// profileScope and account condition enforcement's domainScope are shaped
	// this way.
	Single bool

	// ServerDefault, when non-empty, is the value the server materialises when
	// the criterion is absent from the request. profileScope comes back as
	// ["ALL"] on rules written through the API without it, including rules
	// sent with empty criteria, so the attribute must be computed with this
	// default or state will not match configuration.
	ServerDefault string

	// Values says how the API and the browser extension treat each value in
	// matches, for the criteria where a value the schema accepts can still
	// fail: rejected by the API at apply, rewritten by it so that the
	// read-back no longer matches, or stored and then never matched.
	// CheckValue holds the rules for each kind.
	Values ValueKind

	Description string
}

// ResolvesEmails reports whether configuration names this criterion's values
// by employee email address, leaving the provider to resolve them to the
// identifiers the wire carries.
//
// Only employeeIds is like this, and it is derived from the wire name rather
// than declared per criterion because there is no case for the alternative: a
// UUID in a pull request is unreviewable, where an email address says who the
// rule is about. Every other criterion already matches on something a person
// can read — a group name, an app category, a URL pattern.
func (c Criterion) ResolvesEmails() bool { return c.APIName == "employeeIds" }

// MatchesLimit is the most values the API accepts in this criterion's matches.
func (c Criterion) MatchesLimit() int {
	if c.MaxMatches > 0 {
		return c.MaxMatches
	}
	return DefaultMaxMatches
}

// ConstraintKind is which cross-field rule a Constraint states. Each kind
// says which of the Constraint's fields it reads.
type ConstraintKind int

const (
	// RequiredForModes means the field must be set when mode is one of Modes.
	RequiredForModes ConstraintKind = iota
	// ForbiddenForModes means the field must be absent when mode is one of Modes.
	ForbiddenForModes
	// DiscardedForModes also means the field must be absent when mode is one
	// of Modes, but for a different reason: the API accepts the field and then
	// drops it, so the rule is written and the value does not come back.
	// Distinct from ForbiddenForModes because the failure is "Provider produced
	// inconsistent result after apply" rather than a 400, and the diagnostic
	// should say which.
	DiscardedForModes
	// ForbiddenTrueForModes means a boolean field must not be true when mode is
	// one of Modes. Distinct from ForbiddenForModes because an explicit false
	// is fine: the server forces the value to false in those modes, so sending
	// true would come back changed.
	ForbiddenTrueForModes
	// RequiredWhenFieldTrue means the field must be set when the boolean field
	// named Other is true.
	RequiredWhenFieldTrue
	// ForbiddenWhenFieldFalse means the field must be absent when the boolean
	// field named Other is false. When Modes is non-empty, it applies only in
	// those modes.
	ForbiddenWhenFieldFalse
	// DiscardedWhenFieldFalse also means the field must be absent when the
	// boolean field named Other is false, but because the API accepts the
	// field and then drops it, as with DiscardedForModes.
	DiscardedWhenFieldFalse
	// RequiredWhenCriterionSet means the field must be set when the criterion
	// named Other is present, and absent when it is not. When Modes is
	// non-empty, the requirement applies only in those modes; the prohibition
	// when the criterion is absent always applies.
	RequiredWhenCriterionSet
	// RequiredWhenCriterionAbsent is the mirror image: the field must be set
	// when the criterion named Other is *not* present and mode is one of
	// Modes, and must be absent in every other combination.
	RequiredWhenCriterionAbsent
	// AtLeastOneCriterion means at least one of Others must be present.
	AtLeastOneCriterion
	// CriterionRequiredForValues constrains a criterion rather than a field:
	// the criterion named Criterion must be present when the single-valued
	// criterion named Other holds one of Values, and absent when it holds any
	// other value. Nothing is checked while Other is absent or not yet known.
	CriterionRequiredForValues
)

// Constraint is one cross-field rule taken from the API's field descriptions.
type Constraint struct {
	Kind ConstraintKind
	// Field is the rule attribute the constraint applies to. Empty for
	// AtLeastOneCriterion, which applies to the rule as a whole, and for
	// CriterionRequiredForValues, which applies to Criterion.
	Field string
	// Criterion is the criterion the constraint applies to, for
	// CriterionRequiredForValues.
	Criterion string
	// Modes lists the modes the constraint applies to, for the mode kinds.
	Modes []string
	// Other names the field or criterion the constraint depends on.
	Other string
	// Others names several criteria, for AtLeastOneCriterion.
	Others []string
	// Values lists the values of Other that require Criterion, for
	// CriterionRequiredForValues.
	Values []string
}

// Path is the URL path the configuration is read from and written to.
func (s Spec) Path() string {
	if s.Endpoint == Telemetry {
		return "/v1/telemetry/" + s.APIName + "/configuration"
	}
	return "/v1/controls/" + s.APIName + "/configuration"
}

// ResourceName is the Terraform resource type, provider prefix included.
func (s Spec) ResourceName() string { return "pushsecurity_" + s.TypeName }

// Field returns the rule field with this Terraform attribute name.
func (s Spec) Field(name string) (Field, bool) {
	for _, f := range s.Fields {
		if f.Name == name {
			return f, true
		}
	}
	return Field{}, false
}

// Criterion returns the criterion with this Terraform attribute name.
func (s Spec) Criterion(name string) (Criterion, bool) {
	for _, c := range s.Criteria {
		if c.Name == name {
			return c, true
		}
	}
	return Criterion{}, false
}
