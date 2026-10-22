package controlspec

// Criteria shared between controls. Defined once so a change to a condition's
// shape lands everywhere it applies.
//
// Note that the API's vocabulary is not consistent across these: the
// single-valued `profileScope` uses COMPANY_DOMAIN, while
// `browserExtensionProfile` uses COMPANY_DOMAINS. Both are reproduced as the
// API defines them.
var (
	employeeIDs = Criterion{
		Name: "employee_ids", APIName: "employeeIds", Excludable: true,
		Description: "Match specific employees by email address. The provider resolves " +
			"addresses to the identifiers the API matches on, in both directions, so " +
			"configuration never holds a UUID.",
	}
	employeeGroups = Criterion{
		Name: "employee_groups", APIName: "employeeGroups", Excludable: true,
		Description: "Match employees by the groups they belong to.",
	}

	// profileScope is the API's one single-valued criterion: a one-element
	// array on the wire, flattened to a string here.
	//
	// It carries a server default because the API documents one ("If omitted,
	// defaults to ALL") and returns it on rules written without it. A rule
	// created in the console on malicious browser extension detection can come
	// back without it, so criteriaFromAPI normalises an omitted value back to
	// this default rather than to null. Absent and "ALL" mean the same thing,
	// so state says the same thing either way.
	profileScope = Criterion{
		Name: "profile_scope", APIName: "profileScope",
		Enum:          profileScopes,
		Single:        true,
		ServerDefault: "ALL",
		Description:   "Match by the profile in use on the browser.",
	}
)

// profileScopes is the criterion's value set.
var profileScopes = []string{"ALL", "COMPANY_DOMAIN", "NON_COMPANY_DOMAIN"}

// appScopedCriteria is the criteria set shared verbatim by the four app-scoped
// controls: app banner, MFA enforcement, password logging prevention and strong
// password enforcement.
//
// appCategories takes app category identifiers — opaque numeric strings such as
// "2" — because that is what the API accepts. There is no endpoint that lists
// them, so they cannot be looked up by name.
func appScopedCriteria(appTypesDesc, appLabelsDesc, appCategoriesDesc, approvalDesc, sensitivityDesc string) []Criterion {
	return []Criterion{
		employeeIDs,
		employeeGroups,
		{Name: "app_types", APIName: "appTypes", Excludable: true, Description: appTypesDesc},
		{Name: "app_labels", APIName: "appLabels", Excludable: true, Description: appLabelsDesc},
		{
			Name: "app_categories", APIName: "appCategories",
			Enum:        appCategoryIDs,
			Description: appCategoriesDesc + " Given as an app category identifier.",
		},
		{
			Name: "approval_statuses", APIName: "approvalStatuses", Excludable: true,
			Enum:        []string{"UNDER_REVIEW", "APPROVED", "NOT_APPROVED", "NOT_REVIEWED"},
			Description: approvalDesc,
		},
		{
			Name: "sensitivity_levels", APIName: "sensitivityLevels", Excludable: true,
			Enum:        []string{"HIGH", "MEDIUM", "LOW", "NOT_REVIEWED"},
			Description: sensitivityDesc,
		},
	}
}

// appCategoryIDs is the set the API accepts for criteria.appCategories. The
// identifiers are not contiguous, so the list is enumerated rather than
// generated.
var appCategoryIDs = []string{
	"2", "5", "6", "7", "8", "9", "10", "12", "14", "16", "17", "18", "20", "21",
	"23", "25", "26", "29", "30", "31", "34", "35", "36", "37", "41", "42", "43",
	"45", "46", "53", "56", "57", "58", "59", "60", "61", "62", "64", "66", "67",
	"68", "69", "71", "73", "75", "76", "77", "78", "79", "81", "83", "84", "85",
}

// Text fields shared across controls. Which modes require them differs per
// control, so the constraints stay with each spec.
var (
	titleField = Field{
		Name: "title", APIName: "title", Type: TypeString, MaxLength: 75,
		Description: "Heading shown to the user.",
	}
	subtextField = Field{
		Name: "subtext", APIName: "subtext", Type: TypeString, MaxLength: 1000,
		Description: "Message shown to the user. Markdown is supported.",
	}
	// ignoredHosts is the globals shape shared by the three detection controls.
	ignoredHostsGlobal = Global{
		Name: "ignored_hosts", APIName: "ignoredHosts", Type: GlobalStringList, MaxItems: 100,
		Description: "Hosts to ignore. Each may be a domain (`example.com`), a wildcard " +
			"(`*.example.com`), a hostname (`myhost`) or an IP address (`10.0.1.1`).",
	}
)

// bannerModes and the banner fields are shared by the two app banner controls,
// which differ only in how they select what to show the banner on.
var bannerModes = []string{"INFORM", "ACKNOWLEDGE", "REASON", "BLOCK", "DO_NOT_SHOW"}

func bannerFields(buttonTextDesc string) []Field {
	return []Field{
		titleField,
		subtextField,
		{
			Name: "button_text", APIName: "buttonText", Type: TypeString, MaxLength: 75,
			Description: buttonTextDesc,
		},
		{
			Name: "allow_reason_submission", APIName: "allowReasonSubmission", Type: TypeBool,
			Description: "Whether the user may submit a reason to proceed.",
		},
		{
			Name: "display_frequency", APIName: "displayFrequency", Type: TypeEnum,
			Enum:        []string{"ONCE_PER_BROWSER", "ONCE_PER_TAB"},
			Description: "How often the banner is shown to a matching user.",
		},
	}
}

// bannerConstraints are the cross-field rules both banner controls share.
//
// `allow_reason_submission` is only valid for BLOCK, where it is required — so
// it is both required and forbidden depending on mode. `button_text` is
// required for the two acknowledgement modes, required for BLOCK when a reason
// may be submitted, rejected for BLOCK when one may not, and rejected for
// INFORM.
func bannerConstraints() []Constraint {
	notDoNotShow := []string{"INFORM", "ACKNOWLEDGE", "REASON", "BLOCK"}
	return []Constraint{
		{Kind: RequiredForModes, Field: "title", Modes: notDoNotShow},
		{Kind: RequiredForModes, Field: "subtext", Modes: notDoNotShow},
		{Kind: RequiredForModes, Field: "button_text", Modes: []string{"ACKNOWLEDGE", "REASON"}},
		{Kind: ForbiddenForModes, Field: "button_text", Modes: []string{"INFORM"}},
		{Kind: RequiredWhenFieldTrue, Field: "button_text", Other: "allow_reason_submission"},
		{Kind: ForbiddenWhenFieldFalse, Field: "button_text", Other: "allow_reason_submission",
			Modes: []string{"BLOCK"}},
		{Kind: RequiredForModes, Field: "allow_reason_submission", Modes: []string{"BLOCK"}},
		{Kind: ForbiddenForModes, Field: "allow_reason_submission",
			Modes: []string{"INFORM", "ACKNOWLEDGE", "REASON", "DO_NOT_SHOW"}},
		// The API accepts these for DO_NOT_SHOW and stores only the mode.
		{Kind: DiscardedForModes, Field: "title", Modes: []string{"DO_NOT_SHOW"}},
		{Kind: DiscardedForModes, Field: "subtext", Modes: []string{"DO_NOT_SHOW"}},
		{Kind: DiscardedForModes, Field: "button_text", Modes: []string{"DO_NOT_SHOW"}},
		{Kind: DiscardedForModes, Field: "display_frequency", Modes: []string{"DO_NOT_SHOW"}},
	}
}
