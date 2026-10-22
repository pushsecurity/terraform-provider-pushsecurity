package controlspec

// CustomDetectionRules describes the rule shape of a custom detection.
//
// Custom detections are not configuration-shaped endpoints — they are real
// CRUD with their own identity — so this Spec is not part of All and its
// Endpoint, APIName and Path are unused. It exists so that the rule schema,
// conversion and identity machinery shared by the sixteen control resources
// covers custom detection rules too, rather than being reimplemented.
var CustomDetectionRules = Spec{
	TypeName:    "custom_detection",
	Description: "Custom detection rules.",
	Modes:       []string{"MONITOR", "WARN", "BLOCK", "OFF"},
	Fields: []Field{
		{
			Name: "severity", APIName: "severity", Type: TypeEnum,
			Enum:        []string{"LOW", "MEDIUM", "HIGH", "CRITICAL"},
			Description: "The severity of a detection this rule produces.",
		},
		titleField,
		subtextField,
		{
			Name: "button_text", APIName: "buttonText", Type: TypeString, MaxLength: 75,
			Description: "Label for the message's action button.",
		},
		{
			// The server substitutes false when absent, and forces false for
			// mode OFF regardless of what is sent.
			Name: "detect_on_internal_hosts", APIName: "detectOnInternalHosts", Type: TypeBool,
			ServerDefault: false,
			Description: "Whether the rule also applies to private IP addresses and internal " +
				"hosts. Always false for mode `OFF`.",
		},
	},
	Criteria: []Criterion{employeeIDs, employeeGroups},
	Constraints: []Constraint{
		// "Required for every mode except OFF."
		{Kind: RequiredForModes, Field: "severity", Modes: []string{"MONITOR", "WARN", "BLOCK"}},
		{Kind: RequiredForModes, Field: "title", Modes: []string{"WARN", "BLOCK"}},
		{Kind: RequiredForModes, Field: "subtext", Modes: []string{"WARN", "BLOCK"}},
		{Kind: RequiredForModes, Field: "button_text", Modes: []string{"WARN"}},
		{Kind: ForbiddenTrueForModes, Field: "detect_on_internal_hosts", Modes: []string{"OFF"}},
		// Not in the OpenAPI description, but the API rejects each of these
		// outside the modes that use it.
		{Kind: ForbiddenForModes, Field: "severity", Modes: []string{"OFF"}},
		{Kind: ForbiddenForModes, Field: "title", Modes: []string{"OFF", "MONITOR"}},
		{Kind: ForbiddenForModes, Field: "subtext", Modes: []string{"OFF", "MONITOR"}},
		{Kind: ForbiddenForModes, Field: "button_text", Modes: []string{"OFF", "MONITOR", "BLOCK"}},
	},
}
