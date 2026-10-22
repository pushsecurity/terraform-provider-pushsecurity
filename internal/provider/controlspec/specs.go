package controlspec

// The sixteen rule-based configuration endpoints. Each is data; the resource
// implementation is shared.
//
// Descriptions and constraints are taken from the API's own field
// descriptions, which state the mode-dependent requirements. They differ per
// control — fourteen controls have fourteen different tables — which is why
// they live here rather than in shared code.

// FileDownloadBlocking monitors, warns on or blocks file downloads.
var FileDownloadBlocking = Spec{
	TypeName: "file_download_blocking",
	APIName:  "fileDownloadBlocking",
	Endpoint: Control,
	Description: "Manages the file download blocking control: which downloads are " +
		"monitored, warned on or blocked.",
	Modes: []string{"OFF", "MONITOR", "WARN", "BLOCK"},
	Fields: []Field{
		titleField,
		subtextField,
		{
			Name: "button_text", APIName: "buttonText", Type: TypeString, MaxLength: 75,
			Description: "Label for the button that lets the user continue past a warning.",
		},
	},
	Criteria: []Criterion{
		employeeIDs,
		employeeGroups,
		{
			// A value matches anywhere in the file name, ignoring case, not
			// only the exact file name. The API lowercases each value.
			Name: "file_names", APIName: "fileNames", Excludable: true,
			Values: LowercaseValues,
			Description: "Match downloads whose file name contains any of these values, " +
				"ignoring case. A value can match anywhere in the name, so `anydesk` matches " +
				"`AnyDesk_Setup.exe` and also `AnyDesk_Manual.pdf`. With `action = \"EXCLUDE\"`, " +
				"the rule matches every download whose file name contains none of the values. " +
				"The API stores values in lowercase, so write them that way.",
		},
		{
			Name: "file_name_patterns", APIName: "fileNamePatterns",
			Values:      FileNameRegexes,
			Description: fileNamePatternsDescription("downloads"),
		},
		{
			Name: "file_extensions", APIName: "fileExtensions", Excludable: true,
			Values: FileExtensionValues, MaxMatches: 200,
			Description: fileExtensionsDescription("downloads"),
		},
		{
			Name: "url_patterns", APIName: "urlPatterns",
			Values: MatchPatternURLs,
			Description: "Match downloads by URL, using match patterns such as " +
				"`*://*.example.com/*`. A download matches if a pattern matches the URL it " +
				"comes from, its referrer, or the URL of the tab it started in. " +
				matchPatternURLsDescription,
		},
		profileScope,
	},
	Constraints: []Constraint{
		{Kind: RequiredForModes, Field: "title", Modes: []string{"WARN", "BLOCK"}},
		{Kind: RequiredForModes, Field: "subtext", Modes: []string{"WARN", "BLOCK"}},
		{Kind: RequiredForModes, Field: "button_text", Modes: []string{"WARN"}},
		// "Required when mode is WARN, and must not be set for any other mode."
		{Kind: ForbiddenForModes, Field: "button_text", Modes: []string{"OFF", "MONITOR", "BLOCK"}},
		// Not in the OpenAPI description, but the API rejects a message for
		// MONITOR and OFF.
		{Kind: ForbiddenForModes, Field: "title", Modes: []string{"OFF", "MONITOR"}},
		{Kind: ForbiddenForModes, Field: "subtext", Modes: []string{"OFF", "MONITOR"}},
	},
}

// fileNamePatternsDescription, fileExtensionsDescription and
// matchPatternURLsDescription are shared by file download and upload blocking,
// which match these criteria the same way.
func fileNamePatternsDescription(what string) string {
	return "Match " + what + " whose file name matches any of these regular expressions. " +
		"They are JavaScript regular expressions: case-sensitive, unanchored and without " +
		"flags. To ignore case, use character classes, as in `[Aa]ny[Dd]esk`; to anchor, use " +
		"`^` and `$`."
}

func fileExtensionsDescription(what string) string {
	return "Match " + what + " by file extension, each a dot followed by the extension, " +
		"such as `.exe` or `.tar.gz`. Matching ignores case. The API stores extensions in " +
		"lowercase, so write them that way."
}

// The two URL pattern descriptions document how each control matches a URL
// pattern; urlpatterns.go holds the checks that rely on it.
const matchPatternURLsDescription = "`*.example.com` covers `example.com` and all its " +
	"subdomains, and a pattern matches every port. The path is case-sensitive and matched in " +
	"full, so end it with `*` to match what follows: `*://example.com/*` matches every page, " +
	"but `*://example.com/` only the site root."

// globURLsDescription is shared by clipboard blocking and the URL pattern app
// banner, which match URL patterns the same way.
const globURLsDescription = "Each `*` matches any run of characters, so `*.example.com` " +
	"matches subdomains but not `example.com` itself: add `*://example.com/*` for that. The " +
	"page's query string and fragment are ignored, and a page on a non-default port only " +
	"matches a pattern that names that port."

// FileUploadBlocking mirrors file download blocking, minus file names.
var FileUploadBlocking = Spec{
	TypeName: "file_upload_blocking",
	APIName:  "fileUploadBlocking",
	Endpoint: Control,
	Description: "Manages the file upload blocking control: which uploads are monitored, " +
		"warned on or blocked.",
	Modes: []string{"OFF", "MONITOR", "WARN", "BLOCK"},
	Fields: []Field{
		titleField,
		subtextField,
		{
			Name: "button_text", APIName: "buttonText", Type: TypeString, MaxLength: 75,
			Description: "Label of the button that lets the user continue past a warning.",
		},
	},
	Criteria: []Criterion{
		employeeIDs,
		employeeGroups,
		{
			Name: "file_name_patterns", APIName: "fileNamePatterns",
			Values:      FileNameRegexes,
			Description: fileNamePatternsDescription("uploads"),
		},
		{
			Name: "file_extensions", APIName: "fileExtensions", Excludable: true,
			Values: FileExtensionValues, MaxMatches: 200,
			Description: fileExtensionsDescription("uploads"),
		},
		{
			// A pattern matches the URL of the page the upload is made from,
			// not the URL the file is sent to.
			Name: "url_patterns", APIName: "urlPatterns",
			Values: MatchPatternURLs,
			Description: "Match uploads by the URL of the page they are made from, using match " +
				"patterns such as `*://*.example.com/*`. " + matchPatternURLsDescription,
		},
		profileScope,
	},
	Constraints: []Constraint{
		{Kind: RequiredForModes, Field: "title", Modes: []string{"WARN", "BLOCK"}},
		{Kind: RequiredForModes, Field: "subtext", Modes: []string{"WARN", "BLOCK"}},
		{Kind: RequiredForModes, Field: "button_text", Modes: []string{"WARN"}},
		// "Required when mode is WARN; not permitted otherwise."
		{Kind: ForbiddenForModes, Field: "button_text", Modes: []string{"OFF", "MONITOR", "BLOCK"}},
		// Not in the OpenAPI description, but the API rejects a message for
		// MONITOR and OFF.
		{Kind: ForbiddenForModes, Field: "title", Modes: []string{"OFF", "MONITOR"}},
		{Kind: ForbiddenForModes, Field: "subtext", Modes: []string{"OFF", "MONITOR"}},
	},
}

// AppBanner shows a banner on apps selected by app attributes.
var AppBanner = Spec{
	TypeName: "app_banner",
	APIName:  "appBanner",
	Endpoint: Control,
	Description: "Manages the app banner control: the banner shown to employees on apps " +
		"selected by app type, label, category, approval status or sensitivity.",
	Modes:  bannerModes,
	Fields: bannerFields("Label for the banner's action button."),
	Criteria: appScopedCriteria(
		"Match apps by their type.",
		"Match apps by the labels applied to them.",
		"Match apps by their category.",
		"Match apps by their approval status.",
		"Match apps by their sensitivity level.",
	),
	Constraints: bannerConstraints(),
}

// AppBannerURLPattern shows a banner on pages selected by URL.
var AppBannerURLPattern = Spec{
	TypeName: "app_banner_url_pattern",
	APIName:  "appBannerUrlPattern",
	Endpoint: Control,
	Description: "Manages the app banner (URL pattern) control: the banner shown to " +
		"employees on pages selected by URL pattern rather than by app.",
	Modes:  bannerModes,
	Fields: bannerFields("Label for the banner's button."),
	Criteria: []Criterion{
		employeeIDs,
		employeeGroups,
		{
			Name: "url_patterns", APIName: "urlPatterns",
			Values: GlobURLs,
			Description: "Match pages by URL pattern, such as `*://*.example.com/*`. " +
				globURLsDescription,
		},
	},
	Constraints: bannerConstraints(),
}

// MfaEnforcement prompts employees to acknowledge missing MFA.
var MfaEnforcement = Spec{
	TypeName: "mfa_enforcement",
	APIName:  "mfaEnforcement",
	Endpoint: Control,
	Description: "Manages the MFA enforcement control: the acknowledgement prompt shown " +
		"to employees whose accounts lack multi-factor authentication.",
	Modes: []string{"ACKNOWLEDGE", "OFF"},
	Fields: []Field{
		{
			Name: "title", APIName: "title", Type: TypeString, MaxLength: 75,
			Description: "Heading shown to the user in the acknowledgement prompt.",
		},
		{
			Name: "subtext", APIName: "subtext", Type: TypeString, MaxLength: 1000,
			Description: "Message shown to the user in the acknowledgement prompt. " +
				"Markdown is supported.",
		},
		{
			Name: "button_text", APIName: "buttonText", Type: TypeString, MaxLength: 75,
			Description: "Label for the acknowledgement button shown to the user.",
		},
	},
	Criteria: appScopedCriteria(
		"Match accounts by the app they belong to.",
		"Match accounts by the labels applied to their app.",
		"Match accounts by the category of the app they belong to.",
		"Match accounts by the approval status of their app.",
		"Match accounts by the sensitivity level of their app.",
	),
	Constraints: []Constraint{
		{Kind: RequiredForModes, Field: "title", Modes: []string{"ACKNOWLEDGE"}},
		{Kind: RequiredForModes, Field: "subtext", Modes: []string{"ACKNOWLEDGE"}},
		{Kind: RequiredForModes, Field: "button_text", Modes: []string{"ACKNOWLEDGE"}},
		// Not in the OpenAPI description, but the API rejects all three for
		// OFF.
		{Kind: ForbiddenForModes, Field: "title", Modes: []string{"OFF"}},
		{Kind: ForbiddenForModes, Field: "subtext", Modes: []string{"OFF"}},
		{Kind: ForbiddenForModes, Field: "button_text", Modes: []string{"OFF"}},
	},
}

// PasswordLoggingPrevention stops passwords being typed into the wrong places.
var PasswordLoggingPrevention = Spec{
	TypeName: "password_logging_prevention",
	APIName:  "passwordLoggingPrevention",
	Endpoint: Control,
	Description: "Manages the password logging prevention control: whether entering a " +
		"company password into a non-login field is monitored or blocked.",
	Modes: []string{"OFF", "MONITOR", "BLOCK"},
	Fields: []Field{
		{
			Name: "title", APIName: "title", Type: TypeString, MaxLength: 75,
			Description: "Heading shown to the user when password entry is blocked.",
		},
		{
			Name: "subtext", APIName: "subtext", Type: TypeString, MaxLength: 1000,
			Description: "Message shown to the user when password entry is blocked. " +
				"Markdown is supported.",
		},
	},
	Criteria: appScopedCriteria(
		"Match apps by their type.",
		"Match apps by the labels applied to them.",
		"Match apps by their category.",
		"Match apps by their approval status.",
		"Match apps by their sensitivity level.",
	),
	Constraints: []Constraint{
		// "Required when mode is BLOCK, and must be omitted otherwise."
		{Kind: RequiredForModes, Field: "title", Modes: []string{"BLOCK"}},
		{Kind: ForbiddenForModes, Field: "title", Modes: []string{"OFF", "MONITOR"}},
		{Kind: RequiredForModes, Field: "subtext", Modes: []string{"BLOCK"}},
		{Kind: ForbiddenForModes, Field: "subtext", Modes: []string{"OFF", "MONITOR"}},
	},
}

// StrongPasswordEnforcement prompts employees about weak or reused passwords.
var StrongPasswordEnforcement = Spec{
	TypeName: "strong_password_enforcement",
	APIName:  "strongPasswordEnforcement",
	Endpoint: Control,
	Description: "Manages the strong password enforcement control: the acknowledgement " +
		"prompt shown to employees whose passwords are weak, leaked, reused or stolen.",
	Modes: []string{"OFF", "ACKNOWLEDGE"},
	Fields: []Field{
		titleField,
		subtextField,
		{
			Name: "button_text", APIName: "buttonText", Type: TypeString, MaxLength: 75,
			Description: "Label for the acknowledgement button.",
		},
		{
			Name: "applicable_findings", APIName: "applicableFindings", Type: TypeEnumSet,
			Enum: []string{"WEAK_PASSWORD", "LEAKED_PASSWORD", "STOLEN_CREDENTIALS",
				"REUSED_PASSWORD"},
			Description: "Which password findings the rule applies to.",
		},
	},
	Criteria: appScopedCriteria(
		"Match the apps the password is used on.",
		"Match apps by the labels applied to them.",
		"Match apps by their category.",
		"Match apps by their approval status.",
		"Match apps by their assigned sensitivity level.",
	),
	Constraints: []Constraint{
		// "Required for every mode except OFF", and the only other mode is
		// ACKNOWLEDGE.
		{Kind: RequiredForModes, Field: "title", Modes: []string{"ACKNOWLEDGE"}},
		{Kind: RequiredForModes, Field: "subtext", Modes: []string{"ACKNOWLEDGE"}},
		{Kind: RequiredForModes, Field: "button_text", Modes: []string{"ACKNOWLEDGE"}},
		{Kind: RequiredForModes, Field: "applicable_findings", Modes: []string{"ACKNOWLEDGE"}},
	},
}

// ClipboardBlocking is the shape outlier: criteria are required, two rule
// fields are required, and three of its button labels depend on whether the
// rule matches regex patterns.
var ClipboardBlocking = Spec{
	TypeName: "clipboard_blocking",
	APIName:  "clipboardBlocking",
	Endpoint: Control,
	Description: "Manages the clipboard blocking control: which copy and paste " +
		"operations are monitored, warned on or blocked, and whether their content is " +
		"captured.",
	Modes: []string{"OFF", "MONITOR", "WARN", "BLOCK"},
	Fields: []Field{
		{
			Name: "operation", APIName: "operation", Type: TypeEnum, Required: true,
			Enum:        []string{"COPY", "PASTE"},
			Description: "Which clipboard operation the rule applies to.",
		},
		{
			Name: "content_capture", APIName: "contentCapture", Type: TypeBool, Required: true,
			Description: "Whether the matching clipboard content is captured on the " +
				"resulting events.",
		},
		{
			Name: "mask_pii", APIName: "maskPii", Type: TypeBool,
			Description: "Whether personally identifiable information is masked in captured " +
				"content. Required when `content_capture` is true, and must be omitted when " +
				"it is false: the API drops it.",
		},
		{
			Name: "title", APIName: "title", Type: TypeString, MaxLength: 75,
			Description: "Heading of the banner shown to the user.",
		},
		{
			Name: "subtext", APIName: "subtext", Type: TypeString, MaxLength: 1000,
			Description: "Message of the banner shown to the user. Markdown is supported.",
		},
		{
			Name: "copy_redacted_button_text", APIName: "copyRedactedButtonText",
			Type: TypeString, MaxLength: 75,
			Description: "Text of the banner button that copies a redacted version of the " +
				"content.",
		},
		{
			Name: "copy_original_button_text", APIName: "copyOriginalButtonText",
			Type: TypeString, MaxLength: 75,
			Description: "Text of the banner button that proceeds with the original content.",
		},
		{
			Name: "acknowledge_button_text", APIName: "acknowledgeButtonText",
			Type: TypeString, MaxLength: 75,
			Description: "Text of the banner button that dismisses the banner.",
		},
	},
	CriteriaRequired: true,
	Criteria: []Criterion{
		employeeIDs,
		employeeGroups,
		{
			Name: "url_patterns", APIName: "urlPatterns",
			Values: GlobURLs,
			Description: "Match by the URL of the page the clipboard operation happens on, " +
				"using URL patterns such as `*://*.example.com/*`. " + globURLsDescription,
		},
		{
			Name: "regex_patterns", APIName: "regexPatterns", MaxMatches: 250,
			Description: "Match the clipboard content against regex patterns, referenced by " +
				"their identifier. Each value must resolve to a pattern in the Push " +
				"catalogue or to one declared in `globals.custom_content_patterns`.",
		},
		profileScope,
	},
	Globals: []Global{
		{
			Name: "custom_content_patterns", APIName: "customContentPatterns",
			Type: GlobalObjectList, MaxItems: 250,
			Description: "Your organisation's custom content patterns for matching clipboard " +
				"content, available to every rule alongside the Push-defined catalogue.",
			Attributes: []Field{
				{
					Name: "name", APIName: "name", Type: TypeString, MaxLength: 60,
					Required:    true,
					Description: "A short name to help you recognise the pattern.",
				},
				{
					Name: "regex", APIName: "regex", Type: TypeString, MaxLength: 1024,
					Required:    true,
					Description: "The regular expression to match clipboard content against.",
				},
				{
					Name: "enum", APIName: "enum", Type: TypeString, Computed: true,
					Description: "Identifier that rules reference in " +
						"`criteria.regex_patterns`. Derived by the server from `name`.",
				},
			},
		},
	},
	Constraints: []Constraint{
		{Kind: RequiredWhenFieldTrue, Field: "mask_pii", Other: "content_capture"},
		// The API stores maskPii only when contentCapture is true.
		{Kind: DiscardedWhenFieldFalse, Field: "mask_pii", Other: "content_capture"},
		// "Required when mode is WARN or BLOCK, and must be omitted for
		// MONITOR and OFF."
		{Kind: RequiredForModes, Field: "title", Modes: []string{"WARN", "BLOCK"}},
		{Kind: ForbiddenForModes, Field: "title", Modes: []string{"OFF", "MONITOR"}},
		{Kind: RequiredForModes, Field: "subtext", Modes: []string{"WARN", "BLOCK"}},
		{Kind: ForbiddenForModes, Field: "subtext", Modes: []string{"OFF", "MONITOR"}},
		// "Required when mode is WARN, and must be omitted for every other mode."
		{Kind: RequiredForModes, Field: "copy_original_button_text", Modes: []string{"WARN"}},
		{Kind: ForbiddenForModes, Field: "copy_original_button_text",
			Modes: []string{"OFF", "MONITOR", "BLOCK"}},
		// The API rejects every message field for OFF and MONITOR. The
		// criterion-dependent constraints below only forbid this one when the
		// rule has no regex patterns.
		{Kind: ForbiddenForModes, Field: "copy_redacted_button_text",
			Modes: []string{"OFF", "MONITOR"}},
		// The two conditional labels depend on whether the rule matches regex
		// patterns as well as on the mode.
		{
			Kind: RequiredWhenCriterionSet, Field: "copy_redacted_button_text",
			Other: "regex_patterns", Modes: []string{"WARN", "BLOCK"},
		},
		{
			Kind: RequiredWhenCriterionAbsent, Field: "acknowledge_button_text",
			Other: "regex_patterns", Modes: []string{"BLOCK"},
		},
		{
			Kind:   AtLeastOneCriterion,
			Others: []string{"url_patterns", "regex_patterns"},
		},
	},
}

// BrowserExtensionBlocking allows or blocks extensions by their properties.
var BrowserExtensionBlocking = Spec{
	TypeName: "browser_extension_blocking",
	APIName:  "browserExtensionBlocking",
	Endpoint: Control,
	Description: "Manages the browser extension blocking control: which browser " +
		"extensions employees may install and run.",
	Modes: []string{"OFF", "ENABLE", "BLOCK"},
	Fields: []Field{
		{
			Name: "title", APIName: "title", Type: TypeString, MaxLength: 75,
			Description: "Heading shown to the user when an extension is blocked.",
		},
		{
			Name: "subtext", APIName: "subtext", Type: TypeString, MaxLength: 1000,
			Description: "Message shown to the user when an extension is blocked. " +
				"Markdown is supported.",
		},
	},
	Criteria: []Criterion{
		employeeIDs,
		employeeGroups,
		{
			// The API documents the accepted values in prose but declares no
			// enum, so they are documented and not validated: rejecting a value
			// the API would accept is worse than passing it through. Note the
			// plural, which differs from profile_scope's singular.
			Name: "browser_extension_profile", APIName: "browserExtensionProfile",
			MaxMatches: 1,
			Description: "Match extensions by the browser profile they are installed in. " +
				"One of `ALL`, `COMPANY_DOMAINS` or `NON_COMPANY_DOMAINS`.",
		},
		{
			Name: "browser_extensions", APIName: "browserExtensions", Excludable: true,
			MaxMatches: 300,
			Description: "Match specific extensions by their extension identifier, such as " +
				"a 32-character Chrome extension ID.",
		},
		{
			Name: "browser_extension_permissions", APIName: "browserExtensionPermissions",
			Excludable:  true,
			Description: "Match extensions by the browser permissions they request.",
		},
		{
			Name: "browser_extension_deployment_type", APIName: "browserExtensionDeploymentType",
			Excludable: true,
			Description: "Match extensions by how they were installed. One of " +
				"`DEVELOPMENT`, `MANAGED`, `MANUAL`, `OTHER`, `SIDELOAD` or `UNKNOWN`.",
		},
	},
	Constraints: []Constraint{
		{Kind: RequiredForModes, Field: "title", Modes: []string{"BLOCK"}},
		{Kind: RequiredForModes, Field: "subtext", Modes: []string{"BLOCK"}},
		// The API accepts a message for OFF and ENABLE, and stores only the
		// mode.
		{Kind: DiscardedForModes, Field: "title", Modes: []string{"OFF", "ENABLE"}},
		{Kind: DiscardedForModes, Field: "subtext", Modes: []string{"OFF", "ENABLE"}},
	},
}

// MaliciousBrowserExtensionDetection monitors or blocks extensions Push
// assesses as malicious.
//
// profileScope is a criterion here, as on every other control that supports
// it. The API rejects it as a rule-level field on this control.
//
// Rules written through the API without profileScope come back with ["ALL"],
// as on every other control that supports the criterion, but a rule created
// in the console can come back with criteria {} and no profileScope at all.
// The criterion still carries its ServerDefault; criteriaFromAPI normalises
// the omitted case back to it, since the API documents absent as meaning ALL.
var MaliciousBrowserExtensionDetection = Spec{
	TypeName: "malicious_browser_extension_detection",
	APIName:  "maliciousBrowserExtensionDetection",
	Endpoint: Control,
	Description: "Manages the malicious browser extension detection control: whether " +
		"extensions Push assesses as malicious are monitored or blocked.",
	Modes: []string{"OFF", "MONITOR", "BLOCK"},
	Fields: []Field{
		{
			Name: "title", APIName: "title", Type: TypeString, MaxLength: 75,
			Description: "Heading shown to the user when an extension is blocked.",
		},
		{
			Name: "subtext", APIName: "subtext", Type: TypeString, MaxLength: 1000,
			Description: "Message shown to the user when an extension is blocked. " +
				"Markdown is supported.",
		},
	},
	Criteria: []Criterion{
		employeeIDs,
		employeeGroups,
		{
			Name: "browser_extension_severities", APIName: "browserExtensionSeverities",
			Excludable: true,
			Description: "Match extensions by the severity of the detection. One of `LOW`, " +
				"`MEDIUM` or `HIGH`.",
		},
		profileScope,
	},
	Globals: []Global{
		{
			Name: "excluded_extensions", APIName: "excludedExtensions",
			Type: GlobalObjectList, MaxItems: 100,
			Description: "Extensions excluded from malicious browser extension detection.",
			Attributes: []Field{
				{
					Name: "extension_id", APIName: "extensionId", Type: TypeString,
					Required: true, NoWhitespace: true,
					Description: "The extension to exclude, identified by its extension ID, " +
						"such as a 32-character Chrome extension ID.",
				},
				{
					Name: "notes", APIName: "notes", Type: TypeString,
					Description: "Free-text notes explaining why the extension is excluded.",
				},
			},
		},
	},
	Constraints: []Constraint{
		{Kind: RequiredForModes, Field: "title", Modes: []string{"BLOCK"}},
		{Kind: ForbiddenForModes, Field: "title", Modes: []string{"OFF", "MONITOR"}},
		{Kind: RequiredForModes, Field: "subtext", Modes: []string{"BLOCK"}},
		{Kind: ForbiddenForModes, Field: "subtext", Modes: []string{"OFF", "MONITOR"}},
	},
}

// ClonedLoginPageDetection warns on or blocks cloned login pages.
var ClonedLoginPageDetection = Spec{
	TypeName: "cloned_login_page_detection",
	APIName:  "clonedLoginPageDetection",
	Endpoint: Control,
	Description: "Manages the cloned login page detection control: whether pages that " +
		"clone a login page are monitored, warned on or blocked.",
	Modes: []string{"MONITOR", "BLOCK", "WARN", "OFF"},
	Fields: []Field{
		titleField,
		subtextField,
		{
			Name: "ignore_button_text", APIName: "ignoreButtonText", Type: TypeString,
			MaxLength:   75,
			Description: "Label for the button that lets the user proceed anyway.",
		},
	},
	Criteria: []Criterion{employeeIDs, employeeGroups},
	Globals:  []Global{ignoredHostsGlobal},
	Constraints: []Constraint{
		{Kind: RequiredForModes, Field: "title", Modes: []string{"BLOCK", "WARN"}},
		{Kind: ForbiddenForModes, Field: "title", Modes: []string{"MONITOR", "OFF"}},
		{Kind: RequiredForModes, Field: "subtext", Modes: []string{"BLOCK", "WARN"}},
		{Kind: ForbiddenForModes, Field: "subtext", Modes: []string{"MONITOR", "OFF"}},
		{Kind: RequiredForModes, Field: "ignore_button_text", Modes: []string{"WARN"}},
		{Kind: ForbiddenForModes, Field: "ignore_button_text",
			Modes: []string{"MONITOR", "BLOCK", "OFF"}},
	},
}

// PhishingToolDetection warns on or blocks known phishing toolkits.
var PhishingToolDetection = Spec{
	TypeName: "phishing_tool_detection",
	APIName:  "phishingToolDetection",
	Endpoint: Control,
	Description: "Manages the phishing tool detection control: whether pages served by a " +
		"known phishing toolkit are monitored, warned on or blocked.",
	Modes: []string{"MONITOR", "BLOCK", "WARN", "OFF"},
	Fields: []Field{
		titleField,
		subtextField,
		{
			Name: "ignore_button_text", APIName: "ignoreButtonText", Type: TypeString,
			MaxLength:   75,
			Description: "Label for the button that lets the user continue.",
		},
	},
	Criteria: []Criterion{employeeIDs, employeeGroups},
	Globals:  []Global{ignoredHostsGlobal},
	Constraints: []Constraint{
		{Kind: RequiredForModes, Field: "title", Modes: []string{"BLOCK", "WARN"}},
		{Kind: ForbiddenForModes, Field: "title", Modes: []string{"MONITOR", "OFF"}},
		{Kind: RequiredForModes, Field: "subtext", Modes: []string{"BLOCK", "WARN"}},
		{Kind: ForbiddenForModes, Field: "subtext", Modes: []string{"MONITOR", "OFF"}},
		{Kind: RequiredForModes, Field: "ignore_button_text", Modes: []string{"WARN"}},
		{Kind: ForbiddenForModes, Field: "ignore_button_text",
			Modes: []string{"MONITOR", "BLOCK", "OFF"}},
	},
}

// MaliciousCopyPasteDetection catches paste-run style attacks.
var MaliciousCopyPasteDetection = Spec{
	TypeName: "malicious_copy_paste_detection",
	APIName:  "maliciousCopyPasteDetection",
	Endpoint: Control,
	Description: "Manages the malicious copy/paste detection control: whether clipboard " +
		"content that looks like an attacker-supplied command is monitored, warned on or " +
		"blocked.",
	Modes: []string{"MONITOR", "BLOCK", "WARN", "OFF"},
	Fields: []Field{
		titleField,
		subtextField,
		{
			Name: "button_text", APIName: "buttonText", Type: TypeString, MaxLength: 75,
			Description: "Label for the button that lets the user proceed.",
		},
		{
			Name: "safe_text", APIName: "safeText", Type: TypeString, MaxLength: 200,
			Description: "Message shown to the user when the paste is deemed safe.",
		},
		{
			// The server substitutes false when this is absent.
			Name: "payload_collection", APIName: "payloadCollection", Type: TypeBool,
			ServerDefault: false,
			Description: "Whether to collect the paste payload for matching activity. " +
				"Applies to `MONITOR`, `WARN` and `BLOCK`.",
		},
		{
			// Likewise: the server substitutes WINDOWS when this is absent.
			Name: "os_target", APIName: "osTarget", Type: TypeEnum,
			Enum:          []string{"WINDOWS", "UNIX"},
			ServerDefault: "WINDOWS",
			Description:   "The operating system family this rule targets.",
		},
	},
	Criteria: []Criterion{employeeIDs, employeeGroups},
	Globals:  []Global{ignoredHostsGlobal},
	Constraints: []Constraint{
		{Kind: RequiredForModes, Field: "title", Modes: []string{"BLOCK", "WARN"}},
		{Kind: ForbiddenForModes, Field: "title", Modes: []string{"MONITOR", "OFF"}},
		{Kind: RequiredForModes, Field: "subtext", Modes: []string{"BLOCK", "WARN"}},
		{Kind: ForbiddenForModes, Field: "subtext", Modes: []string{"MONITOR", "OFF"}},
		{Kind: RequiredForModes, Field: "safe_text", Modes: []string{"BLOCK", "WARN"}},
		{Kind: ForbiddenForModes, Field: "safe_text", Modes: []string{"MONITOR", "OFF"}},
		{Kind: RequiredForModes, Field: "button_text", Modes: []string{"WARN"}},
		{Kind: ForbiddenForModes, Field: "button_text",
			Modes: []string{"MONITOR", "BLOCK", "OFF"}},
	},
}

// AccountConditionEnforcement acts on logins to a fixed set of apps, depending
// on the email domain used, how the user logged in and the browser.
//
// It is the one control with required criteria: domainScope and appTypes. The
// published OpenAPI document marks only domainScope as required; the API
// rejects a rule without either. The API uppercases the values of appTypes,
// loginTypes and browserTypes, and accepts only the values listed here, so the
// closed enums make a value that would come back changed fail during plan.
var AccountConditionEnforcement = Spec{
	TypeName: "account_condition_enforcement",
	APIName:  "accountConditionEnforcement",
	Endpoint: Control,
	Description: "Manages the account condition enforcement control: whether logins to " +
		"selected apps are monitored, warned on or blocked, depending on the email domain " +
		"the user logs in with, how they log in and the browser they use. A `WARN` rule " +
		"shows a page the user can continue past or end the session from; a `BLOCK` rule " +
		"shows one from which they can only end it, which signs them out of the app.",
	Modes: []string{"OFF", "MONITOR", "WARN", "BLOCK"},
	Fields: []Field{
		{
			Name: "title", APIName: "title", Type: TypeString, MinLength: 1, MaxLength: 75,
			Description: "Heading of the page shown to the user.",
		},
		{
			Name: "subtext", APIName: "subtext", Type: TypeString, MinLength: 1, MaxLength: 1000,
			Description: "Message of the page shown to the user. Markdown is supported.",
		},
		{
			Name: "terminate_button_text", APIName: "terminateButtonText", Type: TypeString,
			MinLength: 1, MaxLength: 75,
			Description: "Text of the button that ends the session, signing the user out of " +
				"the app.",
		},
		{
			Name: "continue_button_text", APIName: "continueButtonText", Type: TypeString,
			MinLength: 1, MaxLength: 75,
			Description: "Text of the button that lets the user continue past the warning.",
		},
	},
	CriteriaRequired: true,
	Criteria: []Criterion{
		employeeIDs,
		employeeGroups,
		{
			Name: "app_types", APIName: "appTypes", Required: true,
			Enum: accountConditionAppTypes,
			Description: "Match logins to these apps. `ANTHROPIC` and `ANTHROPIC_CLAUDE` are " +
				"treated as one app, as are `OPENAI` and `OPENAI_CHATGPT`, so naming either " +
				"covers both.",
		},
		{
			Name: "domain_scope", APIName: "domainScope", Required: true, Single: true,
			Enum: []string{"COMPANY_DOMAINS", "NON_COMPANY_DOMAINS", "SPECIFIC_DOMAINS"},
			Description: "Match by the domain of the email the user logs in with: " +
				"`COMPANY_DOMAINS` matches an email on one of your company domains, " +
				"`NON_COMPANY_DOMAINS` an email on any other domain, and `SPECIFIC_DOMAINS` " +
				"the domains listed in `login_domains`.",
		},
		{
			Name: "login_domains", APIName: "loginDomains", Excludable: true,
			Values: DomainValues,
			Description: "The email domains to match. Required when `domain_scope` is " +
				"`SPECIFIC_DOMAINS`, and must be omitted otherwise. A login matches when its " +
				"email's domain is one of these exactly, so `example.com` does not match " +
				"`user@mail.example.com`. With `action = \"EXCLUDE\"`, the rule matches every " +
				"login whose email domain is not listed. The API stores domains in lowercase, " +
				"so write them that way.",
		},
		{
			Name: "login_types", APIName: "loginTypes", Excludable: true,
			Enum: []string{"PASSWORD_LOGIN", "OIDC", "FEDCM"},
			Description: "Match by how the user logs in: `PASSWORD_LOGIN` with a username and " +
				"password, `OIDC` or `FEDCM` through single sign-on over that protocol. A rule " +
				"with this criterion, whatever its `action`, only matches at login; a rule " +
				"without it also matches a session that is already signed in as it is used.",
		},
		{
			Name: "browser_types", APIName: "browserTypes", Excludable: true,
			Enum: []string{"ARC", "ATLAS", "BRAVE", "CHROME", "COMET", "DIA", "EDGE", "FIREFOX",
				"ISLAND", "OPERA", "PRISMA_ACCESS", "SAFARI"},
			Description: "Match by the browser in use, as the Push browser extension " +
				"identifies it.",
		},
		profileScope,
	},
	Constraints: []Constraint{
		// "Required when mode is WARN or BLOCK, and must be omitted for
		// MONITOR and OFF."
		{Kind: RequiredForModes, Field: "title", Modes: []string{"WARN", "BLOCK"}},
		{Kind: ForbiddenForModes, Field: "title", Modes: []string{"OFF", "MONITOR"}},
		{Kind: RequiredForModes, Field: "subtext", Modes: []string{"WARN", "BLOCK"}},
		{Kind: ForbiddenForModes, Field: "subtext", Modes: []string{"OFF", "MONITOR"}},
		{Kind: RequiredForModes, Field: "terminate_button_text", Modes: []string{"WARN", "BLOCK"}},
		{Kind: ForbiddenForModes, Field: "terminate_button_text", Modes: []string{"OFF", "MONITOR"}},
		// "Required when mode is WARN, and must be omitted for every other mode."
		{Kind: RequiredForModes, Field: "continue_button_text", Modes: []string{"WARN"}},
		{Kind: ForbiddenForModes, Field: "continue_button_text",
			Modes: []string{"OFF", "MONITOR", "BLOCK"}},
		{
			Kind: CriterionRequiredForValues, Criterion: "login_domains",
			Other: "domain_scope", Values: []string{"SPECIFIC_DOMAINS"},
		},
	},
}

// accountConditionAppTypes are the apps account condition enforcement supports.
// Unlike appTypes on the other controls, which takes any app Push knows, the
// API accepts only this list. It grows as the control gains support for more
// apps; add each new value here.
var accountConditionAppTypes = []string{
	"ANTHROPIC", "ANTHROPIC_CLAUDE", "AWS", "BOX", "COPILOT", "DEEPSEEK", "DROPBOX", "FIGMA",
	"GITHUB", "GOOGLE_GEMINI", "GROK", "MICROSOFT_COPILOT", "NOTION", "OPENAI",
	"OPENAI_CHATGPT", "PERPLEXITY",
}

// FileDownloadTelemetry and FileUploadTelemetry are the two telemetry
// configurations. They share the control document shape exactly but have no
// rule fields at all: a rule is a name, a mode and its criteria.
var FileDownloadTelemetry = Spec{
	TypeName: "file_download_telemetry",
	APIName:  "fileDownload",
	Endpoint: Telemetry,
	Description: "Manages the file download telemetry configuration: whose file downloads " +
		"are recorded.",
	Modes:    []string{"OFF", "ON"},
	Criteria: []Criterion{employeeIDs, employeeGroups, profileScope},
}

// FileUploadTelemetry is the upload half; see FileDownloadTelemetry.
var FileUploadTelemetry = Spec{
	TypeName: "file_upload_telemetry",
	APIName:  "fileUpload",
	Endpoint: Telemetry,
	Description: "Manages the file upload telemetry configuration: whose file uploads are " +
		"recorded, and where telemetry is collected from.",
	Modes:    []string{"OFF", "ON"},
	Criteria: []Criterion{employeeIDs, employeeGroups, profileScope},
}

// All is every control resource the provider registers.
var All = []Spec{
	// App-scoped controls.
	AppBanner,
	MfaEnforcement,
	PasswordLoggingPrevention,
	StrongPasswordEnforcement,
	AccountConditionEnforcement,
	// URL, file and clipboard controls, plus telemetry.
	AppBannerURLPattern,
	FileDownloadBlocking,
	FileUploadBlocking,
	ClipboardBlocking,
	FileDownloadTelemetry,
	FileUploadTelemetry,
	// Extension and detection controls.
	BrowserExtensionBlocking,
	MaliciousBrowserExtensionDetection,
	ClonedLoginPageDetection,
	PhishingToolDetection,
	MaliciousCopyPasteDetection,
}
