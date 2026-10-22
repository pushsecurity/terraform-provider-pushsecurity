package controlspec

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ValueKind says how the API and the browser extension treat the values of a
// criterion's matches, for the criteria where that differs from "any string".
type ValueKind int

const (
	// PlainValues have no checks beyond the schema's.
	PlainValues ValueKind = iota

	// LowercaseValues are lowercased by the API on write: file download
	// blocking's file names, which the extension then matches as a
	// case-insensitive substring.
	LowercaseValues

	// FileExtensionValues are lowercased by the API on write and must be a dot
	// followed by one or two labels of letters, digits and hyphens, such as
	// `.exe` or `.tar.gz`.
	FileExtensionValues

	// DomainValues are plain domains, lowercased by the API on write: account
	// condition enforcement's login domains, which the extension compares
	// with the domain of the login email.
	DomainValues

	// The three kinds below are checked in urlpatterns.go and
	// filenamepatterns.go; the comment at the top of each says why.

	// MatchPatternURLs are `*://` URL patterns evaluated as WebExtension match
	// patterns. File download and upload blocking.
	MatchPatternURLs

	// GlobURLs are `*://` URL patterns matched as a regular expression in
	// which `*` is `.*`, `.` matches only itself, and every other character
	// keeps its regular expression meaning. Clipboard blocking and the URL
	// pattern app banner.
	GlobURLs

	// FileNameRegexes are regular expressions matched as JavaScript `RegExp`
	// patterns, which the API validates by different rules. File download and
	// upload blocking.
	FileNameRegexes
)

// ValueProblem is what is wrong with one criterion value.
type ValueProblem struct {
	// Warning marks a value that works, but not the way it reads.
	Warning bool
	// Summary is a one-line statement of the problem.
	Summary string
	// Detail explains what happens to the value and what to write instead.
	Detail string
}

// CheckValue returns what is wrong with one value of the criterion's matches,
// or nil when nothing is.
//
// A value the schema accepts can still fail in three ways, and only the first
// is visible without this:
//
//   - The API rejects it, and the apply fails with a 400.
//   - The API rewrites it before storing it. The provider sets state from what
//     the API stored, so the apply fails with "Provider produced inconsistent
//     result after apply".
//   - The API stores it, but it can never match. Nothing fails: the rule
//     just never matches.
//
// There is no dry-run endpoint, so plan is the only place to catch any of
// them before the pull request merges.
func (c Criterion) CheckValue(v string) *ValueProblem {
	switch c.Values {
	case LowercaseValues:
		return checkLowercase(v, "file names")
	case FileExtensionValues:
		return checkFileExtension(v)
	case DomainValues:
		return checkDomain(v)
	case MatchPatternURLs, GlobURLs:
		return checkURLPattern(v, c.Values)
	case FileNameRegexes:
		return checkFileNameRegex(v)
	}
	return nil
}

// checkLowercase catches a value the API will lowercase on write, which would
// come back different from what was planned.
func checkLowercase(v, what string) *ValueProblem {
	if lower := strings.ToLower(v); lower != v {
		return &ValueProblem{
			Summary: "Value must be lowercase",
			Detail: fmt.Sprintf("The Push API stores %s in lowercase and matches them ignoring "+
				"case, so %q would be stored as %q and the apply would report an "+
				"inconsistent result. Write %q.", what, v, lower, lower),
		}
	}
	return nil
}

// fileExtensionRegex is the file extension format the API accepts.
var fileExtensionRegex = regexp.MustCompile(`^\.[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)?$`)

func checkFileExtension(v string) *ValueProblem {
	if !fileExtensionRegex.MatchString(v) {
		return &ValueProblem{
			Summary: "Not a file extension the Push API accepts",
			Detail: fmt.Sprintf("%q is not a file extension the Push API accepts: write a dot "+
				"followed by letters, digits or hyphens, such as `.exe`, with at most one "+
				"more dot, such as `.tar.gz`.", v),
		}
	}
	return checkLowercase(v, "file extensions")
}

// maxDomainLength is the longest domain the API accepts.
const maxDomainLength = 253

// checkDomain applies the API's deliberately loose domain check: at most 253
// characters, at least one dot, and no whitespace, `@` or `*`.
func checkDomain(v string) *ValueProblem {
	if utf8.RuneCountInString(v) > maxDomainLength || !strings.Contains(v, ".") ||
		strings.ContainsAny(v, "@*") || strings.IndexFunc(v, unicode.IsSpace) >= 0 {
		return &ValueProblem{
			Summary: "Not a domain the Push API accepts",
			Detail: fmt.Sprintf("%q is not a domain the Push API accepts: write a domain such as "+
				"`example.com`, with at least one dot, no wildcard, `@` or whitespace, and at most "+
				"%d characters.", v, maxDomainLength),
		}
	}
	return checkLowercase(v, "login domains")
}
