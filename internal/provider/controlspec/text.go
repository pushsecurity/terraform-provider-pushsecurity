package controlspec

import (
	"fmt"
	"strings"
)

// The API applies two rules to rule text fields on write, and neither shows
// up until the apply.
//
// Every text field except subtext is stored, and returned, HTML-escaped: `&`
// comes back as `&amp;`, `<` as `&lt;` and `>` as `&gt;`. The provider sets
// state from what the API returns, so the apply fails with "Provider produced
// inconsistent result after apply". Writing the escaped form does not help
// either: the API keeps it as written, but these fields are shown to the user
// as plain text, so the user sees `&amp;`. A tenant adopted with
// push-tf-bootstrap holds exactly that. subtext is exempt: the API returns its
// markdown as written.
//
// Every text field, subtext included, is rejected if it contains the word
// "javascript" in any case, with an HTTP 500 rather than a validation error.

// escapedCharacters are the characters the API stores HTML-escaped.
var escapedCharacters = []string{"&", "<", ">"}

// bannedWord is the substring the API refuses in any rule text field.
const bannedWord = "javascript"

// StoredEscaped reports whether the API HTML-escapes this rule field's text on
// write. It applies to rule fields only: the control-wide settings are stored
// as written.
func (f Field) StoredEscaped() bool {
	return (f.Type == TypeString || f.Type == TypeEnum) && f.APIName != "subtext"
}

// IsText reports whether a rule field holds text the rules above apply to.
func (f Field) IsText() bool {
	return f.Type == TypeString || f.Type == TypeEnum
}

// CheckText returns what is wrong with the value of one rule text field, or
// nil when nothing is.
func (f Field) CheckText(v string) *ValueProblem {
	if !f.IsText() {
		return nil
	}

	if strings.Contains(strings.ToLower(v), bannedWord) {
		return &ValueProblem{
			Summary: "Text must not contain \"" + bannedWord + "\"",
			Detail: fmt.Sprintf("The Push API does not accept rule text containing %q, in "+
				"any combination of upper and lower case, and the apply fails. Reword `%s`.",
				bannedWord, f.Name),
		}
	}

	if !f.StoredEscaped() {
		return nil
	}
	var found []string
	for _, c := range escapedCharacters {
		if strings.Contains(v, c) {
			found = append(found, c)
		}
	}
	if len(found) == 0 {
		return nil
	}
	detail := fmt.Sprintf("The Push API stores `%s` HTML-escaped: `&` comes back as `&amp;`, "+
		"`<` as `&lt;` and `>` as `&gt;`, so the apply would report an inconsistent result. "+
		"Writing the escaped form does not help, because this text is shown to the user as "+
		"written, entity and all. Reword it without %s.",
		f.Name, Backticked(found))
	if looksEscaped(v) {
		detail += "\n\nThis text already holds an escaped form, as text adopted from the " +
			"tenant does, and it is shown to the user literally."
	}
	return &ValueProblem{
		Summary: "Text must not contain " + Backticked(found),
		Detail:  detail,
	}
}

// escapedForms are what the API stores in place of escapedCharacters.
var escapedForms = []string{"&amp;", "&lt;", "&gt;"}

func looksEscaped(v string) bool {
	for _, e := range escapedForms {
		if strings.Contains(v, e) {
			return true
		}
	}
	return false
}
