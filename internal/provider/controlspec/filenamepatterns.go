package controlspec

// File name pattern checks: CheckValue for FileNameRegexes.
//
// A file name pattern is matched as a JavaScript regular expression, with no
// flags, and a pattern that does not compile as one never matches. The Push
// API validates patterns by rules of its own: it accepts some syntax that
// JavaScript rejects, and rejects some that JavaScript accepts. So a pattern
// can fail at apply, or be stored and never match.
//
// The API also rejects, by their structure, patterns that risk catastrophic
// backtracking. That check is mirrored exactly. The two regular expression
// dialects are not reimplemented: scanFileNameRegex catches the constructs
// only one side accepts, and the commonest mistakes either rejects. `\A` and
// `\Z` are flagged although both sides accept them, because JavaScript reads
// them as letters. Anything else the API rejects still fails at apply.

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	// nestedGroupRegex is the API's first backtracking rule: two `(` with no
	// `)` between them. It reads the raw string, so an escaped `\(` or a `(`
	// in a character class counts as opening a group.
	nestedGroupRegex = regexp.MustCompile(`\([^()]*\(`)

	// quantifiedGroupRegex is the second: a group containing `*`, `+` or
	// `{n,}`, itself followed by one of those, such as `(a+)+`.
	quantifiedGroupRegex = regexp.MustCompile(`(?s)\((?:[^()\\]|\\.|\[[^\[\]]*\])*` +
		`(?:[+*]|\{[0-9]+,\})(?:[^()\\]|\\.|\[[^\[\]]*\])*\)(?:[+*]|\{[0-9]+,\})`)

	// inlineFlagsRegex is an inline flag group that applies to the whole
	// pattern, such as `(?i)`. The scoped form, `(?i:…)`, is valid in current
	// browsers and is not matched here.
	inlineFlagsRegex = regexp.MustCompile(`^\(\?[aiLmsux]+\)`)

	// braceQuantifierRegex is a `{n}`, `{n,}` or `{n,m}` quantifier.
	braceQuantifierRegex = regexp.MustCompile(`^\{[0-9]+(,[0-9]*)?\}`)
)

func checkFileNameRegex(p string) *ValueProblem {
	if p == "" {
		return &ValueProblem{
			Summary: "File name pattern is empty",
			Detail:  "The Push API rejects an empty file name pattern.",
		}
	}

	if nestedGroupRegex.MatchString(p) {
		return &ValueProblem{
			Summary: "The Push API rejects nested groups",
			Detail: fmt.Sprintf("%q has a group inside a group, which the Push API rejects as a "+
				"backtracking risk. It counts every `(` as opening a group, including an escaped "+
				"`\\(` and one inside a character class, so a literal parenthesis counts too. "+
				"Rewrite the pattern without the nesting. To match literal parentheses, put them "+
				"in one character class with whatever surrounds them, as in "+
				"`^level[ ()0-9]*\\.msi$`.", p),
		}
	}

	if quantifiedGroupRegex.MatchString(p) {
		return &ValueProblem{
			Summary: "The Push API rejects a repeated group that contains a repeat",
			Detail: fmt.Sprintf("%q repeats a group that itself contains `*`, `+` or `{n,}`, as "+
				"in `(a+)+`, which the Push API rejects as a backtracking risk. Repeat the group "+
				"or what is inside it, not both.", p),
		}
	}

	return scanFileNameRegex(p)
}

// scanFileNameRegex walks the pattern, skipping escapes and character classes,
// and reports the first construct that JavaScript's RegExp will not compile,
// that the API rejects, or that JavaScript reads differently from the API.
func scanFileNameRegex(p string) *ValueProblem {
	const summary = "File name pattern never matches"
	depth := 0

	for i := 0; i < len(p); i++ {
		switch c := p[i]; c {
		case '\\':
			if i+1 == len(p) {
				return &ValueProblem{
					Summary: "File name pattern ends with `\\`",
					Detail: fmt.Sprintf("%q ends with a `\\` that escapes nothing. The Push API "+
						"rejects it. To match a backslash, write `\\\\`.", p),
				}
			}
			if a, ok := letterAnchors[p[i+1]]; ok {
				return &ValueProblem{
					Summary: "File name pattern does not match what it says",
					Detail: fmt.Sprintf("%q uses `\\%c`, which some regular expression dialects "+
						"read as the %s of the string. File name patterns are JavaScript regular "+
						"expressions, in which `\\%c` is the letter %c, so the pattern does not "+
						"match what it says. Use `%s` instead.", p, p[i+1], a.where, p[i+1], p[i+1], a.js),
				}
			}
			// The API rejects an escaped ASCII letter it does not know, where
			// JavaScript would read it as the letter.
			if isASCIILetter(p[i+1]) && !strings.ContainsRune(apiLetterEscapes, rune(p[i+1])) {
				return &ValueProblem{
					Summary: "The Push API rejects this file name pattern",
					Detail: fmt.Sprintf("%q contains `\\%c`, which the Push API does not accept "+
						"as an escape, so it rejects the pattern. To match the letter itself, drop "+
						"the backslash.", p, p[i+1]),
				}
			}
			i++

		case '[':
			end := classEnd(p, i)
			if end < 0 {
				return &ValueProblem{
					Summary: "File name pattern has an unclosed `[`",
					Detail: fmt.Sprintf("%q opens a character class with `[` and never closes "+
						"it. The Push API rejects it.", p),
				}
			}
			i = end

		case '(':
			depth++
			if prob := checkGroupOpening(p, p[i:]); prob != nil {
				return prob
			}
			if i+1 < len(p) && p[i+1] == '?' {
				// Group syntax, not a quantifier: step over it so that the
				// `?` is not read as one below.
				i++
			} else if quantifierAt(p, i+1) {
				return nothingToRepeatProblem(p)
			}

		case ')':
			depth--
			if depth < 0 {
				return unbalancedProblem(p)
			}

		// An anchor cannot be repeated either, in either language.
		case '|', '^', '$':
			if quantifierAt(p, i+1) {
				return nothingToRepeatProblem(p)
			}

		case '*', '+', '?', '{':
			end := i
			if c == '{' {
				m := braceQuantifierRegex.FindString(p[i:])
				if m == "" {
					// A literal `{`.
					continue
				}
				end = i + len(m) - 1
			}
			if i == 0 {
				return nothingToRepeatProblem(p)
			}
			// A lazy quantifier, such as `*?`, is valid in both.
			if end+1 < len(p) && p[end+1] == '?' {
				end++
			}
			if quantifierAt(p, end+1) {
				return &ValueProblem{
					Summary: summary,
					Detail: fmt.Sprintf("%q has two quantifiers in a row, such as `*+` or `**`. "+
						"That is not valid in a JavaScript regular expression, so the pattern "+
						"never matches. Remove one. To match the character itself, escape it, as "+
						"in `\\+`.", p),
				}
			}
			i = end
		}
	}

	if depth > 0 {
		return unbalancedProblem(p)
	}
	return nil
}

// checkGroupOpening catches group syntax that one side accepts and the other
// does not. s starts at the `(`.
func checkGroupOpening(p, s string) *ValueProblem {
	const summary = "File name pattern never matches"

	switch {
	case inlineFlagsRegex.MatchString(s):
		return &ValueProblem{
			Summary: summary,
			Detail: fmt.Sprintf("%q sets flags with `%s`. That is not valid in a JavaScript "+
				"regular expression, so the pattern never matches. "+
				"File name patterns are case-sensitive and take no flags. "+
				"To ignore case, spell out both cases with character classes, as in "+
				"`[Aa]ny[Dd]esk`; on file download blocking, `file_names` ignores case.",
				p, inlineFlagsRegex.FindString(s)),
		}

	case strings.HasPrefix(s, "(?P<"), strings.HasPrefix(s, "(?P="), strings.HasPrefix(s, "(?P>"):
		return &ValueProblem{
			Summary: summary,
			Detail: fmt.Sprintf("%q uses the `(?P…` named group syntax. That is not valid in "+
				"a JavaScript regular expression, so the pattern never matches. Use a plain "+
				"group, `(…)`, or `(?:…)`.", p),
		}

	case strings.HasPrefix(s, "(?#"), strings.HasPrefix(s, "(?>"):
		return &ValueProblem{
			Summary: summary,
			Detail: fmt.Sprintf("%q uses `%s…)`, which is not valid in a JavaScript regular "+
				"expression, so the pattern never matches.", p, s[:3]),
		}

	// The reverse: JavaScript's named groups, which the API rejects. `(?<=`
	// and `(?<!` are lookbehinds, which both accept.
	case strings.HasPrefix(s, "(?<") && !strings.HasPrefix(s, "(?<=") &&
		!strings.HasPrefix(s, "(?<!"):
		return &ValueProblem{
			Summary: "The Push API rejects this file name pattern",
			Detail: fmt.Sprintf("%q uses the `(?<name>…)` named group syntax, which the Push "+
				"API does not accept. Use a plain group, `(…)`, or `(?:…)`.", p),
		}
	}

	return nil
}

// letterAnchors are escapes that some regular expression dialects read as
// anchors and JavaScript, without flags, reads as plain letters.
var letterAnchors = map[byte]struct{ where, js string }{
	'A': {"start", "^"},
	'Z': {"end", "$"},
}

// apiLetterEscapes are the escaped ASCII letters the API accepts outside a
// character class. It rejects any other escaped letter.
const apiLetterEscapes = "abBdDfnNrsStuUvwWxAZ"

func isASCIILetter(b byte) bool { return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') }

// classEnd returns the index of the `]` closing the character class opened at
// p[i], or -1 if nothing closes it. A `]` straight after the `[` or `[^` is a
// literal, as the API reads it.
func classEnd(p string, i int) int {
	j := i + 1
	if j < len(p) && p[j] == '^' {
		j++
	}
	if j < len(p) && p[j] == ']' {
		j++
	}
	for ; j < len(p); j++ {
		switch p[j] {
		case '\\':
			j++
		case ']':
			return j
		}
	}
	return -1
}

// quantifierAt reports whether a quantifier starts at p[i]. The callers have
// already established that one there would have nothing to repeat.
func quantifierAt(p string, i int) bool {
	if i >= len(p) {
		return false
	}
	switch p[i] {
	case '*', '+', '?':
		return true
	case '{':
		return braceQuantifierRegex.MatchString(p[i:])
	}
	return false
}

func nothingToRepeatProblem(p string) *ValueProblem {
	return &ValueProblem{
		Summary: "File name pattern has a quantifier with nothing to repeat",
		Detail: fmt.Sprintf("%q has `*`, `+`, `?` or `{…}` where it has nothing to repeat: at "+
			"the start of the pattern, a group or an alternative, or after `^` or `$`. The Push "+
			"API rejects it. To match the character itself, escape it, as in `\\+`.", p),
	}
}

func unbalancedProblem(p string) *ValueProblem {
	return &ValueProblem{
		Summary: "File name pattern has unbalanced parentheses",
		Detail: fmt.Sprintf("%q has a `(` without a matching `)`, or the reverse. The Push API "+
			"rejects it. To match a parenthesis itself, put it in a character class, as in "+
			"`[(]`.", p),
	}
}
