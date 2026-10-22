// Command push-tf-bootstrap prepares an existing Push tenant for management by
// the Terraform provider.
//
// Adoption is the critical path: a tenant already has configuration, and the
// first apply must be a no-op rather than a replacement of whatever is live.
// Terraform can generate the configuration itself — this tool produces the
// import blocks that let it, extracts custom detection logic into files, and
// reports configuration that the first plan will reject or warn about.
//
// It writes files and reads the API. It never writes to the API.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/provider/controlspec"
	"github.com/pushsecurity/terraform-provider-pushsecurity/internal/pushapi"
)

const (
	envAPIKey  = "PUSH_API_KEY"
	envBaseURL = "PUSH_BASE_URL"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "push-tf-bootstrap: %v\n", err)
		os.Exit(1)
	}
}

type options struct {
	outDir        string
	detectionsDir string
	skipEmpty     bool
}

// run is the whole command, given its arguments and where to write the report
// and the usage.
func run(args []string, stdout, stderr io.Writer) error {
	var opts options
	flags := flag.NewFlagSet("push-tf-bootstrap", flag.ExitOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&opts.outDir, "out", ".", "directory to write generated files into")
	flags.StringVar(&opts.detectionsDir, "detections-dir", "detections",
		"directory, relative to -out, for extracted custom detection logic")
	flags.BoolVar(&opts.skipEmpty, "skip-empty", true,
		"omit controls that have no rules; they have nothing to adopt")
	flags.Usage = func() { usage(flags) }
	// ExitOnError: a flag it cannot parse ends the process with the usage, as
	// the default command line does.
	_ = flags.Parse(args)
	// The tool takes flags only. Parsing stops at the first argument that is
	// not a flag, so any flag after it would otherwise be ignored without a
	// word.
	if flags.NArg() > 0 {
		flags.Usage()
		return fmt.Errorf("unexpected argument %q; every option is a flag", flags.Arg(0))
	}

	apiKey := os.Getenv(envAPIKey)
	if apiKey == "" {
		return fmt.Errorf("%s is not set; create a key under Settings in the Push admin "+
			"console (read-only is enough for this tool)", envAPIKey)
	}

	client, err := pushapi.New(os.Getenv(envBaseURL), apiKey,
		pushapi.WithUserAgent("push-tf-bootstrap"))
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	tenant, err := survey(ctx, client, opts)
	if err != nil {
		return err
	}

	if err := write(tenant, opts); err != nil {
		return err
	}

	return report(stdout, tenant, opts)
}

func usage(flags *flag.FlagSet) {
	_, _ = fmt.Fprint(flags.Output(), `push-tf-bootstrap prepares an existing Push tenant for Terraform.

It reads the tenant and writes:

  imports.tf              import blocks for everything worth adopting
  detections/*.yaml       each custom detection's logic, extracted verbatim
                          (the directory is set by -detections-dir)

Then, in the same directory:

  terraform plan -generate-config-out=generated.tf

Move the generated resources into your configuration, remove the `+"`provider`"+`
arguments from the import blocks, and apply. See the output for details.

It never writes to the Push API; a read-only key is sufficient.

Environment:
  PUSH_API_KEY   required
  PUSH_BASE_URL  optional; defaults to the production API

Flags:
`)
	flags.PrintDefaults()
}

// control is one control configuration found in the tenant.
type control struct {
	Spec       controlspec.Spec
	Rules      int
	Violations []ruleViolation
}

// detection is one custom detection found in the tenant.
type detection struct {
	EventType  string
	Name       string
	Logic      string
	Rules      int
	Violations []ruleViolation
	// LogicFile is the path, relative to -out, the logic was written to.
	LogicFile string
	// Label is the import block's resource label, unique among detections.
	Label string
}

// ruleViolation is configuration the API will not accept back: GET is more
// permissive than PUT, so a tenant can hold rules that cannot be rewritten.
// It is also a criterion value or rule text that the provider rejects, or
// warns about, during plan, and a list longer than the API accepts.
type ruleViolation struct {
	// RuleIndex is -1 for a problem with the resource as a whole, such as too
	// many rules.
	RuleIndex int
	RuleName  string
	Mode      string
	// Criterion or Field, with Value, name the value at fault, for a problem
	// with one criterion value or one rule field rather than with the rule as
	// a whole. Value is empty where the problem is the number of values.
	Criterion string
	Field     string
	Value     string
	Summary   string
	// Warning marks a value that plans, with a warning, rather than failing.
	Warning bool
}

type tenantSurvey struct {
	Controls    []control
	Detections  []detection
	BlockedURLs []string
	// BlockedURLViolations holds a list longer than the API accepts.
	BlockedURLViolations []ruleViolation
}

func survey(ctx context.Context, client *pushapi.Client, opts options) (*tenantSurvey, error) {
	out := &tenantSurvey{}

	for _, spec := range controlspec.All {
		var cfg *pushapi.ControlConfig
		var err error
		if spec.Endpoint == controlspec.Telemetry {
			cfg, err = client.GetTelemetryConfig(ctx, spec.APIName)
		} else {
			cfg, err = client.GetControlConfig(ctx, spec.APIName)
		}
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", spec.APIName, err)
		}
		if len(cfg.Rules) == 0 && !hasGlobals(spec, cfg.Globals) && opts.skipEmpty {
			continue
		}
		out.Controls = append(out.Controls, control{
			Spec:  spec,
			Rules: len(cfg.Rules),
			Violations: append(checkSizes(spec, len(cfg.Rules), cfg.Globals),
				checkRules(spec, cfg.Rules)...),
		})
	}

	summaries, err := client.ListCustomDetections(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing custom detections: %w", err)
	}
	// The index carries identity only and there is no expand parameter, so
	// each detection needs its own read.
	for _, s := range summaries {
		full, err := client.GetCustomDetection(ctx, s.DetectionEventType)
		if err != nil {
			return nil, fmt.Errorf("reading custom detection %s: %w", s.DetectionEventType, err)
		}
		out.Detections = append(out.Detections, detection{
			EventType: full.DetectionEventType,
			Name:      full.DetectionEventName,
			Logic:     full.DetectionLogic,
			Rules:     len(full.Rules),
			Violations: append(checkSizes(controlspec.CustomDetectionRules, len(full.Rules), nil),
				checkRules(controlspec.CustomDetectionRules, full.Rules)...),
		})
	}

	blocked, err := client.ListBlockedURLs(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing blocked URLs: %w", err)
	}
	out.BlockedURLs = blocked
	if len(blocked) > controlspec.MaxBlockedURLs {
		out.BlockedURLViolations = []ruleViolation{{
			RuleIndex: -1,
			Summary: fmt.Sprintf("%d patterns, more than the %d the API accepts",
				len(blocked), controlspec.MaxBlockedURLs),
		}}
	}

	return out, nil
}

// hasGlobals reports whether any of a control's control-wide lists has
// entries. A control with no rules but with globals still has configuration
// to adopt.
func hasGlobals(spec controlspec.Spec, globals map[string]any) bool {
	for _, g := range spec.Globals {
		if items, _ := globals[g.APIName].([]any); len(items) > 0 {
			return true
		}
	}
	return false
}

// checkSizes reports a control or detection holding more rules, or more
// entries in a control-wide list, than the API accepts. The provider checks
// the same limits during plan.
func checkSizes(spec controlspec.Spec, rules int, globals map[string]any) []ruleViolation {
	var out []ruleViolation
	if rules > controlspec.MaxRules {
		out = append(out, ruleViolation{
			RuleIndex: -1,
			Summary: fmt.Sprintf("%d rules, more than the %d the API accepts",
				rules, controlspec.MaxRules),
		})
	}
	for _, g := range spec.Globals {
		items, _ := globals[g.APIName].([]any)
		if g.MaxItems > 0 && len(items) > g.MaxItems {
			out = append(out, ruleViolation{
				RuleIndex: -1,
				Summary: fmt.Sprintf("globals.%s has %d entries, more than the %d the API accepts",
					g.Name, len(items), g.MaxItems),
			})
		}
	}
	return out
}

// checkRules evaluates the same cross-field constraints, text checks,
// criterion value checks and size limits the provider applies during plan, so
// the report predicts what a plan will say rather than approximating it.
func checkRules(spec controlspec.Spec, rules []pushapi.Rule) []ruleViolation {
	var out []ruleViolation
	for i, r := range rules {
		for _, v := range spec.CheckRule(apiRuleValues{r}) {
			out = append(out, ruleViolation{
				RuleIndex: i,
				RuleName:  r.Name,
				Mode:      r.Mode,
				Summary:   v.Summary,
			})
		}
		if n := utf8.RuneCountInString(r.Name); n > controlspec.MaxRuleNameLength {
			out = append(out, ruleViolation{
				RuleIndex: i,
				RuleName:  r.Name,
				Mode:      r.Mode,
				Summary: fmt.Sprintf("Name is %d characters, more than the %d the API accepts",
					n, controlspec.MaxRuleNameLength),
			})
		}
		// What the API stored for these fields is what it escaped on write,
		// so this is where a title holding `&amp;` turns up.
		for _, f := range spec.Fields {
			text, ok := r.Fields[f.APIName].(string)
			if !ok {
				continue
			}
			if p := f.CheckText(text); p != nil {
				out = append(out, ruleViolation{
					RuleIndex: i,
					RuleName:  r.Name,
					Mode:      r.Mode,
					Field:     f.Name,
					Value:     text,
					Summary:   p.Summary,
				})
			}
		}
		for _, c := range spec.Criteria {
			// A stored rule can lack a criterion the API requires on write,
			// and the configuration generated from it then fails plan.
			if c.Required && len(r.Criteria[c.APIName].Matches) == 0 {
				out = append(out, ruleViolation{
					RuleIndex: i,
					RuleName:  r.Name,
					Mode:      r.Mode,
					Summary:   fmt.Sprintf("`criteria.%s` is missing, which the API requires", c.Name),
				})
			}
			if n := len(r.Criteria[c.APIName].Matches); !c.Single && n > c.MatchesLimit() {
				out = append(out, ruleViolation{
					RuleIndex: i,
					RuleName:  r.Name,
					Mode:      r.Mode,
					Criterion: c.Name,
					Summary: fmt.Sprintf("%d values, more than the %d the API accepts",
						n, c.MatchesLimit()),
				})
			}
		}
		// The criteria come off the wire keyed by API name, so the spec maps
		// them back to the criterion that knows how to check them. Walking the
		// spec rather than the map keeps the report in a stable order.
		for _, c := range spec.Criteria {
			// A closed set the API extends can hold a value newer than the
			// provider's copy of it.
			for _, m := range r.Criteria[c.APIName].Matches {
				if len(c.Enum) > 0 && !slices.Contains(c.Enum, m) {
					out = append(out, ruleViolation{
						RuleIndex: i,
						RuleName:  r.Name,
						Mode:      r.Mode,
						Criterion: c.Name,
						Value:     m,
						Summary:   "Not one of the values this version of the provider accepts",
					})
				}
			}
			if c.Values == controlspec.PlainValues {
				continue
			}
			for _, m := range r.Criteria[c.APIName].Matches {
				p := c.CheckValue(m)
				if p == nil {
					continue
				}
				out = append(out, ruleViolation{
					RuleIndex: i,
					RuleName:  r.Name,
					Mode:      r.Mode,
					Criterion: c.Name,
					Value:     m,
					Summary:   p.Summary,
					Warning:   p.Warning,
				})
			}
		}
	}
	return out
}

type apiRuleValues struct{ rule pushapi.Rule }

func (a apiRuleValues) Mode() string { return a.rule.Mode }

func (a apiRuleValues) IsSet(field string) bool {
	v, present := a.rule.Fields[apiName(field)]
	if !present || v == nil {
		return false
	}
	if s, ok := v.(string); ok {
		return s != ""
	}
	if items, ok := v.([]any); ok {
		return len(items) > 0
	}
	return true
}

func (a apiRuleValues) IsTrue(field string) bool {
	b, _ := a.rule.Fields[apiName(field)].(bool)
	return b
}

func (a apiRuleValues) IsFalse(field string) bool {
	b, ok := a.rule.Fields[apiName(field)].(bool)
	return ok && !b
}

func (a apiRuleValues) HasCriterion(name string) bool {
	c, present := a.rule.Criteria[apiName(name)]
	return present && len(c.Matches) > 0
}

func (a apiRuleValues) CriterionValue(name string) string {
	c := a.rule.Criteria[apiName(name)]
	if len(c.Matches) != 1 {
		return ""
	}
	return c.Matches[0]
}

// apiName converts a Terraform attribute name back to the API's camelCase.
// Constraints are written in terms of attribute names, but the data here came
// off the wire.
func apiName(attr string) string {
	parts := strings.Split(attr, "_")
	for i := 1; i < len(parts); i++ {
		if parts[i] == "" {
			continue
		}
		parts[i] = strings.ToUpper(parts[i][:1]) + parts[i][1:]
	}
	return strings.Join(parts, "")
}

func write(t *tenantSurvey, opts options) error {
	if err := os.MkdirAll(opts.outDir, 0o755); err != nil {
		return fmt.Errorf("creating %s: %w", opts.outDir, err)
	}

	// Detection logic goes to files so that `file()` can read it, which is what
	// makes the logic reviewable as a diff rather than as an escaped string.
	if len(t.Detections) > 0 {
		dir := filepath.Join(opts.outDir, opts.detectionsDir)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("creating %s: %w", dir, err)
		}
		slugs := uniqueSlugs(t.Detections)
		for i := range t.Detections {
			d := &t.Detections[i]
			base := slugs[i] + ".yaml"
			d.Label = identifier(slugs[i])
			d.LogicFile = filepath.Join(opts.detectionsDir, base)
			full := filepath.Join(opts.outDir, d.LogicFile)
			// Written byte for byte: the API stores and returns it unchanged,
			// so any reformatting here would show up as a permanent diff.
			if err := os.WriteFile(full, []byte(d.Logic), 0o644); err != nil {
				return fmt.Errorf("writing %s: %w", full, err)
			}
		}
	}

	importsPath := filepath.Join(opts.outDir, "imports.tf")
	f, err := os.Create(importsPath)
	if err != nil {
		return fmt.Errorf("creating %s: %w", importsPath, err)
	}
	defer func() { _ = f.Close() }()

	if err := writeImports(f, t); err != nil {
		return fmt.Errorf("writing %s: %w", importsPath, err)
	}
	return f.Close()
}

func writeImports(f io.Writer, t *tenantSurvey) error {
	w := func(format string, args ...any) error {
		_, err := fmt.Fprintf(f, format, args...)
		return err
	}

	if err := w(`# Generated by push-tf-bootstrap.
#
# The provider argument is required for the configuration-generation step and
# must be REMOVED before you apply: Terraform only accepts it on import blocks
# that generate configuration.
#
#   terraform plan -generate-config-out=generated.tf
#   # move the resources from generated.tf into your configuration
#   # delete the provider arguments below
#   terraform apply
#
# Control configurations are singletons, so their import identifier is ignored;
# "default" is the convention.

`); err != nil {
		return err
	}

	for _, c := range t.Controls {
		if err := w("# %d rule(s)\nimport {\n  to       = %s.this\n  provider = pushsecurity\n  id       = \"default\"\n}\n\n",
			c.Rules, c.Spec.ResourceName()); err != nil {
			return err
		}
	}

	for _, d := range t.Detections {
		if err := w("# %q, %d rule(s); logic extracted to %s\nimport {\n  to       = pushsecurity_custom_detection.%s\n  provider = pushsecurity\n  id       = %q\n}\n\n",
			d.Name, d.Rules, d.LogicFile, d.Label, d.EventType); err != nil {
			return err
		}
	}

	if len(t.BlockedURLs) > 0 {
		if err := w("# %d blocked URL(s)\nimport {\n  to       = pushsecurity_blocked_urls.this\n  provider = pushsecurity\n  id       = \"default\"\n}\n\n",
			len(t.BlockedURLs)); err != nil {
			return err
		}
	}

	return nil
}

// report prints what was found and what to do next. The whole report is built
// in memory and written once, so a broken pipe is reported rather than
// producing a half-written report.
func report(out io.Writer, t *tenantSurvey, opts options) error {
	var b strings.Builder

	fmt.Fprintf(&b, "Wrote %s\n", filepath.Join(opts.outDir, "imports.tf"))

	var totalRules int
	for _, c := range t.Controls {
		totalRules += c.Rules
	}
	fmt.Fprintf(&b, "\n%d control(s) with configuration, %d rule(s) in total:\n",
		len(t.Controls), totalRules)
	for _, c := range t.Controls {
		fmt.Fprintf(&b, "  %-40s %d rule(s)\n", c.Spec.ResourceName(), c.Rules)
	}
	if len(t.Controls) == 0 {
		b.WriteString("  (none)\n")
	}

	if len(t.Detections) > 0 {
		fmt.Fprintf(&b, "\n%d custom detection(s):\n", len(t.Detections))
		for _, d := range t.Detections {
			fmt.Fprintf(&b, "  %-40s %d rule(s), logic -> %s\n", d.EventType, d.Rules, d.LogicFile)
		}
	}
	if len(t.BlockedURLs) > 0 {
		fmt.Fprintf(&b, "\n%d blocked URL(s).\n", len(t.BlockedURLs))
		b.WriteString("  Note: the provider normalises these patterns, so imported ones may be\n" +
			"  spelled differently from what you see in the console; both mean the same\n" +
			"  thing.\n")
	}

	writeViolations(&b, t)

	b.WriteString(`
Next steps:

  1. terraform plan -generate-config-out=generated.tf
  2. Move the resources from generated.tf into your configuration.
  3. Delete the ` + "`provider`" + ` arguments from imports.tf.
  4. Give every rule a stable ` + "`key`" + `. Generated rules have key = null, and
     without a key the provider matches rules to the server by position, so a
     later reorder moves the server-side rule identifiers onto different
     rules.
  5. For each custom detection, replace the inline detection_logic with
     file("${path.module}/<extracted file>").
  6. terraform apply, then terraform plan again. The second plan must be empty.
`)

	_, err := io.WriteString(out, b.String())
	return err
}

// writeViolations reports what will stop the first plan, which is rules the API
// will refuse to write back and criterion values the provider rejects, and
// then the criterion values the plan will only warn about.
func writeViolations(b *strings.Builder, t *tenantSurvey) {
	errs := groupViolations(t, false)
	warnings := groupViolations(t, true)

	if len(errs) == 0 {
		b.WriteString("\nEvery rule in this tenant satisfies the API's own validation rules and the\n" +
			"provider's checks on criterion values, so nothing needs fixing before the\n" +
			"first apply.\n")
	} else {
		b.WriteString(`
!! Some existing rules will not pass validation.

   The API can return a stored rule that it would reject on write, and the
   provider applies checks of its own. Terraform will report these during
   plan and refuse to apply. Fix them as part of adopting the control.

`)
		if anyViolation(errs, func(v ruleViolation) bool { return v.Criterion != "" && v.Value != "" }) {
			b.WriteString(`   Criterion values are checked too, and the same goes for them.
   terraform plan says why each one is rejected and what to write instead.

`)
		}
		if anyViolation(errs, func(v ruleViolation) bool { return v.Field != "" }) {
			b.WriteString(`   Message text is checked too. The API stores &, < and > in a title or
   button label HTML-escaped, so text adopted from the tenant holds &amp; where
   & was typed. These characters are not supported there. Reword it.

`)
		}
		if anyViolation(errs, pathless) {
			b.WriteString(`   URL patterns with no path, such as *://*.example.com, are the commonest
   case. The API adds /* to a pattern written without a path, but returns a
   pattern already stored without one as it is, so the configuration
   Terraform generates fails plan until each of them ends in /*. Adding /* can
   change what a rule matches, so check what each one does before you apply.

`)
		}
		writeGroups(b, errs)
	}

	if len(warnings) > 0 {
		b.WriteString(`
!  Some criterion values will plan with a warning.

   Terraform accepts these, but they do not match the way they read.
   terraform plan explains each one. Review them as part of adopting the
   control.

`)
		writeGroups(b, warnings)
	}
}

// violationGroup is one resource's violations, as the report lists them.
type violationGroup struct {
	Name       string
	Violations []ruleViolation
}

// groupViolations collects either the errors or the warnings by resource, in
// resource name order.
func groupViolations(t *tenantSurvey, warnings bool) []violationGroup {
	var out []violationGroup
	add := func(name string, all []ruleViolation) {
		var vs []ruleViolation
		for _, v := range all {
			if v.Warning == warnings {
				vs = append(vs, v)
			}
		}
		if len(vs) > 0 {
			out = append(out, violationGroup{Name: name, Violations: vs})
		}
	}
	for _, c := range t.Controls {
		add(c.Spec.ResourceName(), c.Violations)
	}
	for _, d := range t.Detections {
		add("pushsecurity_custom_detection "+d.EventType, d.Violations)
	}
	add("pushsecurity_blocked_urls", t.BlockedURLViolations)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func anyViolation(groups []violationGroup, match func(ruleViolation) bool) bool {
	for _, g := range groups {
		for _, v := range g.Violations {
			if match(v) {
				return true
			}
		}
	}
	return false
}

// pathless reports whether a violation is a URL pattern with no path. The API
// adds `/*` to those on write, but returns one already stored without a path
// as it is.
func pathless(v ruleViolation) bool {
	rest, ok := strings.CutPrefix(v.Value, "*://")
	return v.Criterion == "url_patterns" && ok && !strings.ContainsAny(rest, "/?#")
}

func writeGroups(b *strings.Builder, groups []violationGroup) {
	for _, g := range groups {
		fmt.Fprintf(b, "   %s\n", g.Name)
		for _, v := range g.Violations {
			if v.RuleIndex < 0 {
				fmt.Fprintf(b, "     %s\n", strings.ReplaceAll(v.Summary, "`", ""))
				continue
			}
			fmt.Fprintf(b, "     rules[%d] %q (mode %s)", v.RuleIndex, v.RuleName, v.Mode)
			switch at := v.Criterion + v.Field; {
			case at != "" && v.Value != "":
				fmt.Fprintf(b, ", %s %q", at, v.Value)
			case at != "":
				fmt.Fprintf(b, ", %s", at)
			}
			fmt.Fprintf(b, ": %s\n", strings.ReplaceAll(v.Summary, "`", ""))
		}
		b.WriteString("\n")
	}
}

var nonIdentifier = regexp.MustCompile(`[^a-z0-9]+`)

// slugify turns a detection name into a file name.
func slugify(name string) string {
	s := nonIdentifier.ReplaceAllString(strings.ToLower(strings.TrimSpace(name)), "-")
	s = strings.Trim(s, "-")
	if s == "" {
		return "detection"
	}
	return s
}

// identifier turns a slug into a Terraform resource label, which may not
// start with a digit.
func identifier(slug string) string {
	s := strings.ReplaceAll(slug, "-", "_")
	if s == "" {
		return "detection"
	}
	if s[0] >= '0' && s[0] <= '9' {
		return "d_" + s
	}
	return s
}

// uniqueSlugs returns a slug for each detection, numbering the second and
// later of any that share one, so that no detection's file or import block
// overwrites another's. Names such as "Foo Bar" and "Foo-Bar" share a slug,
// as do all names with no ASCII letters or digits.
func uniqueSlugs(detections []detection) []string {
	used := map[string]bool{}
	out := make([]string, len(detections))
	for i, d := range detections {
		base := slugify(d.Name)
		slug := base
		for n := 2; used[slug] || used[identifier(slug)]; n++ {
			slug = fmt.Sprintf("%s-%d", base, n)
		}
		used[slug] = true
		used[identifier(slug)] = true
		out[i] = slug
	}
	return out
}
