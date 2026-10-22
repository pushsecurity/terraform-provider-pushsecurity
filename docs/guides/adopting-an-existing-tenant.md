---
page_title: "Adopting an existing tenant"
subcategory: ""
description: |-
  How to bring a tenant that already has configuration under Terraform management without changing anything.
---

# Adopting an existing tenant

~> The Push Security provider is experimental: not yet generally available or
officially supported, and it may change between releases. Contact
support@pushsecurity.com before you rely on it. See the
[provider overview](https://registry.terraform.io/providers/pushsecurity/pushsecurity/latest/docs).

Your tenant already has control configuration. The goal of adoption is a first
apply that changes **nothing** — you want Terraform to agree with what is
already live before you start editing it.

This matters more here than with most providers, because each control resource
owns its control in full: the API replaces the whole document on every write.
An apply against an incomplete configuration does not merge, it replaces. So
import first.

Adopt one control at a time. A control is either fully Terraform-managed or
fully console-managed; there is no middle ground.

## 1. Survey the tenant

`push-tf-bootstrap` reads the tenant and writes the import blocks for you. It
never writes to the API, so a read-only key is enough:

```shell
export PUSH_API_KEY=...
push-tf-bootstrap -out .
```

It produces:

- `imports.tf` — an import block for every control that has rules, every custom
  detection, and the blocked URL list.
- `detections/*.yaml` — each custom detection's logic, extracted byte for byte.

It also prints anything that will fail validation. See
[Configuration the API will not accept back](#configuration-the-api-will-not-accept-back).

## 2. Let Terraform generate the configuration

```shell
terraform plan -generate-config-out=generated.tf
```

The import blocks include a `provider` argument, which this step needs: without
it Terraform looks for `hashicorp/pushsecurity` and fails.

## 3. Move the generated resources in, and drop the provider arguments

Move the resources out of `generated.tf` into your own files, then **delete the
`provider` arguments from the import blocks**. Terraform only accepts that
argument on import blocks that generate configuration; leaving it in place fails
the next plan with `Invalid import provider argument`.

```shell
terraform apply     # imports; changes nothing
terraform plan      # must be empty
```

An empty plan here is the whole point. If it is not empty, the provider and the
API disagree about something — that is a bug worth reporting, not something to
apply past.

## 4. Add rule keys

Generated rules have `key = null`. Give each one a stable, meaningful key:

```terraform
rules = [
  {
    key     = "block-executables"   # add this
    name    = "Block executables from unapproved sources"
    ...
```

This is the one concept with no counterpart in the console. Rule names are not
unique — the console generates them from a template, so duplicates are normal —
so without a key the provider matches your rules to the server's by
**position**. Reordering positionally matched rules keeps the server-side
identifiers but moves them onto different rules.

The identifiers are returned by the API, so a key is what keeps them stable
for any tooling of your own that reads them — and it makes the mapping exact
rather than inferred, which is worth having when a mistake is invisible in the
plan.

Keys live only in state, so the apply after adding them changes nothing the API
stores. It is still an apply: the provider rewrites the whole document, and
imported state has no keys for the new ones to match against, so it maps them
to the existing rules by **position**. The server-side rule identifiers are
preserved.

Position is the right answer only while the rules are still in the order they
were imported in, which the provider cannot check for you. Prefer adding the
keys as a change of their own, and reorder in the next one, once state carries
the keys and matching is exact. Nothing breaks if you do both at once — the
resulting configuration is correct either way — but the identifiers will have
moved between rules.

## 5. Point detection logic at the extracted files

Replace the generated inline `detection_logic` string with a file reference:

```terraform
detection_logic = file("${path.module}/detections/torrent-website-visit.yaml")
```

The API stores and returns detection logic byte for byte, so this is a no-op —
and from here on a change to your detection logic reads as a diff in a YAML
file rather than as an edited escape sequence.

## Configuration the API will not accept back

The API can return configuration that it rejects on write. For example, an
app banner rule with mode `INFORM` and a `title` but no `subtext`: `GET`
returns it, and `PUT` rejects it with

```
rules[0]._schema: title and subtext are required for all modes except DO_NOT_SHOW
```

So an import can succeed, produce an empty plan, and still fail on the first
apply that touches that control. This provider checks the API's cross-field
rules during plan, so you get a diagnostic naming the rule and the field instead
of a 400 after your pull request has merged — and `push-tf-bootstrap` reports
them up front, before you have written any configuration.

Fix the data as part of adopting the control.

The same goes for criterion values, and the commonest case is a URL pattern with
no path, such as `*://*.anydesk.com`. The API adds `/*` to a pattern written
without a path, but returns a pattern already stored without one as it is. The
provider rejects these during plan, because an apply would send them back and
read a different value. Add `/*` to each, and check what the rule does before
you apply: the fix can change what it matches.

The provider also rejects values that are not supported, such as a file name
pattern that starts with `(?i)` or a clipboard URL pattern with a query string,
and warns about a few that work but not the way they read.
`push-tf-bootstrap` reports these too, listing the warnings separately from what
will stop the plan.

## Employees named by a rule

Rules restrict to people by `employee_ids`, which on the wire matches on opaque
employee identifiers. Configuration is written with **email addresses**, and the
provider resolves them in both directions: addresses become identifiers on the
way to the API, and identifiers become addresses on the way into state. So the
configuration Terraform generates for you names people, not UUIDs, and there is
nothing to translate by hand.

An address the tenant does not hold fails during plan, naming the rule and the
address — the same treatment the cross-field rules get, and for the same reason.

The one case to watch on adoption is the mirror image: a rule that names an
employee the tenant no longer holds, which is what an offboarded person still
sitting in an old rule looks like. The identifier cannot be turned back into an
address, so the refresh raises a warning rather than failing — failing would
leave no way to see or repair the rule. Directly after an import there is no
configuration to recover the address from, so that identifier is left out of
state and **the next apply would drop it from the rule**. The warning says so.
Review those rules before the first apply.

A stale identifier is worth looking for while adopting: an employee record that
was recreated keeps the address but changes the identifier, so a rule written
against the old one stops matching anybody. Adoption surfaces these,
because the address is what the configuration then holds.

## What not to manage

`stolenCredentials` is deliberately not implemented. It takes plaintext
passwords, which do not belong in a repository or in Terraform state.
