---
page_title: "pushsecurity_custom_detection List Resource - pushsecurity"
subcategory: ""
description: |-
  Finds the tenant's custom detections, to adopt with terraform query, in order of detection event type.
---

# pushsecurity_custom_detection (List Resource)

Finds the tenant's custom detections, to adopt with `terraform query`, in order of detection event type.

List resources need Terraform 1.14 or later.

## Example usage

Put the list block in a file ending in `.tfquery.hcl`, beside your
configuration:

```terraform
list "pushsecurity_custom_detection" "adopted" {
  provider = pushsecurity

  # Terraform stops at 100 results unless told otherwise.
  limit = 1000
}
```

Then let Terraform write the resources and their import blocks:

```shell
terraform query -generate-config-out=generated.tf
```

- **Every list block needs `provider = pushsecurity`**, or the query
  fails.
- **Keep the `provider` block and `required_providers` in a `.tf` file.** A
  `.tfquery.hcl` file cannot hold a `terraform` block. A `provider` block in
  one is used by the query alone, and plan then configures the provider without
  it.
- **`generated.tf` must not exist yet.** Terraform only writes generated
  configuration to a new file.

Move the generated resources into your configuration and run `terraform apply`
to record the imports. Leave the `provider` argument on the resources and the
import blocks: the plan accepts both.

The resources are named `adopted_0`, `adopted_1` and so on, in order of
detection event type, so the names stay the same from one query to the next.
Rename each after its detection, before the first apply or with a `moved` block
after. Give every rule a stable `key` too: generated rules have `key = null`,
because keys exist only in Terraform and cannot be recovered from the API.

## Detection logic as files

Terraform writes `detection_logic` into the generated configuration as one
escaped string. To keep it in files and read it with `file()`, write each
detection's logic out of state after the import apply and the renaming. `jq -j`
writes the string exactly as stored, with no newline added:

```shell
mkdir -p detections
terraform show -json > state.json
jq -r '.values.root_module.resources[]
       | select(.type == "pushsecurity_custom_detection") | .name' state.json |
while read -r name; do
  jq -j --arg n "$name" '.values.root_module.resources[]
       | select(.type == "pushsecurity_custom_detection" and .name == $n)
       | .values.detection_logic' state.json > "detections/$name.yaml"
done
rm state.json
```

Then replace each `detection_logic` with
`file("${path.module}/detections/<name>.yaml")`. The next plan must be empty.

## Cost

The API lists detections without their logic or rules, so each result that
Terraform asks for in full, as `-generate-config-out` does, costs one more
request. `limit` bounds that.

## Warnings

When a detection holds configuration that the first plan will reject or warn
about, its result carries a warning, named after the detection, that lists each
rule and value at fault. There are two warnings:

- **`configuration the first plan will reject`**: the configuration Terraform
  generates fails plan until it is fixed.
- **`configuration that plans with a warning`**: Terraform accepts it, but the
  value does not match the way it reads.

A detection's rules are only read when Terraform asks for it in full, so these
warnings appear with `-generate-config-out`, or with `include_resource = true`
in the list block, and not otherwise.

## Schema

The list block takes no `config` block. `limit` and `include_resource` are
Terraform's own.
