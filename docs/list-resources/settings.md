---
page_title: "pushsecurity_settings List Resource - pushsecurity"
subcategory: ""
description: |-
  Finds the tenant's settings, to adopt with terraform query. Every tenant has them, so this always returns one result.
---

# pushsecurity_settings (List Resource)

Finds the tenant's settings, to adopt with `terraform query`. Every tenant has them, so this always returns one result.

List resources need Terraform 1.14 or later.

## Example usage

Put the list block in a file ending in `.tfquery.hcl`, beside your
configuration:

```terraform
list "pushsecurity_settings" "adopted" {
  provider = pushsecurity
}
```

Then let Terraform write the resource and its import block:

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

Move the generated resource into your configuration and run `terraform apply`
to record the import. Leave the `provider` argument on the resource and the
import block: the plan accepts both. The resource is named `adopted_0`. Rename
it before the first apply, or with a `moved` block after.

The generated resource sets both `monitored_domains` and `monitor_all_domains`.
Each is managed only while it is configured, so remove one to leave it to the
console.

## Schema

The list block takes no `config` block.
