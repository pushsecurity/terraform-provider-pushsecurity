# Terraform Provider for Push Security

Manages [Push Security](https://pushsecurity.com) control configuration as code,
so that changes to your controls go through pull request and review, and their
history and rollback come from git.

> [!IMPORTANT]
> **This provider is experimental.** Push Security publishes it to find out how
> useful managing Push configuration as code is to customers. It is not
> generally available and not yet officially supported. Resources, attributes
> and behaviour may change between releases without a deprecation period, and
> every release is a beta (`0.x.y-beta.N`) until that changes.
>
> If you would like to use it, contact Push Security support at
> [support@pushsecurity.com](mailto:support@pushsecurity.com) first.

- **Documentation:** [`docs/`](docs/) — generated from the provider schema, and
  what the Terraform Registry publishes.
- **Start here:** [Adopting an existing tenant](docs/guides/adopting-an-existing-tenant.md),
  then [A review-then-apply pipeline](docs/guides/gitops-workflow.md).

## What it manages

| | |
| --- | --- |
| 14 control configurations | app banner (both kinds), MFA enforcement, password logging prevention, strong password enforcement, account condition enforcement, file download/upload blocking, clipboard blocking, browser extension blocking, malicious extension detection, cloned login page detection, phishing tool detection, malicious copy/paste detection |
| 2 telemetry configurations | file download, file upload |
| Custom detections | detection logic as YAML files, plus the rules that act on them |
| Blocked URLs | the tenant's blocked URL list |
| Settings | the domains Push monitors as your organisation's, and whether it monitors every domain |
| Employees | an employee's record and licence, and merging their other addresses into it, by name or by rule |
| Data sources | employees, apps, app categories, custom detections |

`stolenCredentials` is deliberately not implemented: it takes plaintext
passwords, which do not belong in a repository or in Terraform state.

## Installation

Requires Terraform 1.8 or later. The provider is published on the Terraform
Registry as `pushsecurity/pushsecurity`. Every release is a beta, and Terraform
only installs a beta when its version is pinned exactly, so name the release
you want, and move to a newer one deliberately:

```hcl
terraform {
  required_version = ">= 1.8"

  required_providers {
    pushsecurity = {
      source  = "pushsecurity/pushsecurity"
      version = "0.1.0-beta.1"
    }
  }
}

provider "pushsecurity" {}
```

The provider reads its configuration from the environment:

| Variable | |
| --- | --- |
| `PUSH_API_KEY` | An API key, created under Settings in the Push admin console. A read-only key is enough for `plan` and for `push-tf-bootstrap`; `apply` needs full access. |
| `PUSH_BASE_URL` | Optional. The API's base URL, `https://api.pushsecurity.com` unless you have been given another. |

Both can also be set as `api_key` and `base_url` in the provider block, but
keep the key out of configuration: a key there ends up in plan files and,
usually, in version control.

## Two things to understand before you start

**Each control resource owns its control in full.** The API replaces the whole
configuration document on every write, so an apply deletes any rule not in your
configuration — including rules created in the console. A control is either
fully Terraform-managed or fully console-managed. Import before your first
apply.

**Give every rule a `key`.** Rule names are not unique — the console generates
them from a template, so duplicates are normal — so without a key the provider
matches your rules to the server's by position. Reordering positionally matched
rules keeps the server-side identifiers but moves them onto different rules.
Nothing in Push refers to a rule identifier, so nothing breaks either way — set
a key if your own tooling reads the identifiers the API returns.

## Adoption

`push-tf-bootstrap` surveys an existing tenant and writes the Terraform import
blocks, extracts custom detection logic to files, and reports configuration the
API will refuse to write back or the first plan will otherwise reject. It only
reads, so a read-only key is enough.

```shell
export PUSH_API_KEY=...
push-tf-bootstrap -out .
terraform plan -generate-config-out=generated.tf
```

See the [adoption guide](docs/guides/adopting-an-existing-tenant.md) for the
remaining steps; there is one Terraform quirk in the middle worth reading about.

To get `push-tf-bootstrap`, download it from the GitHub
[releases](https://github.com/pushsecurity/terraform-provider-pushsecurity/releases):
each provider release carries a `push-tf-bootstrap` archive per platform, with
signed checksums of its own. With a Go toolchain, you can instead install it
from source:

```shell
go install github.com/pushsecurity/terraform-provider-pushsecurity/cmd/push-tf-bootstrap@latest
```

## Development

A devcontainer is the supported build environment. Open this folder in VS Code
and **Reopen in Container**; the definition is in
[`.devcontainer/`](.devcontainer/) and ships Go, Terraform, `golangci-lint`,
`tfplugindocs` and `gotestsum` at the versions CI uses.

```shell
make build          # provider and push-tf-bootstrap
make install        # into GOBIN, which ~/.terraformrc dev_overrides points at
make test           # unit tests; nothing touches a real tenant
make lint
make docs           # regenerate docs/ from the schema, examples/ and templates/
```

### Acceptance tests

Gated behind `TF_ACC`, so `make test` stays offline.

```shell
cp .env.example .env    # then fill in PUSH_API_KEY (full access)
direnv allow            # or export it by hand
make testacc
```

CI runs acceptance tests against both the oldest supported Terraform and the
current release. To reproduce the older leg, point the test framework at the
`terraform1.8` the devcontainer installs alongside the current one:

```shell
TF_ACC_TERRAFORM_PATH=/usr/local/bin/terraform1.8 make testacc
```

> Acceptance tests **replace whole control configurations** and destroy what they
> create. Point them at a dedicated test tenant, never at one holding anything
> real. The smoke test alone writes to every control.

The smoke test is the one to keep an eye on: it applies a minimal rule to every
control and requires the following plan to be empty. That is what catches the
API drifting from its own specification.

## Support

The provider is an experiment and is not yet covered by Push Security support.
Before you use it, contact [support@pushsecurity.com](mailto:support@pushsecurity.com):
we would like to hear what you plan to manage with it, and can help you get
started. Report bugs as GitHub issues.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md). To report a vulnerability, follow
[SECURITY.md](SECURITY.md) rather than opening an issue.

## License

[MIT License](LICENSE).
