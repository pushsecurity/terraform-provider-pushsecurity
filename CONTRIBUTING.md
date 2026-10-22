# Contributing

Thanks for helping improve the Push Security Terraform provider. Bug reports,
fixes and documentation improvements are all welcome.

The provider is an experiment: it is not yet generally available or officially
supported, and it may change between releases without a deprecation period.
If you are a Push Security customer and want to use it, contact
support@pushsecurity.com first.

## Reporting a bug

Open an issue with the provider and Terraform versions, the configuration that
fails (with anything sensitive removed), and the output, ideally with
`TF_LOG=debug`. Read the log before you attach it and remove anything
sensitive: it can contain your tenant's configuration.

Security issues are different: see [SECURITY.md](SECURITY.md), and do not open
a public issue.

## Making a change

Open pull requests against `development`, the default branch. Releases are cut
from `main`, which only ever receives `development`.

For anything larger than a small fix, open an issue first, so we can agree on
the approach before you write the code.

### Environment

The [devcontainer](.devcontainer/) is the supported build environment: open the
repository in VS Code and choose **Reopen in Container**. It installs Go,
Terraform, `golangci-lint`, `tfplugindocs` and `gotestsum` at the versions CI
uses.

### Before you push

CI runs these on every pull request, and they need no Push tenant:

```shell
make build
make test      # unit tests, offline
make lint      # golangci-lint, and terraform fmt on examples/
make docs      # regenerate docs/; commit the result
```

`docs/` is generated from the provider schema, `examples/` and `templates/`.
Edit those, never `docs/` directly, and commit what `make docs` produces.

### Acceptance tests

Acceptance tests (`make testacc`) **replace whole control configurations** in
a real tenant, so they only ever run against a dedicated test tenant. CI does
not run them on pull requests from forks, which cannot be given its
credentials. A maintainer runs them before your change is released. You do not
need to run them yourself, but if you have a tenant that holds nothing real,
see the README.

Add a test with your change. Most behaviour can be tested offline: the
resource tests in `internal/provider` run against a stub tenant.

### Commit messages

Write the subject as what the change does for someone using the provider, for
example `pushsecurity_blocked_urls: keep the list unchanged when only the spelling
differs`. A scope prefix naming the resource or area is welcome where it helps.
Subjects become the release notes. Use the body to say why.

## License

By contributing, you agree that your contributions are licensed under the
[MIT License](LICENSE).
