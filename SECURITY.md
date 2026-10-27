# Security policy

## Reporting a vulnerability

Please do not report security vulnerabilities in public issues, discussions or
pull requests.

Report them privately through GitHub: on this repository's **Security** tab,
choose **Report a vulnerability**. Include what you found, how to reproduce it,
and the versions of the provider and Terraform affected.

We will acknowledge your report, keep you informed while we work on a fix, and
credit you in the release notes if you would like to be credited.

## Scope

This policy covers the provider in this repository. Vulnerabilities in the Push Security platform itself, including its
API and browser extension, are covered by Push Security's own disclosure
process, not this one.

## Supported versions

The provider is experimental, and every release is a beta. Security fixes are
released as a new beta. Only the latest release receives them, so upgrade to
it.

## Verifying a release

Every release's `SHA256SUMS` file is signed with Push Security's release key.
Terraform verifies provider downloads against that signature automatically.
