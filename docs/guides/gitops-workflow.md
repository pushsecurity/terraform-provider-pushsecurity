---
page_title: "A review-then-apply pipeline"
subcategory: ""
description: |-
  Running the provider so that control changes go through pull request and review.
---

# A review-then-apply pipeline

~> The Push Security provider is experimental: not yet generally available or
officially supported, and it may change between releases. Contact
support@pushsecurity.com before you rely on it. See the
[provider overview](https://registry.terraform.io/providers/pushsecurity/pushsecurity/latest/docs).

The reason to manage Push configuration with Terraform is that changes become
reviewable: a proposed change to a blocking rule shows up as a diff, someone
approves it, and the history is in git. This guide covers the parts of that
which are specific to this provider.

## Two keys

The API distinguishes read-only from full-access keys, and that maps onto the
pipeline directly:

| Stage | Key | Why |
| --- | --- | --- |
| Pull request — `terraform plan` | **read-only** | A plan only reads. A compromised pipeline at this stage cannot change your controls. |
| Merge to main — `terraform apply` | **full access** | Held in a protected environment, used only after review. |

Create both under Settings in the Push admin console. Pass them as
`PUSH_API_KEY`; never put a key in configuration, where it would end up in
plan files and in git.

## State

Each pipeline run starts on a fresh runner, so state has to live in a remote
backend. Without one, every run starts from empty state: the plan shows every
resource as new, and the apply writes each control's whole configuration over
whatever is live without showing you what it replaces, and creates each custom
detection again.

```terraform
# State has to persist between pipeline runs, so it lives in a remote backend.
# Any backend that stores state privately and locks it will do; S3 is one.
terraform {
  backend "s3" {
    bucket       = "example-push-terraform-state" # replace with your bucket
    key          = "push/terraform.tfstate"
    region       = "us-east-1"
    encrypt      = true
    use_lockfile = true
  }
}
```

The plan and apply jobs both need the backend. The pull request plan only
reads state, but it takes the state lock unless you pass `-lock=false`, so give
it access to the lock too. Only the apply writes state.

State holds your complete control configuration and the employee email
addresses your criteria name, so keep it private and encrypted at rest.

## A reference workflow

```yaml
# A review-then-apply pipeline for Push control configuration.
#
# Plans run on pull requests with a read-only key, so a compromised pipeline at
# review time cannot change anything. Applies run only after merge, from a
# protected environment holding a full-access key.
#
# State must outlive the job: configure a remote backend in your root module
# first (see backend.tf alongside this file). Without one, every run starts from
# empty state.

name: push-config

on:
  pull_request:
  push:
    branches: [main]

# Jobs widen this only where they need to.
permissions:
  contents: read

jobs:
  plan:
    if: github.event_name == 'pull_request'
    runs-on: ubuntu-latest
    environment: push-plan # holds the READ-ONLY key
    steps:
      - uses: actions/checkout@v5
        with:
          persist-credentials: false
      - uses: hashicorp/setup-terraform@v3

      # Pass your backend's credentials to every step that runs terraform.
      - run: terraform init
      - run: terraform fmt -check -recursive

      # Catches the API's cross-field rules — "title is required for mode
      # BLOCK" and the like — on the pull request rather than after merge.
      - run: terraform validate

      - name: plan
        env:
          PUSH_API_KEY: ${{ secrets.PUSH_API_KEY_READ_ONLY }}
        run: terraform plan -no-color -out=tfplan

      # Rendering a saved plan needs no API key.
      - name: render the plan
        run: |
          {
            echo '## Terraform plan'
            echo '```'
            terraform show -no-color tfplan
            echo '```'
          } > plan.md

      - uses: actions/upload-artifact@v4
        with:
          name: plan
          path: plan.md

  # Review the diff in the pull request. Rule order is part of the
  # configuration: a reordered rules list changes which rule matches first.
  #
  # A job of its own, so the token that can write to the pull request never
  # shares a runner with the API key or with terraform evaluating the pull
  # request's configuration.
  comment:
    needs: plan
    runs-on: ubuntu-latest
    permissions:
      pull-requests: write
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: plan
      - name: comment the plan
        env:
          GH_TOKEN: ${{ github.token }}
        run: gh pr comment "${{ github.event.number }}" --repo "${{ github.repository }}" --body-file plan.md

  apply:
    if: github.ref == 'refs/heads/main' && github.event_name == 'push'
    runs-on: ubuntu-latest
    # Require a reviewer on this environment, and hold the FULL-ACCESS key here.
    environment: push-apply
    # One apply at a time: the API serialises configuration writes per tenant,
    # and a second run would fight the first.
    concurrency: push-apply
    steps:
      - uses: actions/checkout@v5
        with:
          persist-credentials: false
      - uses: hashicorp/setup-terraform@v3

      # Pass your backend's credentials to every step that runs terraform.
      - run: terraform init

      # Replan against the tenant as it is now, not as it was when the pull
      # request was reviewed. The diff is in this job's log.
      - name: plan
        env:
          PUSH_API_KEY: ${{ secrets.PUSH_API_KEY_FULL_ACCESS }}
        run: terraform plan -no-color -out=tfplan

      # Applying the saved plan writes exactly what the plan printed, and needs
      # no -auto-approve. Planning in the same job keeps the window between
      # reading and writing to seconds: there is no optimistic concurrency on
      # the API, so a console edit inside that window is overwritten.
      - name: apply
        env:
          PUSH_API_KEY: ${{ secrets.PUSH_API_KEY_FULL_ACCESS }}
        run: terraform apply -no-color tfplan
```

The pull request plan is for review. The apply job does not reuse it: by the
time the change merges, someone may have edited the tenant or merged another
change, so it plans again and applies exactly that saved plan, seconds later.
Its log shows the diff it applied.

## What a plan cannot tell you

Two limitations to plan around.

**A console edit between plan and apply is overwritten.** There is no
version or `If-Match` on the configuration endpoints, so the provider cannot
detect that someone changed a control after your plan was generated. Your apply
replaces the whole document and their change disappears. Keep the window
between plan and apply short by applying a plan file produced moments earlier,
as the reference workflow does.

The API *does* detect two simultaneous writes — it answers the loser with `409
CONCURRENT_MODIFICATION`, which the provider retries — but that is a different
problem from a sequential edit you never saw.

**Some rules are only checked at apply.** The API has no dry-run endpoint. The
provider mirrors its cross-field rules during plan, so most mistakes fail on the
pull request, but anything the provider does not know about surfaces as a
rejected apply after merge. When that happens the diagnostic names the rule and
the field.

## Ordering and parallelism

Rules within a control are evaluated in the order you write them and the first
match wins, so the order of the `rules` list is part of your configuration —
review it as such.

Across controls, Terraform applies resources in parallel and the API serialises
configuration writes per tenant. The provider retries the resulting conflicts
with jittered backoff, so no special `-parallelism` setting is needed.

## Blocked URLs are not atomic

`pushsecurity_blocked_urls` is the one resource whose API has no bulk replace, so
changing it deletes the whole list and re-adds it entry by entry. Blocking is
degraded while that runs — roughly a second per entry. Schedule changes to large
lists accordingly.
