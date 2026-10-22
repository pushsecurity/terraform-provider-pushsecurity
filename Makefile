# A devcontainer is the supported build environment; see .devcontainer/.

BINARY  := terraform-provider-pushsecurity
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.DEFAULT_GOAL := build

# The provider binary and push-tf-bootstrap, in the repository root.
.PHONY: build
build: bootstrap
	go build -ldflags "-X main.version=$(VERSION)" -o $(BINARY) .

# The adoption tool. `make install` installs it alongside the provider.
.PHONY: bootstrap
bootstrap:
	go build -o push-tf-bootstrap ./cmd/push-tf-bootstrap

# `dev_overrides` in ~/.terraformrc points at GOBIN, so installing is the whole
# dev loop: no init, no version bump, no registry.
.PHONY: install
install:
	go install -ldflags "-X main.version=$(VERSION)" ./...

.PHONY: test
test:
	gotestsum -- -race ./...

# Acceptance tests create and destroy real configuration in whatever tenant
# PUSH_API_KEY points at. Never point it at a tenant that holds anything real.
.PHONY: testacc
testacc:
	TF_ACC=1 gotestsum -- -race -parallel 4 -timeout 30m -run '^TestAcc' ./internal/provider

.PHONY: lint
lint:
	golangci-lint run
	terraform fmt -check -recursive ./examples

.PHONY: fmt
fmt:
	gofmt -w .
	terraform fmt -recursive ./examples

# docs/ is generated from the provider schema plus examples/ and templates/.
# CI checks it is up to date, so run this after any schema change.
.PHONY: docs
docs:
	tfplugindocs generate --provider-name pushsecurity

.PHONY: docs-check
# status, not diff: a new page is untracked, and diff ignores it.
docs-check: docs
	@test -z "$$(git status --porcelain -- docs/)" \
		|| (git status --short -- docs/; echo "docs/ is stale: run 'make docs' and commit the result"; exit 1)

.PHONY: clean
clean:
	rm -rf dist/ $(BINARY) push-tf-bootstrap
