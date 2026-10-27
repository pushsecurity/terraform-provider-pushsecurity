#!/usr/bin/env bash
# Runs once, after the dev container is created (and again on every rebuild).
set -euo pipefail

REPO="$(pwd)"

# Pinned so a rebuild six months from now produces the same toolchain.
# golangci-lint and tfplugindocs must both track the versions in
# .github/workflows/ci.yml, or the editor and CI will disagree about what is a
# lint failure and about what `make docs` should produce.
GOLANGCI_LINT_VERSION="v2.13.2"
TFPLUGINDOCS_VERSION="v0.25.0"
GOTESTSUM_VERSION="v1.13.0"

# Oldest Terraform in the CI acceptance matrix, installed alongside the current
# release so a version-specific failure can be reproduced here.
OLD_TERRAFORM_VERSION="1.8.5"

# Registry address the provider publishes under. Terraform matches dev_overrides
# against the `source` string in required_providers, so this has to be
# byte-identical to what a consuming configuration declares — a mismatch is
# silent, and Terraform just goes to the registry instead.
PROVIDER_ADDR="pushsecurity/pushsecurity"

# Read the layout back out of the toolchain rather than assuming it: this image
# puts GOPATH at /go (not $HOME/go) but GOCACHE under $HOME.
GOMODCACHE="$(go env GOMODCACHE)"
GOCACHE="$(go env GOCACHE)"
GOBIN_DIR="$(go env GOBIN)"
[ -n "$GOBIN_DIR" ] || GOBIN_DIR="$(go env GOPATH)/bin"

echo "==> Cache volumes"
# A named volume created over a directory that did not exist in the image mounts
# root-owned, and so does any parent Docker had to create for it. Only recurse
# when ownership is actually wrong — the module cache is tens of thousands of
# files.
for d in "$GOMODCACHE" "$GOCACHE"; do
  sudo mkdir -p "$d"
  [ "$(stat -c '%U' "$d")" = "vscode" ] || sudo chown -R vscode "$d"
  sudo chown vscode "$(dirname "$d")"
done
sudo mkdir -p "$GOBIN_DIR"
sudo chown vscode "$GOBIN_DIR"

echo "==> Extra CLI tools"
sudo apt-get update -qq
sudo apt-get install -y -qq direnv jq unzip >/dev/null

echo "==> Go tooling"
# tfplugindocs generates docs/ from the schema (`make docs`); golangci-lint is
# what CI runs; gotestsum is what the Makefile's test targets invoke, so the
# repo does not build without it.
go install "github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs@${TFPLUGINDOCS_VERSION}"
go install "github.com/golangci/golangci-lint/v2/cmd/golangci-lint@${GOLANGCI_LINT_VERSION}"
go install "gotest.tools/gotestsum@${GOTESTSUM_VERSION}"

echo "==> Terraform ${OLD_TERRAFORM_VERSION} (oldest supported)"
# Best effort: this is a convenience for reproducing a matrix failure, not
# something the build loop needs, so a download failure must not fail create.
if [ -x /usr/local/bin/terraform1.8 ]; then
  echo "    already installed"
else
  arch="$(dpkg --print-architecture)"   # amd64 | arm64 — matches HashiCorp's naming
  url="https://releases.hashicorp.com/terraform/${OLD_TERRAFORM_VERSION}/terraform_${OLD_TERRAFORM_VERSION}_linux_${arch}.zip"
  tmp="$(mktemp -d)"
  if curl -fsSL "$url" -o "$tmp/tf.zip" && unzip -q "$tmp/tf.zip" -d "$tmp"; then
    # Not named `terraform`, so it never shadows the current release on PATH.
    sudo install -m 0755 "$tmp/terraform" /usr/local/bin/terraform1.8
  else
    echo "    WARNING: could not fetch $url — skipping (only affects reproducing the 1.8 matrix leg)"
  fi
  rm -rf "$tmp"
fi

echo "==> Terraform CLI config"
mkdir -p "$HOME/.terraform.d/plugin-cache"
# dev_overrides makes a configuration use the binary in GOBIN directly:
# `make install`, then `terraform plan` — no init, no registry, no version bump.
# `terraform init` deliberately errors while this is active; run
# `TF_CLI_CONFIG_FILE=/dev/null terraform init` to bypass it for real providers
# (an *empty* value is not enough — Terraform falls back to ~/.terraformrc).
cat >"$HOME/.terraformrc" <<EOF
plugin_cache_dir = "$HOME/.terraform.d/plugin-cache"

provider_installation {
  dev_overrides {
    "$PROVIDER_ADDR" = "$GOBIN_DIR"
  }

  # Everything other than the provider under development resolves normally.
  direct {}
}
EOF

echo "==> Shell environment"
if ! grep -q '# --- terraform-provider-pushsecurity ---' "$HOME/.bashrc" 2>/dev/null; then
  cat >>"$HOME/.bashrc" <<'EOF'

# --- terraform-provider-pushsecurity ---
# GOBIN (/go/bin) is already on PATH in this image.
# direnv loads .env (via the repo's one-line .envrc) on cd, so PUSH_API_KEY
# never has to be exported by hand or committed.
eval "$(direnv hook bash)"
# --- end terraform-provider-pushsecurity ---
EOF
fi

echo "==> Dependencies"
go mod download

cat <<EOF

Dev container ready.

  go version        $(go version | awk '{print $3}')  (GOBIN $GOBIN_DIR)
  terraform         $(terraform version -json 2>/dev/null | jq -r .terraform_version 2>/dev/null || echo unknown)
  terraform1.8      $(/usr/local/bin/terraform1.8 version -json 2>/dev/null | jq -r .terraform_version 2>/dev/null || echo "not installed")
  golangci-lint     ${GOLANGCI_LINT_VERSION}
  tfplugindocs      ${TFPLUGINDOCS_VERSION}
  gotestsum         ${GOTESTSUM_VERSION}

  make build / test / lint / docs        # all offline
  make testacc                           # writes to a real tenant

Acceptance tests need a tenant key. Put it in .env
(gitignored) and let direnv load it:

  cp .env.example .env    # then fill in PUSH_API_KEY
  direnv allow

To reproduce the oldest-supported leg of the CI matrix:

  TF_ACC_TERRAFORM_PATH=/usr/local/bin/terraform1.8 make testacc

There is no consumer project in this container. To drive the provider by hand,
build it and plan from a scratch directory outside the repo — dev_overrides
resolves $PROVIDER_ADDR to \$GOBIN, so there is no init step:

  make install
  mkdir -p ~/scratch && cd ~/scratch
  cp $REPO/examples/provider/provider.tf .   # then add a resource block
  terraform plan

EOF
