terraform {
  required_version = ">= 1.8"

  required_providers {
    pushsecurity = {
      source = "pushsecurity/pushsecurity"
      # Every release is a beta while the provider is experimental, and
      # Terraform only installs a beta when it is pinned exactly.
      version = "0.1.0-beta.1"
    }
  }
}

# The API key is read from the PUSH_API_KEY environment variable. Prefer that
# over setting api_key here: a key in configuration is a key in plan files and,
# usually, in version control.
provider "pushsecurity" {}
