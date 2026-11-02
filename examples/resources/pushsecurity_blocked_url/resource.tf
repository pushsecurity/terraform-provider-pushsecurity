# A baseline of blocked URLs that Terraform keeps in place, beside patterns that
# other tools add to the same list through the API. One resource per pattern.
resource "pushsecurity_blocked_url" "baseline" {
  for_each = toset([
    # A host, optionally followed by a port and a path. * is a wildcard
    # anywhere in the host or path. Do not include a scheme: the API matches
    # every scheme, and rejects a pattern that names one.
    "known-bad.example.com",
    "*.phishing.example.net",
    "example.org/malicious/path*",
  ])

  pattern = each.value
}
