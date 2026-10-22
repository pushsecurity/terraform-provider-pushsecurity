resource "pushsecurity_blocked_urls" "this" {
  # A host, optionally followed by a port and a path. * is a wildcard anywhere
  # in the host or path. Do not include a scheme: the API matches every scheme,
  # and rejects a pattern that names one.
  patterns = [
    "known-bad.example.com",
    "*.phishing.example.net",
    "example.org/malicious/path*",
  ]
}

# The form the API stores and the console displays, which is not accepted as
# input: ["*://known-bad.example.com/*", ...]
output "blocked_urls_as_stored" {
  value = pushsecurity_blocked_urls.this.canonical_patterns
}
