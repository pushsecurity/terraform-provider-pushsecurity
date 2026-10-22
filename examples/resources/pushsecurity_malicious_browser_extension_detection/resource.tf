resource "pushsecurity_malicious_browser_extension_detection" "this" {
  globals = {
    excluded_extensions = [
      {
        extension_id = "abcdefghijklmnopabcdefghijklmnop"
        notes        = "Approved by IT for the Finance team."
      },
    ]
  }

  rules = [
    {
      key     = "block-high-severity"
      name    = "Block high severity extensions"
      enabled = true
      mode    = "BLOCK"
      title   = "Extension blocked"
      subtext = "Push assesses this extension as malicious."

      criteria = {
        browser_extension_severities = { matches = ["HIGH"] }
        profile_scope                = "COMPANY_DOMAIN"
      }
    },
    {
      key     = "monitor-the-rest"
      name    = "Monitor everything else"
      enabled = true
      mode    = "MONITOR"
      # title and subtext must be omitted for MONITOR and OFF.
    },
  ]
}
