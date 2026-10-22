resource "pushsecurity_phishing_tool_detection" "this" {
  globals = {
    ignored_hosts = ["*.internal.example.com", "10.0.1.1"]
  }

  rules = [
    {
      key     = "block-everyone"
      name    = "Block known phishing toolkits"
      enabled = true
      mode    = "BLOCK"
      # title and subtext are required for BLOCK and WARN, and rejected for
      # MONITOR and OFF.
      title   = "This page is running a phishing toolkit"
      subtext = "Do not enter your password. Report it to Security."
    },
    {
      key                = "warn-security-team"
      name               = "Warn, rather than block, the security team"
      enabled            = true
      mode               = "WARN"
      title              = "This page is running a phishing toolkit"
      subtext            = "Continue only if you are investigating it."
      ignore_button_text = "Continue anyway" # required for WARN, rejected elsewhere

      criteria = {
        employee_groups = { matches = ["Security"] }
      }
    },
  ]
}
