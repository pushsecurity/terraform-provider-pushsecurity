resource "pushsecurity_password_logging_prevention" "this" {
  rules = [
    {
      key     = "block-on-unapproved"
      name    = "Block company passwords on unapproved apps"
      enabled = true
      mode    = "BLOCK"
      # title and subtext are required for BLOCK and rejected for every other
      # mode, so the MONITOR rule below must not set them.
      title   = "Do not use your company password here"
      subtext = "This app is not approved for company credentials."

      criteria = {
        approval_statuses = { matches = ["NOT_APPROVED", "UNDER_REVIEW"] }
      }
    },
    {
      key     = "monitor-everything-else"
      name    = "Monitor everywhere else"
      enabled = true
      mode    = "MONITOR"
    },
  ]
}
