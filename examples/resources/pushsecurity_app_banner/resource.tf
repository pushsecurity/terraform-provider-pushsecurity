resource "pushsecurity_app_banner" "this" {
  rules = [
    {
      key     = "block-unapproved-ai"
      name    = "Block unapproved AI tools"
      enabled = true
      mode    = "BLOCK"
      title   = "This app is not approved"
      subtext = "Ask IT before using it with company data."

      # BLOCK is the only mode that takes allow_reason_submission, and it
      # requires it. Setting it true also makes button_text required.
      allow_reason_submission = true
      button_text             = "Request access"

      criteria = {
        app_categories    = { matches = ["2"] }
        approval_statuses = { matches = ["NOT_APPROVED", "UNDER_REVIEW"] }
        employee_groups   = { matches = ["Executives"], action = "EXCLUDE" }
      }
    },
    {
      key               = "inform-on-sensitive"
      name              = "Inform on highly sensitive apps"
      enabled           = true
      mode              = "INFORM"
      title             = "Handle with care"
      subtext           = "This app holds sensitive data."
      display_frequency = "ONCE_PER_BROWSER"

      criteria = {
        sensitivity_levels = { matches = ["HIGH"] }
      }
    },
  ]
}
