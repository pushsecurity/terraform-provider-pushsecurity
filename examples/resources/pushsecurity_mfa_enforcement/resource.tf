resource "pushsecurity_mfa_enforcement" "this" {
  rules = [
    {
      key     = "prompt-on-approved-apps"
      name    = "Prompt on approved apps without MFA"
      enabled = true
      mode    = "ACKNOWLEDGE"
      # ACKNOWLEDGE is the only mode that does anything, and it requires all
      # three of these.
      title       = "Turn on multi-factor authentication"
      subtext     = "This account has no second factor. Add one from your account settings."
      button_text = "I understand"

      criteria = {
        approval_statuses = { matches = ["APPROVED"] }
        employee_groups   = { matches = ["Contractors"], action = "EXCLUDE" }
      }
    },
    {
      key     = "leave-low-sensitivity-alone"
      name    = "Say nothing about low sensitivity apps"
      enabled = true
      mode    = "OFF"

      criteria = {
        sensitivity_levels = { matches = ["LOW"] }
      }
    },
  ]
}
