resource "pushsecurity_strong_password_enforcement" "this" {
  rules = [
    {
      key     = "prompt-on-weak-and-reused"
      name    = "Prompt on weak, leaked and reused passwords"
      enabled = true
      mode    = "ACKNOWLEDGE"
      # ACKNOWLEDGE requires all four of these; OFF, the only other mode,
      # takes none of them.
      title               = "Change this password"
      subtext             = "It is weak, reused, or has appeared in a breach."
      button_text         = "I understand"
      applicable_findings = ["WEAK_PASSWORD", "LEAKED_PASSWORD", "REUSED_PASSWORD"]

      criteria = {
        sensitivity_levels = { matches = ["HIGH", "MEDIUM"] }
      }
    },
    {
      key     = "say-nothing-about-unreviewed"
      name    = "Say nothing about unreviewed apps"
      enabled = true
      mode    = "OFF"

      criteria = {
        approval_statuses = { matches = ["NOT_REVIEWED"] }
      }
    },
  ]
}
