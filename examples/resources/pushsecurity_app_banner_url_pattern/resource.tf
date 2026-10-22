# The URL pattern banner selects pages by address rather than by app, which is
# what to reach for when the pages are not an app Push has in its inventory.
resource "pushsecurity_app_banner_url_pattern" "this" {
  rules = [
    {
      key     = "block-legacy-admin"
      name    = "Block the legacy admin console"
      enabled = true
      mode    = "BLOCK"
      title   = "This console is being retired"
      subtext = "Use the new admin app. If you need the old one, say why."

      # BLOCK is the only mode that takes allow_reason_submission, and it
      # requires it. Setting it true also makes button_text required.
      allow_reason_submission = true
      button_text             = "Request access"

      criteria = {
        url_patterns = { matches = ["*://legacy-admin.example.com/*"] }
      }
    },
    {
      key               = "inform-on-partner-portal"
      name              = "Inform on the partner portal"
      enabled           = true
      mode              = "INFORM"
      title             = "Partner data lives here"
      subtext           = "Treat anything you export as confidential."
      display_frequency = "ONCE_PER_BROWSER"
      # button_text is rejected for INFORM.

      criteria = {
        url_patterns    = { matches = ["*://partners.example.com/*"] }
        employee_groups = { matches = ["Contractors"], action = "EXCLUDE" }
      }
    },
  ]
}
