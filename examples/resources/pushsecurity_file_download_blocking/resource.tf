resource "pushsecurity_file_download_blocking" "this" {
  rules = [
    {
      # `key` is provider-side only and never sent to the API. Set one on every
      # rule: it is how the provider tracks which rule is which when you
      # reorder them. Names cannot be used instead — they are not unique.
      key     = "block-executables"
      name    = "Block executables from unapproved sources"
      enabled = true
      mode    = "BLOCK"
      title   = "Download blocked"
      subtext = "Executables from unapproved sites are blocked. Contact IT."

      criteria = {
        file_extensions = { matches = [".exe", ".msi", ".dmg"] }
        url_patterns    = { matches = ["*://*.example.com/*"] }
        # Excludable conditions take an action; include-only ones do not.
        employee_groups = { matches = ["Contractors"], action = "EXCLUDE" }
      }
    },
    {
      key         = "warn-on-archives"
      name        = "Warn on archives"
      enabled     = true
      mode        = "WARN"
      title       = "Careful with archives"
      subtext     = "Archives can hide executables."
      button_text = "Download anyway" # required for WARN, rejected for any other mode

      criteria = {
        file_extensions = { matches = [".zip", ".7z"] }
      }
    },
    {
      # Rules are evaluated in order and the first match wins, so a catch-all
      # belongs last.
      key     = "monitor-everything-else"
      name    = "Monitor everything else"
      enabled = true
      mode    = "MONITOR"
    },
  ]
}
