resource "pushsecurity_file_upload_blocking" "this" {
  rules = [
    {
      key     = "block-source-to-unapproved"
      name    = "Block source archives leaving for unapproved sites"
      enabled = true
      mode    = "BLOCK"
      title   = "Upload blocked"
      subtext = "Source code may not be uploaded to this site."

      criteria = {
        file_extensions = { matches = [".zip", ".tar", ".gz"] }
        url_patterns    = { matches = ["*://*.filesharing.example/*"] }
      }
    },
    {
      key         = "warn-on-spreadsheets"
      name        = "Warn on spreadsheet uploads"
      enabled     = true
      mode        = "WARN"
      title       = "Check before uploading"
      subtext     = "Spreadsheets often hold customer data."
      button_text = "Upload anyway" # required for WARN, rejected for any other mode

      criteria = {
        file_extensions = { matches = [".xlsx", ".csv"] }
        employee_groups = { matches = ["Finance"], action = "EXCLUDE" }
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
