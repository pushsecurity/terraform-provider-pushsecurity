# Telemetry configurations share the control shape but have no rule fields: a
# rule is a name, a mode and its criteria.
resource "pushsecurity_file_download_telemetry" "this" {
  rules = [
    {
      key     = "exclude-contractors"
      name    = "Do not record contractor downloads"
      enabled = true
      mode    = "OFF"
      criteria = {
        employee_groups = { matches = ["Contractors"] }
      }
    },
    {
      key     = "everyone-else"
      name    = "Record downloads for everyone else"
      enabled = true
      mode    = "ON"
    },
  ]
}
