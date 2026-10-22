# Telemetry configurations share the control shape but have no rule fields: a
# rule is a name, a mode and its criteria.
resource "pushsecurity_file_upload_telemetry" "this" {
  rules = [
    {
      key     = "company-profiles-only"
      name    = "Record uploads from company browser profiles"
      enabled = true
      mode    = "ON"
      criteria = {
        # profile_scope is the one single-valued criterion: a plain string
        # rather than a matches list.
        profile_scope = "COMPANY_DOMAIN"
      }
    },
    {
      key     = "everything-else-off"
      name    = "Record nothing from personal profiles"
      enabled = true
      mode    = "OFF"
    },
  ]
}
