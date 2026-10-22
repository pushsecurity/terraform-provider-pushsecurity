data "pushsecurity_apps" "all" {}

# Apps carrying a particular label. The API's app endpoint filters only on
# creation time, so this filtering happens in the provider.
data "pushsecurity_apps" "unreviewed_ai" {
  labels            = ["ai"]
  approval_statuses = ["NOT_REVIEWED", "UNDER_REVIEW"]
}

# Useful for discovering what a tenant actually uses before writing criteria.
output "app_types" {
  value = data.pushsecurity_apps.all.types
}

output "labels_in_use" {
  value = data.pushsecurity_apps.all.all_labels
}

# The types are ready to pass to an app_types criterion, in a rule of a control
# you have already imported:
#
#   criteria = {
#     app_types = { matches = data.pushsecurity_apps.unreviewed_ai.types }
#   }
#
# Import the control before you add it to your configuration. A control
# resource owns the whole control, so applying one you have not imported
# replaces every rule the tenant already has.
output "unreviewed_ai_types" {
  value = data.pushsecurity_apps.unreviewed_ai.types
}
