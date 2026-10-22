# A single app, by type. Fails during plan if no such app exists in the tenant.
data "pushsecurity_app" "workspace" {
  type = "GOOGLE_WORKSPACE"
}

output "workspace_categories" {
  value = data.pushsecurity_app.workspace.category_names
}

output "workspace_sensitivity" {
  value = data.pushsecurity_app.workspace.sensitivity_level
}
