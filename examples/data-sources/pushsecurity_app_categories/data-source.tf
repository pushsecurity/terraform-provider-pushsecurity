data "pushsecurity_app_categories" "all" {}

# The app_categories criterion matches on numeric codes. Writing
# matches = ["34"] in a pull request tells a reviewer nothing; looking the code
# up by name does. Fails during plan if no app in the tenant has the category.
output "information_technology_code" {
  value = data.pushsecurity_app_categories.all.codes_by_name["Information Technology"]
}

# Use the lookup in a rule of a control you have already imported:
#
#   criteria = {
#     app_categories = {
#       matches = [data.pushsecurity_app_categories.all.codes_by_name["Information Technology"]]
#     }
#   }
#
# Import the control before you add it to your configuration. A control
# resource owns the whole control, so applying one you have not imported
# replaces every rule the tenant already has.

# Categories are derived from the apps in the tenant, so this shows what is
# actually resolvable.
output "categories_in_use" {
  value = data.pushsecurity_app_categories.all.categories
}
