# Employees in a group, so a control can be scoped by membership without
# naming each person — and without going stale as the group changes.
data "pushsecurity_employees" "contractors" {
  groups = ["Contractors"]
}

# The API applies these filters, so this stays usable on a large tenant.
data "pushsecurity_employees" "licensed" {
  licensed = true
}

# Criteria are written with email addresses; the provider resolves them to the
# identifiers the API matches on. Pass these to an employee_ids criterion, in a
# rule of a control you have already imported:
#
#   criteria = {
#     employee_ids = { matches = data.pushsecurity_employees.contractors.emails }
#   }
#
# Import the control before you add it to your configuration. A control
# resource owns the whole control, so applying one you have not imported
# replaces every rule the tenant already has.
output "contractor_emails" {
  value = data.pushsecurity_employees.contractors.emails
}

output "licensed_count" {
  value = length(data.pushsecurity_employees.licensed.employees)
}
