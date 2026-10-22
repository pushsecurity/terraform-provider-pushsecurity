# The same merge, expressed as a shape rather than as a list of people:
# wherever somebody has a .admin or .support address, it belongs to them.
#
# {local} and {domain} are filled in from each employee's own address, so a
# match knows whose address it is. New aliases are merged by the plan that
# follows them, with nobody editing this file.
resource "pushsecurity_employee_merge_rule" "admin_aliases" {
  patterns = [
    "{local}.admin@{domain}",
    "{local}.support@{domain}",
  ]

  # Only people in the corporate domain are treated as owners of an alias.
  domains = ["example.com"]

  # Shared mailboxes that happen to follow the same naming convention.
  exclude_emails = ["security.admin@example.com"]

  # A merge can be undone only in part, so an apply that would merge more than
  # this fails and shows the pairs instead. Raise it deliberately, once.
  max_merges = 10
}
