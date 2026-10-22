# A single employee, by email. Fails during plan if the address matches no
# employee, so a typo cannot silently narrow a control to nobody.
data "pushsecurity_employee" "security_lead" {
  email = "security.lead@example.com"
}

output "security_lead_groups" {
  value = data.pushsecurity_employee.security_lead.groups
}
