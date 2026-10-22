# One person, several addresses. The primary is the record that survives; the
# others stop existing as separate employees, so a detection on the .admin
# account is attributed to the person who owns it.
resource "pushsecurity_employee_merge" "ada_lovelace" {
  primary_email = "ada.lovelace@example.com"
  secondary_emails = [
    "ada.lovelace.admin@example.com",
    "ada.lovelace.support@example.com",
  ]
}

# Addresses the tenant does not hold are accepted and warned about: once an
# address has been merged it looks exactly like one that never existed, so a
# re-run after losing state is a no-op rather than an error.
