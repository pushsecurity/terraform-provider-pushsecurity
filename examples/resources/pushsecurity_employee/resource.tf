# An address the tenant already holds is adopted: this grants a licence and
# leaves everything else — groups, names from the directory — alone.
resource "pushsecurity_employee" "ada_lovelace" {
  email    = "ada.lovelace@example.com"
  licensed = true
}

# An address the tenant does not hold is created, which needs a name. Creating
# an employee consumes a licence: the API licenses new employees automatically.
resource "pushsecurity_employee" "contractor" {
  email      = "sam.okafor@contractor.example.com"
  first_name = "Sam"
  last_name  = "Okafor"
}

# Removing a licence deletes the employee record, their accounts, the
# findings raised against them and their browsers, so it has to be asked for
# twice.
resource "pushsecurity_employee" "departed" {
  email           = "alex.ward@example.com"
  licensed        = false
  allow_unlicense = true
}
