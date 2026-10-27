list "pushsecurity_employee" "admins" {
  provider = pushsecurity

  config {
    groups = ["Push administrators"]
  }
}
