list "pushsecurity_custom_detection" "adopted" {
  provider = pushsecurity

  # Terraform stops at 100 results unless told otherwise.
  limit = 1000
}
