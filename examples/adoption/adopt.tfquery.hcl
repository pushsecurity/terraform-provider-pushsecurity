# Every list resource the provider has. terraform query reads this file, and
# with -generate-config-out writes a resource and an import block for each
# result. Delete the blocks for anything you mean to leave to the console.
#
# The provider block and required_providers stay in a .tf file beside it.

list "pushsecurity_account_condition_enforcement" "adopted" {
  provider = pushsecurity
}

list "pushsecurity_app_banner" "adopted" {
  provider = pushsecurity
}

list "pushsecurity_app_banner_url_pattern" "adopted" {
  provider = pushsecurity
}

list "pushsecurity_browser_extension_blocking" "adopted" {
  provider = pushsecurity
}

list "pushsecurity_clipboard_blocking" "adopted" {
  provider = pushsecurity
}

list "pushsecurity_cloned_login_page_detection" "adopted" {
  provider = pushsecurity
}

list "pushsecurity_file_download_blocking" "adopted" {
  provider = pushsecurity
}

list "pushsecurity_file_download_telemetry" "adopted" {
  provider = pushsecurity
}

list "pushsecurity_file_upload_blocking" "adopted" {
  provider = pushsecurity
}

list "pushsecurity_file_upload_telemetry" "adopted" {
  provider = pushsecurity
}

list "pushsecurity_malicious_browser_extension_detection" "adopted" {
  provider = pushsecurity
}

list "pushsecurity_malicious_copy_paste_detection" "adopted" {
  provider = pushsecurity
}

list "pushsecurity_mfa_enforcement" "adopted" {
  provider = pushsecurity
}

list "pushsecurity_password_logging_prevention" "adopted" {
  provider = pushsecurity
}

list "pushsecurity_phishing_tool_detection" "adopted" {
  provider = pushsecurity
}

list "pushsecurity_strong_password_enforcement" "adopted" {
  provider = pushsecurity
}

list "pushsecurity_blocked_urls" "adopted" {
  provider = pushsecurity
}

list "pushsecurity_settings" "adopted" {
  provider = pushsecurity
}

list "pushsecurity_custom_detection" "adopted" {
  provider = pushsecurity

  # Terraform stops at 100 results unless told otherwise.
  limit = 1000
}

# Employees mostly come from directory sync. Adopt only the ones you mean to
# manage here.
list "pushsecurity_employee" "adopted" {
  provider = pushsecurity

  config {
    groups = ["Push administrators"]
  }
}
