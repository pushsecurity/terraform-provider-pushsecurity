# Changelog

Every release is a beta until the provider is generally available, and a beta
may change resources, attributes and behaviour without a deprecation period.
Each entry says what such a change means for an existing configuration.

## 0.1.0-beta.1 (Unreleased)

First public release.

### Resources

- Control configurations: `pushsecurity_account_condition_enforcement`,
  `pushsecurity_app_banner`, `pushsecurity_app_banner_url_pattern`,
  `pushsecurity_browser_extension_blocking`, `pushsecurity_clipboard_blocking`,
  `pushsecurity_cloned_login_page_detection`, `pushsecurity_file_download_blocking`,
  `pushsecurity_file_upload_blocking`, `pushsecurity_malicious_browser_extension_detection`,
  `pushsecurity_malicious_copy_paste_detection`, `pushsecurity_mfa_enforcement`,
  `pushsecurity_password_logging_prevention`, `pushsecurity_phishing_tool_detection` and
  `pushsecurity_strong_password_enforcement`.
- Telemetry configurations: `pushsecurity_file_download_telemetry` and
  `pushsecurity_file_upload_telemetry`.
- `pushsecurity_custom_detection`, `pushsecurity_blocked_urls` and `pushsecurity_settings`.
- `pushsecurity_employee`, `pushsecurity_employee_merge` and `pushsecurity_employee_merge_rule`.

### Data sources

- `pushsecurity_app`, `pushsecurity_apps`, `pushsecurity_app_categories`, `pushsecurity_custom_detections`,
  `pushsecurity_employee` and `pushsecurity_employees`.

### Tools

- `push-tf-bootstrap`, which surveys an existing tenant and writes the import
  blocks and detection logic files to adopt it. Each provider release carries
  a `push-tf-bootstrap` `.tar.gz` archive per platform.
