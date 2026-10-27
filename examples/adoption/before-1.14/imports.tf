# For Terraform 1.8 to 1.13, which have no terraform query. An import block for
# each configuration there is one of per tenant: delete the blocks for anything
# you mean to leave to the console, and in particular for anything empty, which
# Terraform would otherwise own from the next apply on.
#
# The provider argument is needed while Terraform generates the configuration,
# and must be removed before the apply: see the adoption guide.

import {
  to       = pushsecurity_account_condition_enforcement.this
  provider = pushsecurity
  id       = "default"
}

import {
  to       = pushsecurity_app_banner.this
  provider = pushsecurity
  id       = "default"
}

import {
  to       = pushsecurity_app_banner_url_pattern.this
  provider = pushsecurity
  id       = "default"
}

import {
  to       = pushsecurity_browser_extension_blocking.this
  provider = pushsecurity
  id       = "default"
}

import {
  to       = pushsecurity_clipboard_blocking.this
  provider = pushsecurity
  id       = "default"
}

import {
  to       = pushsecurity_cloned_login_page_detection.this
  provider = pushsecurity
  id       = "default"
}

import {
  to       = pushsecurity_file_download_blocking.this
  provider = pushsecurity
  id       = "default"
}

import {
  to       = pushsecurity_file_download_telemetry.this
  provider = pushsecurity
  id       = "default"
}

import {
  to       = pushsecurity_file_upload_blocking.this
  provider = pushsecurity
  id       = "default"
}

import {
  to       = pushsecurity_file_upload_telemetry.this
  provider = pushsecurity
  id       = "default"
}

import {
  to       = pushsecurity_malicious_browser_extension_detection.this
  provider = pushsecurity
  id       = "default"
}

import {
  to       = pushsecurity_malicious_copy_paste_detection.this
  provider = pushsecurity
  id       = "default"
}

import {
  to       = pushsecurity_mfa_enforcement.this
  provider = pushsecurity
  id       = "default"
}

import {
  to       = pushsecurity_password_logging_prevention.this
  provider = pushsecurity
  id       = "default"
}

import {
  to       = pushsecurity_phishing_tool_detection.this
  provider = pushsecurity
  id       = "default"
}

import {
  to       = pushsecurity_strong_password_enforcement.this
  provider = pushsecurity
  id       = "default"
}

import {
  to       = pushsecurity_blocked_urls.this
  provider = pushsecurity
  id       = "default"
}

import {
  to       = pushsecurity_settings.this
  provider = pushsecurity
  id       = "default"
}

# One per custom detection, by its detection event type. The
# pushsecurity_custom_detections data source lists them.
import {
  to       = pushsecurity_custom_detection.torrent_website_visit
  provider = pushsecurity
  id       = "CUSTOM_TORRENT_WEBSITE_VISIT"
}
