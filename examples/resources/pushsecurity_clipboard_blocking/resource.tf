resource "pushsecurity_clipboard_blocking" "this" {
  globals = {
    # `enum` is derived by the server from `name`, and is what rules reference
    # in criteria.regex_patterns.
    custom_content_patterns = [
      { name = "Incident ticket", regex = "INC-\\d{6}" },
    ]
  }

  rules = [
    {
      key             = "block-ticket-copy"
      name            = "Block copying incident references"
      enabled         = true
      mode            = "BLOCK"
      operation       = "COPY"
      content_capture = true
      mask_pii        = true # required whenever content_capture is true
      title           = "Copy blocked"
      subtext         = "Incident references may not be copied off-platform."

      # Required because this rule matches regex patterns. A BLOCK rule that
      # matched no regex patterns would need acknowledge_button_text instead.
      copy_redacted_button_text = "Copy redacted"

      criteria = {
        regex_patterns = { matches = ["CUSTOM_INCIDENT_TICKET"] }
      }
    },
    {
      key             = "monitor-external-pastes"
      name            = "Monitor pastes into external sites"
      enabled         = true
      mode            = "MONITOR"
      operation       = "PASTE"
      content_capture = false

      # criteria is required on this control, and must match on at least one of
      # url_patterns or regex_patterns.
      criteria = {
        url_patterns = { matches = ["*://*.example.com/*"] }
      }
    },
  ]
}
