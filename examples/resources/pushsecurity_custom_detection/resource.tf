resource "pushsecurity_custom_detection" "torrent_website_visit" {
  name = "Torrent website visit"

  # The API stores and returns this byte for byte, so keeping detection logic in
  # its own file gives you detection-as-code with no normalisation surprises:
  # a plan is empty unless the file actually changed.
  detection_logic = file("${path.module}/detections/torrent-website-visit.yaml")

  rules = [
    {
      key      = "block-contractors"
      name     = "Block torrent sites for contractors"
      enabled  = true
      mode     = "BLOCK"
      severity = "HIGH"
      title    = "Blocked"
      subtext  = "Torrent sites are not permitted on company devices."

      criteria = {
        employee_groups = { matches = ["Contractors"] }
      }
    },
    {
      key         = "warn-everyone-else"
      name        = "Warn everyone else"
      enabled     = true
      mode        = "WARN"
      severity    = "MEDIUM"
      title       = "Careful"
      subtext     = "Torrent sites are discouraged. This visit is recorded."
      button_text = "Continue anyway" # required for WARN

      # Also applies to internal hosts and private IP addresses. Must be false
      # (or omitted) when mode is OFF: the API returns it as false there.
      detect_on_internal_hosts = true
    },
  ]
}
