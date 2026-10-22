data "pushsecurity_custom_detections" "all" {}

# Every custom detection in the tenant, by the identifier you import it with.
output "detection_names" {
  value = {
    for d in data.pushsecurity_custom_detections.all.detections :
    d.detection_event_type => d.name
  }
}

# The detections you already manage. In your own configuration, reference the
# resources instead, as in
# pushsecurity_custom_detection.torrent_website_visit.detection_event_type.
locals {
  managed_detection_event_types = []
}

# Useful for finding detections that exist in the tenant but are not yet
# managed by Terraform.
output "unmanaged_detections" {
  value = setsubtract(
    data.pushsecurity_custom_detections.all.detection_event_types,
    local.managed_detection_event_types,
  )
}
