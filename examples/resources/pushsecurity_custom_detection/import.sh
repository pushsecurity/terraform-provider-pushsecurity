# Custom detections have real identity: import by detection event type, which
# the API derives from the name (upper-cased, spaces to underscores, prefixed
# with CUSTOM_).
terraform import pushsecurity_custom_detection.torrent_website_visit CUSTOM_TORRENT_WEBSITE_VISIT
