resource "pushsecurity_malicious_copy_paste_detection" "this" {
  globals = {
    ignored_hosts = ["*.internal.example.com", "build-server"]
  }

  rules = [
    {
      key     = "block-windows-paste-run"
      name    = "Block paste-and-run on Windows"
      enabled = true
      mode    = "BLOCK"
      title   = "That command was not written by you"
      subtext = "Pasting it into a terminal would run an attacker's code."
      # safe_text is required for BLOCK and WARN, and rejected for the rest.
      safe_text          = "This clipboard content looks safe."
      os_target          = "WINDOWS"
      payload_collection = true
    },
    {
      key         = "warn-unix"
      name        = "Warn on paste-and-run on macOS and Linux"
      enabled     = true
      mode        = "WARN"
      title       = "Check this command before running it"
      subtext     = "Attackers ask people to paste commands they did not write."
      safe_text   = "This clipboard content looks safe."
      button_text = "Paste anyway" # required for WARN, rejected for any other mode
      os_target   = "UNIX"

      criteria = {
        employee_groups = { matches = ["Engineering"] }
      }
    },
  ]
}
