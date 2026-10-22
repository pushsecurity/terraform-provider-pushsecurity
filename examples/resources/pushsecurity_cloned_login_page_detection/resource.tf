resource "pushsecurity_cloned_login_page_detection" "this" {
  globals = {
    ignored_hosts = ["*.internal.example.com", "build-server", "10.0.1.1"]
  }

  rules = [
    {
      key                = "warn-everyone"
      name               = "Warn on cloned login pages"
      enabled            = true
      mode               = "WARN"
      title              = "This page may be impersonating a login screen"
      subtext            = "Check the address before entering your password."
      ignore_button_text = "Continue anyway" # required for WARN, rejected elsewhere
    },
  ]
}
