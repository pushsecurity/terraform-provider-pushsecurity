resource "pushsecurity_browser_extension_blocking" "this" {
  rules = [
    {
      key     = "allow-approved-extensions"
      name    = "Allow the extensions we have reviewed"
      enabled = true
      mode    = "ENABLE"

      criteria = {
        browser_extensions = {
          matches = ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]
        }
      }
    },
    {
      key     = "block-sideloaded"
      name    = "Block sideloaded and development extensions"
      enabled = true
      mode    = "BLOCK"
      title   = "This extension is blocked"
      subtext = "Extensions installed outside the store are not permitted."

      criteria = {
        browser_extension_deployment_type = { matches = ["SIDELOAD", "DEVELOPMENT"] }
        browser_extension_profile         = { matches = ["COMPANY_DOMAINS"] }
      }
    },
    {
      key     = "block-broad-permissions"
      name    = "Block extensions that can read every page"
      enabled = true
      mode    = "BLOCK"
      title   = "This extension asks for too much"
      subtext = "It can read and change data on every site you visit."

      criteria = {
        browser_extension_permissions = { matches = ["<all_urls>", "tabs"] }
        employee_groups               = { matches = ["Security"], action = "EXCLUDE" }
      }
    },
  ]
}
