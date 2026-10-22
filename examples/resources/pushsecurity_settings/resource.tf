resource "pushsecurity_settings" "this" {
  # The complete list: an apply removes any domain not here, including one
  # added in the console, and the plan warns about each one it removes.
  # Lower case only, as the API stores them.
  monitored_domains = [
    "example.com",
    "example.co.uk",
  ]

  monitor_all_domains = true
}
