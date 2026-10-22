resource "pushsecurity_account_condition_enforcement" "this" {
  rules = [
    {
      key     = "block-personal-ai-logins"
      name    = "Block password logins to AI apps with a personal email"
      enabled = true
      mode    = "BLOCK"
      # BLOCK requires these three, and rejects continue_button_text.
      title                 = "Use your work account"
      subtext               = "Sign in to this app with your company email address."
      terminate_button_text = "Sign out"

      criteria = {
        # app_types and domain_scope are required on every rule.
        app_types    = { matches = ["OPENAI_CHATGPT", "ANTHROPIC_CLAUDE", "GOOGLE_GEMINI"] }
        domain_scope = "SPECIFIC_DOMAINS"
        # Required when domain_scope is SPECIFIC_DOMAINS, rejected otherwise.
        login_domains = { matches = ["gmail.com", "outlook.com"] }
        login_types   = { matches = ["PASSWORD_LOGIN"] }
      }
    },
    {
      key                   = "warn-non-company-logins"
      name                  = "Warn on code hosting logins outside company domains"
      enabled               = true
      mode                  = "WARN"
      title                 = "This is not a company account"
      subtext               = "Company code belongs in company accounts."
      terminate_button_text = "Sign out"
      continue_button_text  = "Continue anyway" # required for WARN only

      criteria = {
        app_types       = { matches = ["GITHUB"] }
        domain_scope    = "NON_COMPANY_DOMAINS"
        employee_groups = { matches = ["Contractors"], action = "EXCLUDE" }
      }
    },
  ]
}
