# Import by the primary employee's email address. Which addresses were merged
# into that person is not recorded anywhere the API exposes, so the import
# adopts the primary only: write secondary_emails yourself, and the first apply
# is a no-op for the ones that are already merged.
terraform import pushsecurity_employee_merge.ada_lovelace ada.lovelace@example.com
