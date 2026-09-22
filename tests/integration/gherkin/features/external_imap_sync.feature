Feature: External IMAP account bidirectional sync (issue #599)
  As a user
  I want to connect an external IMAP account and sync emails bidirectionally
  So that I can view and send emails from external accounts within the unified inbox

  Scenario: External account connection form accepts host, port, user, password
    Given the route "POST /api/external-accounts" exists
    And the handler "api_external_accounts_create" is registered
    And the input schema accepts "imap.host", "imap.port", "imap.tls", "credentials.secretValue"
    Then the external account creation endpoint is available

  Scenario: External emails are tagged with source in unified inbox
    Given the unified inbox handler "api_emails_unified" exists
    And an external account with email "<EMAIL>" is configured
    When the unified inbox fetches emails with "unified=true"
    Then each external email has "account_type" set to "external"
    And each external email has "source" starting with "external:"
    And each external email has "account_email" set to "<EMAIL>"

  Scenario: External account sync endpoint triggers IMAP fetch
    Given the route "POST /api/external-accounts/{id}/sync" exists
    And the handler "api_external_sync_start" is registered
    And the ExternalImapService has "run_sync_now" method
    Then the sync endpoint triggers an IMAP fetch for the account

  Scenario: External account send endpoint routes via external SMTP
    Given the route "POST /api/external-accounts/{id}/send" exists
    And the handler "api_external_account_send" is registered
    And the account has "smtp_host" configured
    Then the send endpoint routes the email through the external SMTP server

  Scenario: Sync status endpoint returns run state
    Given the route "GET /api/external-accounts/{id}/sync/status" exists
    And the handler "api_external_sync_status" is registered
    Then the sync status endpoint returns the latest sync run for the account
