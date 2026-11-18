Feature: OAuth2 IMAP authentication (MW-2026-062 / issue #728)
  External IMAP accounts authenticate with OAuth2 authorization code flow,
  store their refresh token encrypted at rest, and renew the access token
  automatically before it expires.

  Background:
    Given the source file "src/bin/email_api_dir/external_handlers/oauth2.rs" is loaded
    And the source file "src/external_imap/oauth2.rs" is loaded
    And the source file "src/bin/email_api_dir/startup_routes/external.rs" is loaded
    And the source file "src/security/oauth_token_crypto.rs" is loaded

  Scenario: Provider picker offers Gmail, Outlook, Yahoo and Other
    Given the source file "src/bin/email_api_dir/external_handlers/oauth2.rs" is loaded
    Then the provider picker offers Gmail, Outlook, Yahoo and Other

  Scenario: Successful OAuth2 connection
    Given an external IMAP account with provider "gmail"
    And the provider client credentials are configured
    And the user starts the OAuth2 consent flow
    Then an authorization URL for the provider consent screen is returned
    When the provider redirects back with a valid authorization code
    Then the refresh token is stored encrypted at rest

  Scenario: Expired access token is refreshed
    Given an external IMAP account with provider "gmail" and an expired access token
    And the provider client credentials are configured
    And the mock token endpoint accepts the refresh_token grant
    When the access token is renewed
    Then the renewed access token is returned

  Scenario: Revoked or expired token is rejected with a clear error
    Given an external IMAP account with provider "gmail" and an expired access token
    And the provider client credentials are configured
    And the mock token endpoint rejects the request
    When the access token is renewed
    Then a clear revoked or expired token error is returned

  Scenario: Revoked authorization code is rejected with a clear error
    Given the provider client credentials are configured
    And the mock token endpoint rejects the request
    When the provider redirects back with a revoked authorization code
    Then a clear revoked or expired token error is returned
