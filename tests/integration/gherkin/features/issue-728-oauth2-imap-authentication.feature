Feature: OAuth2 IMAP authentication — authorization code flow + token refresh (MW-2026-062 / issue #728)
  External IMAP accounts connect through the OAuth2 authorization code flow,
  store their refresh token encrypted at rest, and renew the access token
  automatically before it expires.

  Background:
    Given the source file "src/bin/email_api_dir/external_handlers/oauth2.rs" is loaded
    And the source file "src/external_imap/oauth2.rs" is loaded
    And the source file "src/bin/email_api_dir/startup_routes/external.rs" is loaded
    And the source file "src/security/oauth_token_crypto.rs" is loaded

  @AC1
  Scenario: The account picker offers Gmail, Outlook, Yahoo and Other
    Given the source file "src/bin/email_api_dir/external_handlers/oauth2.rs" is loaded
    Then the provider picker offers Gmail, Outlook, Yahoo and Other

  @AC2
  Scenario: The user is redirected to the provider consent screen
    Given the provider client credentials are configured
    When the user starts the OAuth2 consent flow
    Then an authorization URL for the provider consent screen is returned

  @AC3
  Scenario: The refresh token is stored encrypted in MongoDB
    Given an external IMAP account with provider "gmail"
    And the provider redirects back with a valid authorization code
    When the code is exchanged for an access token and a refresh token
    Then the refresh token is stored encrypted at rest

  @AC4
  Scenario: The access token is renewed automatically before it expires
    Given an external IMAP account whose access token is expired
    And a valid refresh token is stored encrypted at rest
    When the account needs an IMAP session
    Then a new access token is stored
    And the IMAP session opens with the new access token

  @AC5
  Scenario: A revoked or expired token raises a clear error
    Given an external IMAP account whose refresh token was revoked
    When the account needs an IMAP session
    Then the API returns HTTP 401 with code "OAUTH2_TOKEN_REVOKED"
    And the user is told to reconnect the account

  @AC6
  Scenario: Successful OAuth2 connection
    Given an external IMAP account with provider "gmail"
    And the provider client credentials are configured
    When the user starts the OAuth2 consent flow
    Then an authorization URL for the provider consent screen is returned
    When the provider redirects back with a valid authorization code
    Then the code is exchanged for an access token and a refresh token
    And the refresh token is stored encrypted at rest
    And the account can open an IMAP session with the access token

  @AC7
  Scenario: Expired access token is refreshed through the refresh_token mock
    Given an external IMAP account whose access token is expired
    And the mock token endpoint start_mock_token_endpoint is mounted
    When refresh_oauth2_access_token is called with the expired access token
    Then the refresh token is decrypted and sent to the provider
    And the renewed access token is asserted

  @AC8
  Scenario: Revoked token is rejected by the rejecting mock
    Given the rejecting mock token endpoint start_mock_token_endpoint(true) is mounted
    When exchange_authorization_code is called against the rejecting mock
    Then a clear revoked or expired error is returned

  @AC9
  Scenario: The Gherkin scenarios of AC6, AC7 and AC8 pass in CI
    Given the Gherkin scenarios of AC6, AC7 and AC8
    When the integration test suite runs in CI
    Then all three scenarios pass

  @AC10
  Scenario: The expired-token refresh scenario calls the refresh function and asserts the renewed token
    Given an external IMAP account whose access token is expired
    And the mock token endpoint start_mock_token_endpoint is mounted
    When refresh_oauth2_access_token is called with the expired access token
    Then the 'refresh_token' grant is exercised against the mock
    And the renewed access token is asserted

  @AC11
  Scenario: The revoked-token scenario calls the exchange against the rejecting mock and asserts a clear error
    Given the rejecting mock token endpoint start_mock_token_endpoint(true) is mounted
    When refresh_oauth2_token is called against the rejecting mock
    Then a clear revoked or expired error is asserted
