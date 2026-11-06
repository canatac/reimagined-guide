Feature: OAuth2 IMAP authentication (MW-2026-062 / issue #728)
  External IMAP accounts connect through the OAuth2 authorization code flow,
  store their refresh token encrypted at rest, and renew the access token
  automatically before it expires.

  Scenario: Successful OAuth2 connection
    Given an external IMAP account with provider "gmail"
    And the provider client credentials are configured
    When the user starts the OAuth2 consent flow
    Then an authorization URL for the provider consent screen is returned
    When the provider redirects back with a valid authorization code
    Then the code is exchanged for an access token and a refresh token
    And the refresh token is stored encrypted at rest
    And the account can open an IMAP session with the access token

  Scenario: Expired access token is refreshed automatically
    Given an external IMAP account whose access token is expired
    And a valid refresh token is stored encrypted at rest
    When the account needs an IMAP session
    Then the refresh token is decrypted and sent to the provider
    And a new access token is stored
    And the IMAP session opens with the new access token

  Scenario: Revoked or expired refresh token raises a clear error
    Given an external IMAP account whose refresh token was revoked
    When the account needs an IMAP session
    Then the provider rejects the refresh token
    And the API returns HTTP 401 with code "OAUTH2_TOKEN_REVOKED"
    And the user is told to reconnect the account

  Scenario: Missing refresh token raises a clear error
    Given an external IMAP account with no stored refresh token
    When a token refresh is requested
    Then the API returns HTTP 400 with code "OAUTH2_REFRESH_TOKEN_MISSING"
