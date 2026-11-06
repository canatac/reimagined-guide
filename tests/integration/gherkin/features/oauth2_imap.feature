Feature: OAuth2 IMAP authentication (MW-2026-062 / issue #728)
  External IMAP accounts connect with the OAuth 2.0 authorization code flow,
  store their refresh token encrypted at rest, and renew the access token
  automatically before it expires.

  Scenario: Provider picker lists the supported providers
    Given the external IMAP API is running
    When the client requests the OAuth2 provider catalogue
    Then the response lists "gmail", "outlook", "yahoo" and "other"
    And each provider carries an authorization endpoint, a token endpoint and scopes

  Scenario: Successful OAuth2 connection
    Given an external IMAP account with provider "gmail"
    And the provider client credentials are configured
    When the user starts the OAuth2 consent flow with the provider in the query
    Then an authorization URL for the provider consent screen is returned
    When the client navigates to the authorize route
    Then the API responds with a redirect to the provider consent screen
    When the provider redirects back with a valid authorization code
    Then the code is exchanged for an access token and a refresh token
    And the refresh token is stored encrypted at rest

  Scenario: Expired access token is refreshed automatically
    Given an external IMAP account with a stored refresh token
    And the stored access token is expired
    When the account sync runs
    Then the access token is refreshed with the stored refresh token
    And the new access token is stored encrypted at rest

  Scenario: Revoked refresh token yields a clear error
    Given an external IMAP account with a stored refresh token
    And the refresh token has been revoked at the provider
    When the account sync runs
    Then the sync fails with a clear revoked-token error
    And the account is marked as needing re-authentication
