# language: en
# Issue #739: OAuth2 IMAP: Gherkin coverage for expired-token refresh and revoked-token error

Feature: OAuth2 IMAP token refresh and revoked-token error
  The OAuth2 IMAP flow must renew an expired access token with the
  refresh_token grant and must answer a clear error when the token is
  revoked or expired.

  Background:
    Given an external IMAP account configured with OAuth2 credentials
    And the mock token endpoint mounted by start_mock_token_endpoint

  @AC1
  Scenario: An expired access token is renewed with the refresh_token grant
    Given the stored access token of the external account is expired
    When refresh_oauth2_access_token is called with the stored refresh token
    Then the renewed access token is asserted from the mock token endpoint
    And the renewed access token is used for the IMAP connection

  @AC2
  Scenario: A revoked or expired token is answered with a clear error
    Given the mock token endpoint rejects the request (start_mock_token_endpoint(true))
    When exchange_authorization_code or refresh_oauth2_token is called against the rejecting mock
    Then a clear revoked or expired error is asserted
