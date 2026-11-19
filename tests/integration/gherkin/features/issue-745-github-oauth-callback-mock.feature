Feature: GitHub OAuth callback tested against a mock token and user endpoint
  The real callback code path must be exercised against a mock, as the OAuth2 IMAP tests do with start_mock_token_endpoint. A test that only builds JSON literals and calls make_session passes even if the callback were a no-op.

  @AC1
  Scenario: A test invokes the real callback against a mock token and user endpoint
    Given a local mock HTTP server serving GITHUB_TOKEN_ENDPOINT and GITHUB_USER_ENDPOINT
    When a test invokes auth_oauth_callback with an authorization code
    Then the callback exchanges the code at the mock token endpoint
    And the callback fetches the user at the mock user endpoint

  @AC2
  Scenario: The mock is a local mock HTTP server in the oauth.rs test module
    Given the oauth.rs test module provides a local mock HTTP server
    When the test starts the mock and points GITHUB_TOKEN_ENDPOINT and GITHUB_USER_ENDPOINT at it
    Then the mock serves both the token endpoint and the user endpoint

  @AC3
  Scenario: The test asserts the session issued by the real callback and the redirect it returns
    Given the mock token endpoint returns an access token
    And the mock user endpoint returns a GitHub login and name
    When the real callback handles the authorization code
    Then the session issued by the real callback is asserted
    And the frontend redirect returned by the callback is asserted

  @AC4
  Scenario: The test passes in CI
    Given the test of the real callback code path is in the repository
    When the test suite runs in CI
    Then the test passes
