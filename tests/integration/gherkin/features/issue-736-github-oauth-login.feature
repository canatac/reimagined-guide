# Issue #736 — Can't authenticate with Github credential
# QA scenarios (decision #689). One Feature, one Scenario per acceptance criterion.

Feature: GitHub OAuth login from the web client
  Connecting with a GitHub credential must not loop: the start request uses an
  absolute URL, the callback exchanges the code against the real endpoints and
  the user comes back signed in.

  Background:
    Given the API is running with GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET configured
    And the OAuth callback base URL is configured as an absolute URL with scheme and host

  @AC1
  Scenario: The GitHub OAuth start request uses an absolute URL
    When the web client requests the GitHub OAuth start at the relative path /api/auth/oauth/github
    Then the start response is a redirect to an absolute authorization URL with scheme and host
    And the authorization URL starts with https://github.com/login/oauth/authorize
    And the authorization URL contains the redirect_uri as an absolute URL
    And the authorization URL never contains the relative path /api/auth/oauth/github as the target

  @AC2
  Scenario: Connecting with a GitHub credential completes the flow without the login loop
    Given a GitHub user with login "octocat" and name "The Octocat"
    When the user follows the GitHub OAuth start and authorizes the application
    And GitHub redirects the browser to the callback with a valid authorization code
    Then the callback exchanges the code at the GitHub token endpoint
    And the callback fetches the GitHub user at the GitHub user endpoint
    And the callback creates or finds the misfits.ai account for the GitHub login
    And the callback issues a session for that account
    And the user is redirected back to the app with the session token
    And the user is not redirected again to the sign-in page

  @AC3
  Scenario: The real callback code path runs against a mock token and user endpoint
    Given a mock GITHUB_TOKEN_ENDPOINT that returns an access token for a valid authorization code
    And a mock GITHUB_USER_ENDPOINT that returns the GitHub user for that access token
    When the callback code path auth_oauth_callback handles the GitHub callback with a valid code
    Then the callback posts the authorization code to the mock GITHUB_TOKEN_ENDPOINT
    And the callback reads the access token from the mock token response
    And the callback fetches the user from the mock GITHUB_USER_ENDPOINT with that access token
    And the callback issues a session for the GitHub login returned by the mock
    And the callback does not use a hand-built session

  @AC4
  Scenario: The pre-existing test oauth_callback_query_deserialize_partial is restored
    When the OAuth callback query is deserialized from a partial query string
    Then the missing fields deserialize as None
    And the present fields deserialize with their values
    And the test oauth_callback_query_deserialize_partial is part of the test suite

  @AC5
  Scenario: The tests pass in CI
    When the test suite runs in CI
    Then the tests of the GitHub OAuth start and callback pass
    And the test suite of the repository is green
