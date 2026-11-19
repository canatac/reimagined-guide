Feature: Restore the full GitHub OAuth handlers and their tests
  Pull request #737 (issue #736) replaced src/bin/email_api_dir/auth_handlers/oauth.rs with a 1-line stub, deleting auth_oauth_start, auth_oauth_callback and the whole test module. The deleted code must come back so no behaviour is lost.

  @AC1
  Scenario: oauth.rs is restored whole with the #736 start fix kept
    Given the file src/bin/email_api_dir/auth_handlers/oauth.rs
    Then it defines the handler auth_oauth_start
    And it defines the handler auth_oauth_callback
    And it defines the struct OAuthCallbackQuery
    And the OAuth start fix of #736 is kept

  @AC2
  Scenario: No behaviour of the callback is lost
    Given the restored handler auth_oauth_callback
    Then the token exchange is unchanged
    And the user fetch is unchanged
    And the session is unchanged
    And the frontend redirect is unchanged

  @AC3
  Scenario: The pre-existing tests of the file are restored
    Given the restored test module of oauth.rs
    Then the pre-existing tests are present
    And the test oauth_callback_query_deserialize_partial is present

  @AC4
  Scenario: The tests pass in CI
    Given the restored oauth.rs and its tests
    When the test suite runs in CI
    Then the tests pass
