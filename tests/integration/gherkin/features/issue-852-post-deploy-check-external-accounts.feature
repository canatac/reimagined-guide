Feature: Post-deploy check for external accounts
  As a deployment pipeline
  I want the external accounts endpoint to return 200
  So that the post-deploy check passes on production

  @AC1
  Scenario: Post-deploy check "external accounts" passes on production
    Given the application is deployed to production
    When a GET request is made to /api/external-accounts
    Then the response status code should be 200
