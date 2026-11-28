Feature: Post-deploy check external accounts
  As a deployment pipeline
  I want the external accounts endpoint to be healthy
  So that the post-deploy check passes on production

  @AC1
  Scenario: Post-deploy check "external accounts" passes on production
    Given the production environment is deployed
    When a GET request is made to /api/external-accounts
    Then the response status code should be 200