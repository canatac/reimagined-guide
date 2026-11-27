Feature: Post-deploy check send an email
  As a deployment pipeline
  I want the post-deploy check "send an email" to pass
  So that the production environment is verified after each deploy

  @AC1
  Scenario: Post-deploy check "send an email" passes on production after the next deploy
    Given the production environment has been deployed with the latest changes
    When the post-deploy check "send an email" is executed
    Then the check should pass with HTTP status 200 or 202
    And the POST /api/compose/send endpoint should return a success response
