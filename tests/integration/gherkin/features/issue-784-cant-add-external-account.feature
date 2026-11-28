Feature: External Account Addition
  As a user
  I want to add external accounts via the avatar menu
  So that I can manage multiple email providers

  @AC1
  Scenario: Provider catalogue request returns HTTP 200
    Given the user clicks on 'Add account' in the avatar menu
    When the provider catalogue request is made
    Then the response status code should be 200

  @AC2
  Scenario: External account can be added successfully via avatar menu
    Given the user is on the avatar menu
    When the user clicks on 'Add account'
    And selects a provider from the catalogue
    And completes the provider's authentication flow
    Then the external account should be added successfully

  @AC3
  Scenario: No HTTP 500 errors when accessing provider catalogue
    Given the user clicks on 'Add account' in the avatar menu
    When the provider catalogue request is made
    Then no HTTP 500 errors should occur