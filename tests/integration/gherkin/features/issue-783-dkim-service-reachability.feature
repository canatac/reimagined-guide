Feature: DKIM Service Reachability and Email Send Success
  As a user of misfits.ai Mail
  I want the DKIM service to be reachable and emails to send without timeout errors
  So that I can reliably send emails

  @AC1
  Scenario: DKIM service is reachable and responds to generate-dkim requests
    Given the DKIM service is running and healthy
    When a generate-dkim request is sent to http://dkim-service:3000/generate-dkim
    Then the DKIM service responds with a success status

  @AC2
  Scenario: Email send succeeds without DKIM timeout errors
    Given the DKIM service is reachable
    And I have composed an email with valid recipient and content
    When I click the send button
    Then the email is sent successfully
    And no DKIM timeout error occurs

  @AC3
  Scenario: Error message no longer appears after clicking send
    Given the DKIM service is reachable
    And I have composed an email with valid recipient and content
    When I click the send button
    Then the email send succeeds
    And the error message "DKIM service temporarily unavailable" does not appear