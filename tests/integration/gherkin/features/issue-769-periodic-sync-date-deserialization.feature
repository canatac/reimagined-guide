Feature: Periodic sync date deserialization
  As a misfits.ai Mail server running periodic_sync,
  I want a date field stored as a BSON Date (extended JSON map) or as an RFC 3339 string to deserialize,
  so that synchronization no longer fails with 'invalid type: map'.

  @AC1
  Scenario: A date field stored as BSON Date deserializes without the 'invalid type: map' error
    Given a document whose date field is stored as a BSON Date (extended JSON map)
    When the document is deserialized
    Then the date field is deserialized
    And no 'invalid type: map' error is raised

  @AC2
  Scenario: A date field stored as an RFC 3339 string still deserializes
    Given a document whose date field is stored as an RFC 3339 string
    When the document is deserialized
    Then the date field is deserialized

  @AC3
  Scenario: A deserialization test covers both forms
    Given a date field stored as a BSON Date (extended JSON map)
    And the same date field stored as an RFC 3339 string
    When the deserialization test runs
    Then both forms are covered by the test
