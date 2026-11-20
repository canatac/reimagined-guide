# language: en
# Issue #740: Default branch master is red: Build & Push SMTP image (SCW Registry)

Feature: Build & Push SMTP image (SCW Registry) is green on master
  The default branch master has a red check, Build & Push SMTP image
  (SCW Registry), which blocks the team: a red default branch cannot be
  distinguished from a regression caused by a merge. The check must be
  green on master, corrected without storing any secret in the
  repository, and stay green after a merge.

  @AC1
  Scenario: The Build & Push SMTP image (SCW Registry) check is green on master
    Given the default branch master of reimagined-guide
    When the Build & Push SMTP image (SCW Registry) check runs on master
    Then the check is green

  @AC2
  Scenario: The registry credentials or the push configuration are corrected without storing any secret in the repository
    Given the Build & Push SMTP image (SCW Registry) workflow configuration
    When the registry credentials or the push configuration are corrected
    Then no secret, token or password is stored in the repository

  @AC3
  Scenario: A merge no longer leaves master red for this check
    Given a pull request merged into master
    When the Build & Push SMTP image (SCW Registry) check runs on master after the merge
    Then master is not left red for this check
