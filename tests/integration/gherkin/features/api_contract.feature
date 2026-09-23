Feature: reimagined-guide API/UI contract integrity
  As a QA automation tester
  I want executable checks on critical runtime and route contracts
  So that Option A can move with explicit DEMANDE_DEV on failures

  Scenario: Mailbox routes expose critical newsletter endpoints
    Given the source file "src/bin/email_api_dir/startup_routes/mailbox.rs" is loaded
    When I inspect declared API routes
    Then newsletter source and summarize endpoints must exist

  Scenario: Mailbox routes expose draft lifecycle endpoints
    Given the source file "src/bin/email_api_dir/startup_routes/mailbox.rs" is loaded
    When I inspect declared API routes
    Then draft list upsert and delete endpoints must exist

  Scenario: Runtime entrypoints avoid unwrap and expect in targeted paths
    Given the source file "src/bin/email_api_dir/main.rs" is loaded
    And the source file "src/bin/smtp_server.rs" is loaded
    And the source file "src/bin/imap_server.rs" is loaded
    When I inspect runtime panic-risk patterns
    Then targeted runtime files must contain zero unwrap or expect

  Scenario: DKIM send-email regression test remains present
    Given the source file "src/bin/email_api_dir/main_tests/dkim.rs" is loaded
    When I inspect the send email assertions
    Then the test should assert successful response status

  # ============================================================
  # MW-2026-030: CORS reflection + auth bypass (P0, issue #647)
  # ============================================================

  Scenario: MW-2026-030 CORS does not reflect arbitrary Origin
    Given the source file "src/bin/email_api_dir/startup.rs" is loaded
    When I inspect CORS configuration
    Then CORS must use origin whitelist not reflection
    And CORS_ALLOWED_ORIGINS env var must be referenced
    And docker-compose must set CORS_ALLOWED_ORIGINS

  Scenario: MW-2026-031 Admin endpoints require authentication
    Given the source file "src/bin/email_api_dir/admin_auth.rs" is loaded
    When I inspect admin auth enforcement
    Then ADMIN_RBAC_ENFORCE feature flag must exist
    And require_admin must reject when RBAC enabled and no token
    And docker-compose must set ADMIN_RBAC_ENFORCE

