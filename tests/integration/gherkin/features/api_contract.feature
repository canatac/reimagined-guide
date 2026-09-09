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

  Scenario: TLS-RPT aggregation module exposes report ingestion endpoint
    Given the source file "src/monitoring/mod.rs" is loaded
    When I inspect declared monitoring routes
    Then POST /api/v1/tls-rpt/reports endpoint must exist

  Scenario: DMARC aggregate report parsing exposes stats endpoint
    Given the source file "src/monitoring/dmarc.rs" is loaded
    When I inspect declared DMARC routes
    Then GET /api/v1/dmarc/stats endpoint must exist
