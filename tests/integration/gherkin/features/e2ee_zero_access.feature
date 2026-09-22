Feature: Zero-access E2EE (End-to-End Encryption) — Issue #600
  As a privacy-focused user
  I want client-side encryption so the server cannot read my emails
  So that my data remains private even if the server is compromised

  Scenario: E2EE enable endpoint exists
    Given the source file "src/bin/email_api_dir/startup_routes/e2e.rs" is loaded
    When I inspect declared API routes
    Then the "/api/v1/e2e/enable" endpoint must exist

  Scenario: E2EE status endpoint exists
    Given the source file "src/bin/email_api_dir/startup_routes/e2e.rs" is loaded
    When I inspect declared API routes
    Then the "/api/v1/e2e/status/{user_id}" endpoint must exist

  Scenario: E2EE rotate endpoint exists
    Given the source file "src/bin/email_api_dir/startup_routes/e2e.rs" is loaded
    When I inspect declared API routes
    Then the "/api/v1/e2e/rotate" endpoint must exist

  Scenario: E2EE recover endpoint exists
    Given the source file "src/bin/email_api_dir/startup_routes/e2e.rs" is loaded
    When I inspect declared API routes
    Then the "/api/v1/e2e/recover" endpoint must exist

  Scenario: E2EE recovery-phrase endpoint exists
    Given the source file "src/bin/email_api_dir/startup_routes/e2e.rs" is loaded
    When I inspect declared API routes
    Then the "/api/v1/e2e/recovery-phrase" endpoint must exist

  Scenario: E2EE disable endpoint exists
    Given the source file "src/bin/email_api_dir/startup_routes/e2e.rs" is loaded
    When I inspect declared API routes
    Then the "/api/v1/e2e/disable/{user_id}" endpoint must exist

  Scenario: E2EE validate-blob endpoint exists
    Given the source file "src/bin/email_api_dir/startup_routes/e2e.rs" is loaded
    When I inspect declared API routes
    Then the "/api/v1/e2e/validate-blob" endpoint must exist

  Scenario: E2EE routes are registered in startup
    Given the source file "src/bin/email_api_dir/startup.rs" is loaded
    When I inspect route registration calls
    Then register_e2e_routes must be called

  Scenario: E2EE handler module exists
    Given the source file "src/bin/email_api_dir/monitoring_handlers/e2e.rs" is loaded
    When I inspect the module
    Then api_e2e_enable must be defined
    And api_e2e_status must be defined
    And api_e2e_rotate must be defined
    And api_e2e_recover must be defined

  Scenario: E2EE zero-knowledge principle enforced
    Given the source file "src/security/e2e.rs" is loaded
    When I inspect the E2E module
    Then encrypted_private_key field must exist in E2EKeyRecord
    And e2e_enabled field must exist in E2EKeyRecord
