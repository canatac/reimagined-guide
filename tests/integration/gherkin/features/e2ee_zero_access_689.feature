Feature: Zero-access end-to-end encryption (issue #689)
  As a privacy-conscious user
  I want client-side end-to-end encryption for my emails
  So that the server cannot read my plaintext emails (zero-knowledge architecture)

  Scenario: E2EE enable endpoint exists
    Given the source file "src/bin/email_api_dir/startup_routes/e2e.rs" is loaded
    When I inspect E2E route declarations
    Then the /api/v1/e2e/enable endpoint must be registered

  Scenario: E2EE status endpoint exists
    Given the source file "src/bin/email_api_dir/startup_routes/e2e.rs" is loaded
    When I inspect E2E route declarations
    Then the /api/v1/e2e/status endpoint must be registered

  Scenario: E2EE rotate endpoint exists
    Given the source file "src/bin/email_api_dir/startup_routes/e2e.rs" is loaded
    When I inspect E2E route declarations
    Then the /api/v1/e2e/rotate endpoint must be registered

  Scenario: E2EE recover endpoint exists
    Given the source file "src/bin/email_api_dir/startup_routes/e2e.rs" is loaded
    When I inspect E2E route declarations
    Then the /api/v1/e2e/recover endpoint must be registered

  Scenario: E2EE recovery-phrase endpoint exists
    Given the source file "src/bin/email_api_dir/startup_routes/e2e.rs" is loaded
    When I inspect E2E route declarations
    Then the /api/v1/e2e/recovery-phrase endpoint must be registered

  Scenario: E2EE disable endpoint exists
    Given the source file "src/bin/email_api_dir/startup_routes/e2e.rs" is loaded
    When I inspect E2E route declarations
    Then the /api/v1/e2e/disable endpoint must be registered

  Scenario: E2EE validate-blob endpoint exists
    Given the source file "src/bin/email_api_dir/startup_routes/e2e.rs" is loaded
    When I inspect E2E route declarations
    Then the /api/v1/e2e/validate-blob endpoint must be registered

  Scenario: E2EE routes registered in startup
    Given the source file "src/bin/email_api_dir/startup.rs" is loaded
    When I inspect HTTP route configuration
    Then register_e2e_routes must be called

  Scenario: E2EE routes registered in startup_routes mod
    Given the source file "src/bin/email_api_dir/startup_routes/mod.rs" is loaded
    When I inspect startup_routes module declarations
    Then e2e module must be included

  Scenario: E2EE enable requires encrypted_private_key
    Given the source file "src/bin/email_api_dir/startup_routes/e2e.rs" is loaded
    When I inspect the enable request struct
    Then E2EEnableRequest must have encrypted_private_key field

  Scenario: E2EE enable requires public_key
    Given the source file "src/bin/email_api_dir/startup_routes/e2e.rs" is loaded
    When I inspect the enable request struct
    Then E2EEnableRequest must have public_key field

  Scenario: E2EE status response indicates e2e_enabled
    Given the source file "src/bin/email_api_dir/startup_routes/e2e.rs" is loaded
    When I inspect the status response struct
    Then E2EStatusResponse must have e2e_enabled field

  Scenario: E2EE key record uses zero-knowledge architecture
    Given the source file "src/security/e2e.rs" is loaded
    When I inspect E2EKeyRecord
    Then encrypted_private_key must be base64 ciphertext only
    And public_key may be plaintext
    And no plaintext private key field exists

  Scenario: E2EE recovery phrase generation available
    Given the source file "src/security/e2e.rs" is loaded
    When I inspect E2E utility functions
    Then generate_recovery_phrase must be public

  Scenario: E2EE blob validation available
    Given the source file "src/security/e2e.rs" is loaded
    When I inspect E2E utility functions
    Then validate_encrypted_blob must be public
