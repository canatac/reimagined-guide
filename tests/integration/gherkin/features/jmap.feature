Feature: JMAP server implementation (issue #624)
  As a JMAP email client
  I want to discover and interact with the JMAP server
  So that I can sync emails and mailboxes using the modern JMAP protocol

  Scenario: JMAP session discovery endpoint exists
    Given the source file "src/bin/email_api_dir/jmap/mod.rs" is loaded
    When I inspect JMAP route declarations
    Then the /.well-known/jmap endpoint must be registered

  Scenario: JMAP session endpoint exists
    Given the source file "src/bin/email_api_dir/jmap/mod.rs" is loaded
    When I inspect JMAP route declarations
    Then the /jmap/session endpoint must be registered

  Scenario: JMAP API endpoint exists
    Given the source file "src/bin/email_api_dir/jmap/mod.rs" is loaded
    When I inspect JMAP route declarations
    Then the /jmap POST endpoint must be registered

  Scenario: JMAP types module defines core protocol types
    Given the source file "src/bin/email_api_dir/jmap/types.rs" is loaded
    When I inspect JMAP type definitions
    Then JmapSession type must be present
    And JmapCapabilities type must be present
    And JmapEmail type must be present
    And JmapMailbox type must be present

  Scenario: JMAP handlers implement required methods
    Given the source file "src/bin/email_api_dir/jmap/handlers.rs" is loaded
    When I inspect JMAP method handlers
    Then Email/get handler must be present
    And Email/query handler must be present
    And Mailbox/get handler must be present
    And Mailbox/set handler must be present

  Scenario: JMAP routes registered in startup_routes
    Given the source file "src/bin/email_api_dir/startup_routes/mod.rs" is loaded
    When I inspect startup route registration
    Then jmap module must be included

  Scenario: JMAP routes registered in HTTP config
    Given the source file "src/bin/email_api_dir/startup.rs" is loaded
    When I inspect HTTP route configuration
    Then register_jmap_routes must be called

  Scenario: JMAP well-known discovery returns capability document
    Given the source file "src/bin/email_api_dir/jmap/handlers.rs" is loaded
    When I inspect the well-known handler
    Then it must return apiUrl
    And it must return authenticationUrl
    And it must include urn:ietf:params:jmap:core capability
    And it must include urn:ietf:params:jmap:mail capability

  Scenario: JMAP session handler requires authentication
    Given the source file "src/bin/email_api_dir/jmap/handlers.rs" is loaded
    When I inspect the session handler
    Then it must check Authorization header
    And it must check session_token cookie

  Scenario: JMAP API handler dispatches method calls
    Given the source file "src/bin/email_api_dir/jmap/handlers.rs" is loaded
    When I inspect the API handler
    Then it must dispatch Email/get
    And it must dispatch Email/query
    And it must dispatch Email/set
    And it must dispatch Mailbox/get
    And it must dispatch Mailbox/set
