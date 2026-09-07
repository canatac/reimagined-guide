# Test Changelog - lot test-automation

## v0.1.0
- Added Gherkin feature file for backend route/runtime guards.
- Added executable harness checks on:
  - newsletters + drafts route contracts
  - panic-risk tokens (unwrap/expect) in targeted runtime entrypoints
  - DKIM send-email regression assertion presence
- First run commands:
  - python3 /root/reimagined-guide/tests/integration/gherkin/run_gherkin.py
  - cargo test --manifest-path /root/reimagined-guide/Cargo.toml --test gherkin_runner -- --nocapture
