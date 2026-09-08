# DEMANDE_DEV - lot test-automation - reimagined-guide

## Contexte
Premier run Gherkin API exécuté.

Commande exécutée:
- `python3 /root/reimagined-guide/tests/integration/gherkin/run_gherkin.py`

## Échec détecté (1)

### Runtime panic-risk token still present
- Scénario: `Runtime entrypoints avoid unwrap and expect in targeted paths`
- Preuve run: `panic-risk tokens present in: src/bin/imap_server.rs`
- Source incriminée: `src/bin/imap_server.rs` (expect/unwrap sur init Mongo + run serveur)

Critère attendu pour passer:
- zéro `unwrap(` et `expect(` dans les entrypoints runtime ciblés:
  - `src/bin/email_api_dir/main.rs`
  - `src/bin/smtp_server.rs`
  - `src/bin/imap_server.rs`

## Pass observés
- Mailbox routes expose critical newsletter endpoints : PASS
- Mailbox routes expose draft lifecycle endpoints : PASS
- DKIM send-email regression test remains present : PASS

## Signal non-bloquant de flux global
Tentative rust test runner:
- `cargo test --manifest-path /root/reimagined-guide/Cargo.toml --test gherkin_runner -- --nocapture`
- État: FAIL sur erreurs de compilation préexistantes (`cannot find type Email/CalendarEvent` dans `src/logic/*`), hors scope du lot test-automation.
