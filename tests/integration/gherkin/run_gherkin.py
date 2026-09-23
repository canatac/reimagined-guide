#!/usr/bin/env python3
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[3]
FEATURE = ROOT / "tests/integration/gherkin/features/api_contract.feature"


def parse_feature(text: str):
    scenarios = []
    current = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("Scenario:"):
            if current:
                scenarios.append(current)
            current = {"name": line.split(":", 1)[1].strip(), "steps": []}
            continue
        for prefix in ("Given ", "When ", "Then ", "And "):
            if line.startswith(prefix) and current is not None:
                current["steps"].append(line[len(prefix):].strip())
                break
    if current:
        scenarios.append(current)
    return scenarios


def execute(step: str, ctx: dict):
    m = re.match(r'^the source file "([^"]+)" is loaded$', step)
    if m:
        rel = m.group(1)
        ctx[rel] = (ROOT / rel).read_text()
        return

    if step == "I inspect declared API routes":
        routes = ctx["src/bin/email_api_dir/startup_routes/mailbox.rs"]
        assert "/api/emails" in routes, "missing /api/emails route"
        return

    if step == "newsletter source and summarize endpoints must exist":
        routes = ctx["src/bin/email_api_dir/startup_routes/mailbox.rs"]
        for required in [
            "/api/newsletters/sources",
            "/api/newsletters/sources/{id}",
            "/api/newsletters/sources/{id}/summarize",
            "/api/newsletters/suggestions",
        ]:
            assert required in routes, f"missing route {required}"
        return

    if step == "draft list upsert and delete endpoints must exist":
        routes = ctx["src/bin/email_api_dir/startup_routes/mailbox.rs"]
        for required in ["/api/drafts", "/api/drafts/{id}", "api_drafts_upsert", "api_drafts_delete"]:
            assert required in routes, f"missing draft contract token {required}"
        return

    if step == "I inspect runtime panic-risk patterns":
        return

    if step == "targeted runtime files must contain zero unwrap or expect":
        targets = [
            "src/bin/email_api_dir/main.rs",
            "src/bin/smtp_server.rs",
            "src/bin/imap_server.rs",
        ]
        offenders = []
        for rel in targets:
            content = ctx[rel]
            if re.search(r"unwrap\(|expect\(", content):
                offenders.append(rel)
        assert not offenders, f"panic-risk tokens present in: {', '.join(offenders)}"
        return

    if step == "I inspect the send email assertions":
        dkim = ctx["src/bin/email_api_dir/main_tests/dkim.rs"]
        assert "test_send_email" in dkim, "missing test_send_email"
        return

    if step == "the test should assert successful response status":
        dkim = ctx["src/bin/email_api_dir/main_tests/dkim.rs"]
        assert "assert!(resp.status().is_success())" in dkim, "missing success assertion"
        return

    # MW-2026-022: IMAP external account sync feeds unified inbox
    if step == "I inspect the unified inbox contract":
        return

    if step == "unified inbox must merge native and external account emails":
        unified = ctx["src/bin/email_api_dir/mailbox/unified_handlers.rs"]
        assert "native_to_unified" in unified, "missing native_to_unified converter"
        assert "external_to_unified" in unified, "missing external_to_unified converter"
        assert "sort_unified_by_date" in unified, "missing unified sort"
        return

    if step == "periodic sync worker must be present for external accounts":
        sync = ctx["src/external_imap/periodic_sync.rs"]
        assert "start_periodic_sync" in sync, "missing start_periodic_sync function"
        assert "run_sync_now" in sync, "missing run_sync_now call in periodic worker"
        return

    if step == "unified inbox route must expose external account messages":
        routes = ctx["src/bin/email_api_dir/startup_routes/mailbox.rs"]
        assert "/api/emails/unified" in routes, "missing /api/emails/unified route"
        return

    if step == "external messages must carry account_type and account_email metadata":
        unified = ctx["src/bin/email_api_dir/mailbox/unified_handlers.rs"]
        assert "account_type" in unified, "missing account_type field in unified DTO"
        assert "account_email" in unified, "missing account_email field in unified DTO"
        assert "\"external\"" in unified, "missing external account type tag"
        return

    raise AssertionError(f"no step definition for: {step}")


def main():
    scenarios = parse_feature(FEATURE.read_text())
    assert scenarios, "no scenarios parsed"
    passed = 0
    failed = 0
    failures = []

    for sc in scenarios:
        ctx = {}
        try:
            for step in sc["steps"]:
                execute(step, ctx)
            passed += 1
            print(f"PASS: {sc['name']}")
        except Exception as e:
            failed += 1
            failures.append((sc["name"], str(e)))
            print(f"FAIL: {sc['name']} -> {e}")

    print(f"SUMMARY: passed={passed} failed={failed} total={len(scenarios)}")
    if failures:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
