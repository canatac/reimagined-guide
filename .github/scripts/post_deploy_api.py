#!/usr/bin/env python3
"""Post-deploy API checks of reimagined-guide on production (paperclip-fleet#879).

Run by the job post-deploy-smoke of .github/workflows/cicd.yml once the
deploy succeeded. Read-only, with the test account of the operator
(QA_TEST_LOGIN, QA_TEST_PASSWORD); the sending of an email is checked only
when QA_TEST_RECIPIENT, an address of the operator, is set. Only the HTTP
codes are printed, never a body. The failures go to the file given as the
first argument, for post_deploy_report.py.

Standard library only.
"""

from __future__ import annotations

import http.cookiejar
import json
import os
import sys
import urllib.error
import urllib.request

TIMEOUT = 30


class Client:
    """HTTP with the cookies of the session (session_token)."""

    def __init__(self, base: str) -> None:
        self.base = base.rstrip("/")
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def call(self, method: str, path: str, body: dict | None = None) -> tuple[int, dict | None]:
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(self.base + path, data=data, method=method,
                                         headers={"Content-Type": "application/json",
                                                  "Accept": "application/json",
                                                  "User-Agent": "post-deploy-smoke"})
        try:
            with self.opener.open(request, timeout=TIMEOUT) as response:
                return response.status, _json(response.read())
        except urllib.error.HTTPError as error:
            return error.code, _json(error.read())
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            return 0, {"error": type(error).__name__}


def _json(raw: bytes) -> dict | None:
    try:
        value = json.loads(raw or b"null")
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


# (name, method, path, codes expected); the login comes after the health.
HEALTH = [("health live", "GET", "/api/health/live", {200}),
          ("health ready", "GET", "/api/health/ready", {200})]
SIGNED_IN = [("account", "GET", "/api/account", {200}),
             ("unified folders", "GET", "/api/unified/folders", {200}),
             ("external accounts", "GET", "/api/external-accounts", {200}),
             ("provider catalogue", "GET", "/api/external-accounts/oauth2/providers", {200})]


def run(client: Client, login: str, password: str, recipient: str = "") -> list[dict]:
    """The failures of the checks, each {"check", "detail"}; prints one line
    per check."""
    failures = []

    def check(name: str, method: str, path: str, expected: set, body: dict | None = None) -> tuple[int, dict | None]:
        status, payload = client.call(method, path, body)
        ok = status in expected
        print(f"{'PASS' if ok else 'FAIL'}: {name}: {method} {path} -> {status or 'no answer'}", flush=True)
        if not ok:
            failures.append({"check": name, "detail": f"{method} {path} answered {status or 'nothing'}, expected "
                                                      f"{' or '.join(str(c) for c in sorted(expected))}"})
        return status, payload

    for name, method, path, expected in HEALTH:
        check(name, method, path, expected)
    status, _ = check("login", "POST", "/api/auth/login", {200}, {"email": login, "password": password})
    if status == 202:
        failures[-1]["detail"] += ": the test account has 2FA, disable it for the post-deploy checks"
    if status != 200:
        return failures
    for name, method, path, expected in SIGNED_IN:
        check(name, method, path, expected)
    if recipient:
        status, payload = check("send an email", "POST", "/api/compose/send", {200, 202},
                                {"to": [{"email": recipient}], "subject": "Post-deploy check",
                                 "body": "Sent by the post-deploy checks of reimagined-guide."})
        if status in (200, 202) and (payload or {}).get("sent") is False:
            print("FAIL: send an email: answered sent=false", flush=True)
            failures.append({"check": "send an email", "detail": f"POST /api/compose/send answered {status} with "
                                                                  "sent=false"})
    check("logout", "POST", "/api/auth/logout", {200, 204})
    return failures


def main(argv: list[str]) -> int:
    login, password = os.environ.get("QA_TEST_LOGIN", ""), os.environ.get("QA_TEST_PASSWORD", "")
    if not login or not password:
        print("::warning::QA_TEST_LOGIN and QA_TEST_PASSWORD are not set: post-deploy checks skipped")
        return 0
    failures = run(Client(os.environ["QA_BASE_URL"]), login, password, os.environ.get("QA_TEST_RECIPIENT", ""))
    with open(argv[1], "w", encoding="utf-8") as out:
        json.dump(failures, out)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
