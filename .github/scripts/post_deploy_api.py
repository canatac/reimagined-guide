#!/usr/bin/env python3
"""Post-deploy API checks of reimagined-guide on production (paperclip-fleet#879).

Run by the job post-deploy-smoke of .github/workflows/cicd.yml once the
deploy succeeded. Read-only, with the test account of the operator
(QA_TEST_LOGIN, QA_TEST_PASSWORD); the sending of an email is checked only
when QA_TEST_RECIPIENT, an address of the operator, is set. Only the HTTP
codes are printed, never a body. The failures and the checks passed go to
the file given as the first argument, {"failures": [...], "passed": [...]},
for post_deploy_report.py (paperclip-fleet#884).

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
    """HTTP as the browser of misfits-web signs its calls (src/lib/api-client.ts,
    paperclip-fleet#886): the cookies of the session, and once signed in
    Authorization: Bearer <accessToken of the login> and x-user-email."""

    def __init__(self, base: str) -> None:
        self.base = base.rstrip("/")
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.signed: dict = {}

    def sign_in(self, token: str, email: str) -> None:
        self.signed = {"Authorization": f"Bearer {token}", "x-user-email": email}

    def call(self, method: str, path: str, body: dict | None = None) -> tuple[int, dict | None]:
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(self.base + path, data=data, method=method,
                                         headers={"Content-Type": "application/json",
                                                  "Accept": "application/json",
                                                  "User-Agent": "post-deploy-smoke", **self.signed})
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
# Only routes the domain serves (paperclip-fleet#886): no /api/health/ready,
# and /api/account answers DELETE only (the deletion of the account).
HEALTH = [("health live", "GET", "/api/health/live", {200})]
SIGNED_IN = [("unified folders", "GET", "/api/unified/folders", {200}),
             ("external accounts", "GET", "/api/external-accounts", {200}),
             ("provider catalogue", "GET", "/api/external-accounts/oauth2/providers", {200})]


def run(client: Client, login: str, password: str, recipient: str = "", passed: list | None = None) -> list[dict]:
    """The failures of the checks, each {"check", "detail"}; prints one line
    per check. PASSED, given, gets the names of the checks passed, whose
    issue the report closes (paperclip-fleet#884); a check not run is not."""
    failures = []
    done = [] if passed is None else passed

    def check(name: str, method: str, path: str, expected: set, body: dict | None = None) -> tuple[int, dict | None]:
        status, payload = client.call(method, path, body)
        ok = status in expected
        print(f"{'PASS' if ok else 'FAIL'}: {name}: {method} {path} -> {status or 'no answer'}", flush=True)
        if ok:
            done.append(name)
        else:
            failures.append({"check": name, "detail": f"{method} {path} answered {status or 'nothing'}, expected "
                                                      f"{' or '.join(str(c) for c in sorted(expected))}"})
        return status, payload

    for name, method, path, expected in HEALTH:
        check(name, method, path, expected)
    status, payload = check("login", "POST", "/api/auth/login", {200}, {"email": login, "password": password})
    if status == 202:
        failures[-1]["detail"] += ": the test account has 2FA, disable it for the post-deploy checks"
    if status != 200:
        return failures
    # The answer of the login, as misfits-web reads it (src/types/auth.ts,
    # LoginResponse; paperclip-fleet#887): {"session": {accessToken, user:
    # {email}}}, its keys camelCase or snake_case; or a challenge of 2FA,
    # {twoFactorRequired: true}, answered 200 too.
    payload = payload or {}
    session = payload.get("session") if isinstance(payload.get("session"), dict) else {}
    token = session.get("accessToken") or session.get("access_token")
    why = ("the test account has 2FA, disable it for the post-deploy checks"
           if payload.get("twoFactorRequired") or payload.get("two_factor_required")
           else None if isinstance(token, str) and token else "no session with an access token in its answer")
    if why:
        print(f"FAIL: login: {why}", flush=True)
        done.remove("login")
        failures.append({"check": "login", "detail": f"POST /api/auth/login answered 200: {why}"})
        return failures
    user = session.get("user")
    client.sign_in(token, (user.get("email") if isinstance(user, dict) else None) or login)
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
            done.remove("send an email")
    check("logout", "POST", "/api/auth/logout", {200, 204})
    return failures


def main(argv: list[str]) -> int:
    login, password = os.environ.get("QA_TEST_LOGIN", ""), os.environ.get("QA_TEST_PASSWORD", "")
    if not login or not password:
        print("::warning::QA_TEST_LOGIN and QA_TEST_PASSWORD are not set: post-deploy checks skipped")
        failures, passed = [], []
    else:
        passed = []
        failures = run(Client(os.environ["QA_BASE_URL"]), login, password, os.environ.get("QA_TEST_RECIPIENT", ""),
                       passed)
    try:
        with open(argv[1], "w", encoding="utf-8") as out:
            json.dump({"failures": failures, "passed": passed}, out)
    except OSError:
        if failures or passed:
            raise
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
