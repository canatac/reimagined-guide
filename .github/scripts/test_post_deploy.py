"""Tests of the post-deploy checks and of their report (paperclip-fleet#879),
on a fake server: no network. python3 -m unittest discover -s .github/scripts"""

from __future__ import annotations

import http.server
import json
import sys
import threading
import unittest
import urllib.error
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import post_deploy_api as api  # noqa: E402
import post_deploy_report as rep  # noqa: E402


class Fake(http.server.BaseHTTPRequestHandler):
    """The API of production: CODES by path, the session cookie set by the
    login and required after it."""
    codes: dict = {}
    calls: list = []
    bodies: list = []
    cookies: list = []

    def log_message(self, *_):
        pass

    def _answer(self, method: str) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length)) if length else None
        Fake.calls.append((method, self.path))
        Fake.bodies.append(body)
        default = (200, {"session": {"id": "s1", "access_token": "t", "user": {"email": "qa@example.org"}}}) \
            if self.path == "/api/auth/login" else (200, {})
        code, payload = Fake.codes.get(self.path, default)
        # As the backend behind misfits-web (paperclip-fleet#886): the token
        # of the login in Authorization, and the email of the user.
        signed = (self.headers.get("Authorization") == "Bearer t"
                  and self.headers.get("x-user-email") == "qa@example.org")
        if self.path not in ("/api/auth/login", "/api/health/live") and not signed:
            code, payload = 401, {"message": "no session"}
        # As the middleware of misfits-web on the routes Caddy gives it
        # (reimagined-guide#841, #842): the cookie mfa_session, which the
        # browser sets itself once signed in.
        Fake.cookies.append(self.headers.get("Cookie") or "")
        if self.path.startswith("/api/external-accounts") and "mfa_session=" not in (self.headers.get("Cookie") or ""):
            code, payload = 401, {"error": "Unauthorized"}
        data = json.dumps(payload).encode()
        self.send_response(code)
        if self.path == "/api/auth/login" and code == 200:
            self.send_header("Set-Cookie", "session_token=t; Path=/")
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self._answer("GET")

    def do_POST(self):
        self._answer("POST")


class Checks(unittest.TestCase):
    def setUp(self):
        Fake.codes, Fake.calls, Fake.bodies, Fake.cookies = {}, [], [], []
        self.server = http.server.HTTPServer(("127.0.0.1", 0), Fake)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.client = api.Client(f"http://127.0.0.1:{self.server.server_address[1]}")

    def test_all_green_reads_only_and_signs_out(self):
        self.assertEqual(api.run(self.client, "qa@example.org", "pw"), [])
        self.assertEqual([c for c in Fake.calls if c[0] == "POST"],
                         [("POST", "/api/auth/login"), ("POST", "/api/auth/logout")])
        self.assertIn(("GET", "/api/external-accounts/oauth2/providers"), Fake.calls)

    def test_a_failing_check_is_named_with_its_code_never_its_body(self):
        # reimagined-guide#784: the provider catalogue in 500.
        Fake.codes["/api/external-accounts/oauth2/providers"] = (500, {"message": "secret detail"})
        failures = api.run(self.client, "qa@example.org", "pw")
        self.assertEqual(failures, [{"check": "provider catalogue", "detail":
                                     "GET /api/external-accounts/oauth2/providers answered 500, expected 200"}])
        self.assertNotIn("secret detail", json.dumps(failures))

    def test_a_refused_login_stops_the_checks(self):
        Fake.codes["/api/auth/login"] = (401, {"message": "invalid"})
        failures = api.run(self.client, "qa@example.org", "pw")
        self.assertEqual([f["check"] for f in failures], ["login"])
        self.assertNotIn(("GET", "/api/unified/folders"), Fake.calls)
        Fake.codes["/api/auth/login"] = (202, {"requires_2fa": True})
        self.assertTrue(api.run(self.client, "qa@example.org", "pw")[0]["detail"].endswith("disable it for the "
                                                                                            "post-deploy checks"))

    def test_an_email_is_sent_only_to_the_recipient_given(self):
        api.run(self.client, "qa@example.org", "pw")
        self.assertNotIn(("POST", "/api/compose/send"), Fake.calls)
        # reimagined-guide#783: the DKIM service unreachable, 503.
        Fake.codes["/api/compose/send"] = (503, {"sent": False, "retryable": True})
        failures = api.run(self.client, "qa@example.org", "pw", "me@example.org")
        self.assertEqual([f["check"] for f in failures], ["send an email"])
        sent = Fake.bodies[Fake.calls.index(("POST", "/api/compose/send"))]
        self.assertEqual(sent["to"], [{"email": "me@example.org"}])
        Fake.codes["/api/compose/send"] = (200, {"sent": False})
        self.assertEqual(api.run(self.client, "qa@example.org", "pw", "me@example.org")[0]["detail"],
                         "POST /api/compose/send answered 200 with sent=false")

    def test_the_checks_passed_and_only_them(self):
        # paperclip-fleet#884: the provider catalogue in 500, an email sent
        # with sent=false: neither passed; after a refused login, the checks
        # not run are not either.
        Fake.codes["/api/external-accounts/oauth2/providers"] = (500, {})
        Fake.codes["/api/compose/send"] = (200, {"sent": False})
        passed = []
        api.run(self.client, "qa@example.org", "pw", "me@example.org", passed)
        self.assertEqual(passed, ["health live", "login", "unified folders", "external accounts", "logout"])
        Fake.codes["/api/auth/login"] = (401, {})
        passed = []
        api.run(api.Client(self.client.base), "qa@example.org", "pw", "", passed)
        self.assertEqual(passed, ["health live"])

    def test_signed_in_as_the_browser(self):
        # paperclip-fleet#886: the session cookie alone answered 401 on
        # /api/external-accounts in production; the browser sends the
        # accessToken of the login. Without one, the login fails.
        self.assertEqual(api.run(self.client, "qa@example.org", "pw"), [])
        self.assertNotIn(("GET", "/api/account"), Fake.calls)
        self.assertNotIn(("GET", "/api/health/ready"), Fake.calls)
        # paperclip-fleet#887: the session in "session", camelCase too.
        Fake.codes["/api/auth/login"] = (200, {"session": {"accessToken": "t", "user": {"email": "qa@example.org"}}})
        self.assertEqual(api.run(api.Client(self.client.base), "qa@example.org", "pw"), [])
        for answer, detail in (({"accessToken": "t", "user": {"email": "qa@example.org"}},
                                "no session with an access token in its answer"),
                               ({"twoFactorRequired": True, "challengeId": "c", "expiresIn": 300},
                                "the test account has 2FA, disable it for the post-deploy checks")):
            Fake.codes["/api/auth/login"] = (200, answer)
            passed = []
            failures = api.run(api.Client(self.client.base), "qa@example.org", "pw", "", passed)
            self.assertEqual(failures, [{"check": "login", "detail": f"POST /api/auth/login answered 200: {detail}"}])
            self.assertEqual(passed, ["health live"])

    def test_the_session_cookie_of_the_browser_is_sent(self):
        # reimagined-guide#841, #842: GET /api/external-accounts and its
        # provider catalogue answered 401 on production, the middleware of
        # misfits-web reading the cookie mfa_session the browser sets once
        # signed in; the session id, as the browser.
        self.assertEqual(api.run(self.client, "qa@example.org", "pw"), [])
        at = Fake.calls.index(("GET", "/api/external-accounts"))
        self.assertIn("mfa_session=s1", Fake.cookies[at])
        self.assertNotIn("mfa_session", Fake.cookies[Fake.calls.index(("POST", "/api/auth/login"))])
        # Without a session id in the answer: its access token.
        Fake.codes["/api/auth/login"] = (200, {"session": {"accessToken": "t", "user": {"email": "qa@example.org"}}})
        Fake.calls, Fake.cookies = [], []
        self.assertEqual(api.run(api.Client(self.client.base), "qa@example.org", "pw"), [])
        self.assertIn("mfa_session=t", Fake.cookies[Fake.calls.index(("GET", "/api/external-accounts"))])

    def test_no_answer_is_a_failure(self):
        client = api.Client("http://127.0.0.1:9")
        failures = api.run(client, "qa@example.org", "pw")
        self.assertEqual(failures[0]["detail"], "GET /api/health/live answered nothing, expected 200")

    def test_without_the_account_it_is_skipped(self):
        for name in ("QA_TEST_LOGIN", "QA_TEST_PASSWORD"):
            api.os.environ.pop(name, None)
        self.assertEqual(api.main(["x", "/nonexistent/out.json"]), 0)


class FakeGitHub:
    def __init__(self, open_issues=(), types=True):
        self.open_issues, self.types, self.calls, self.labelled = list(open_issues), types, [], False

    def call(self, method, path, body=None):
        self.calls.append((method, path, body))
        if path == "/labels":
            if self.labelled:
                raise urllib.error.HTTPError(path, 422, "exists", {}, None)
            self.labelled = True
            return {}
        if method == "GET":
            return self.open_issues
        if path == "/issues" and "type" in body and not self.types:
            raise urllib.error.HTTPError(path, 422, "no types", {}, None)
        return {"number": 900 + len(self.calls)}


class Report(unittest.TestCase):
    FAILURE = {"check": "provider catalogue", "detail": "GET x answered 500 for qa@example.org / hunter2"}

    def test_a_new_failure_opens_a_critical_bug_without_the_secrets(self):
        github = FakeGitHub()
        done = rep.report(github, [self.FAILURE], "a" * 40, "https://run", ["qa@example.org", "hunter2", ""])
        method, path, body = github.calls[-1]
        self.assertEqual((method, path, body["type"], body["labels"]),
                         ("POST", "/issues", "Bug", ["priority-P1", "priority:high", "post-deploy"]))
        self.assertEqual(body["title"], "Post-deploy check failed: provider catalogue")
        self.assertIn("## Acceptance criteria\n- The post-deploy check \"provider catalogue\" passes", body["body"])
        self.assertIn("aaaaaaaaaaaa", body["body"])
        self.assertNotIn("hunter2", json.dumps(github.calls))
        self.assertNotIn("qa@example.org", json.dumps(github.calls))
        self.assertTrue(done[0].endswith("opened: provider catalogue"))

    def test_still_open_it_is_commented(self):
        github = FakeGitHub([{"number": 7, "title": "Post-deploy check failed: provider catalogue"},
                             {"number": 8, "title": "Post-deploy check failed: provider catalogue",
                              "pull_request": {}}])
        self.assertEqual(rep.report(github, [self.FAILURE], "b" * 40, "https://run", []),
                         ["#7 commented: provider catalogue"])
        self.assertEqual(github.calls[-1][1], "/issues/7/comments")

    def test_without_issue_types_it_opens_it_all_the_same(self):
        github = FakeGitHub(types=False)
        github.labelled = True
        rep.report(github, [self.FAILURE], "c" * 40, "", [])
        self.assertNotIn("type", github.calls[-1][2])
        self.assertEqual(github.calls[-1][2]["labels"][0], "priority-P1")

    def test_a_check_that_passes_closes_its_issue(self):
        # paperclip-fleet#884: its acceptance criterion met; a check failed
        # again or not passed keeps its issue open; a pull request never.
        github = FakeGitHub([{"number": 7, "title": "Post-deploy check failed: send an email"},
                             {"number": 8, "title": "Post-deploy check failed: provider catalogue"},
                             {"number": 9, "title": "Post-deploy check failed: account"},
                             {"number": 10, "title": "Post-deploy check failed: send an email", "pull_request": {}}])
        done = rep.report(github, [self.FAILURE], "d" * 40, "https://run", [], ["login", "send an email",
                                                                                  "provider catalogue"])
        self.assertEqual(done, ["#8 commented: provider catalogue", "#7 closed: send an email"])
        self.assertEqual(github.calls[-1], ("PATCH", "/issues/7", {"state": "closed", "state_reason": "completed"}))
        self.assertIn("its acceptance criterion is met, closed", github.calls[-2][2]["body"])
        github = FakeGitHub([{"number": 7, "title": "Post-deploy check failed: account"}])
        self.assertEqual(rep.report(github, [], "e" * 40, "", [], ["account"]), ["#7 closed: account"])
        self.assertNotIn("/labels", [path for _, path, _ in github.calls])

    def test_the_file_of_the_checks_old_or_new(self):
        out = Path(__file__).parent / "_report_test.json"
        self.addCleanup(lambda: out.unlink(missing_ok=True))
        for found in ([], {"failures": [], "passed": []}):
            out.write_text(json.dumps(found))
            self.assertEqual(rep.main(["x", str(out)]), 0)
        # Without the account: the file written empty, nothing to report.
        for name in ("QA_TEST_LOGIN", "QA_TEST_PASSWORD"):
            api.os.environ.pop(name, None)
        self.assertEqual(api.main(["x", str(out)]), 0)
        self.assertEqual(json.loads(out.read_text()), {"failures": [], "passed": []})


if __name__ == "__main__":
    unittest.main()
