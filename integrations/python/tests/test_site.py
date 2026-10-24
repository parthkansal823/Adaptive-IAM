"""HTTP regressions for the memory-only Python relying-party example."""
from __future__ import annotations

from datetime import datetime, timezone
import importlib
import os
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from urllib.parse import urlencode

from fastapi.testclient import TestClient

from integrations.python.adaptive_iam import SiteSession


class SiteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with patch.dict(os.environ, {"IAM_CLIENT_ID": "fixture-client", "IAM_ISSUER": "https://iam.example", "SITE_ORIGIN": "https://website.example"}):
            cls.site = importlib.import_module("integrations.examples.fastapi_site")

    def setUp(self):
        self.now = 1_800_000_000.0
        self.site.flows.clear()
        self.site.sessions.clear()
        self.client = SimpleNamespace(issuer="https://iam.example", exchange_code=Mock(), permission=Mock(), revoke=Mock())
        self.patches = [patch.object(self.site, "client", self.client), patch.object(self.site, "time", SimpleNamespace(time=lambda: self.now))]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)
        self.browser = TestClient(self.site.app)
        self.addCleanup(self.browser.close)

    def access(self):
        return {"identity": {"sub": "aisha"}, "resource_id": "research-vault", "expires_at": datetime.fromtimestamp(self.now+60, timezone.utc).isoformat()}

    def session(self):
        self.site.sessions["fixture-session"] = SiteSession("fixture-token", {"sub": "aisha"}, self.now+60)
        self.browser.cookies.set("iam_site_session", "fixture-session")

    def callback(self, **changes):
        self.site.flows["fixture-flow"] = {"state": "fixture-state", "nonce": "fixture-nonce", "verifier": "v"*43, "expires_at": self.now+300}
        self.browser.cookies.set("iam_login", "fixture-flow")
        return "/callback?"+urlencode({"state": "fixture-state", "iss": self.client.issuer, "code": "fixture-code", **changes})

    def test_duplicate_callback_fields_are_rejected_and_flow_consumed(self):
        for name in ("state", "iss", "code", "error"):
            path = self.callback(**({"error": "access_denied"} if name == "error" else {}))+"&"+name+"=duplicate"
            response = self.browser.get(path)
            self.assertEqual(response.status_code, 401)
            self.assertEqual(response.json()["error"], "invalid_callback_parameters")
            self.assertNotIn("fixture-flow", self.site.flows)
        self.client.exchange_code.assert_not_called()

    def test_non_ascii_state_and_empty_error_fail_before_exchange(self):
        for changes in ({"state": "\u00e9"}, {"error": ""}):
            response = self.browser.get(self.callback(**changes))
            self.assertEqual(response.status_code, 401)
        self.client.exchange_code.assert_not_called()

    def test_live_session_and_grant_allow_protected_record(self):
        self.session()
        self.client.permission.return_value = self.access()
        response = self.browser.get("/protected")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["user"], "aisha")
        self.assertNotIn("fixture-token", response.text)

    def test_logout_during_permission_call_removes_response_authority(self):
        self.session()

        def permission(*_):
            access = self.access()
            response = self.browser.post("/logout", headers={"Origin": "https://website.example"}, follow_redirects=False)
            self.assertEqual(response.status_code, 303)
            return access

        self.client.permission.side_effect = permission
        response = self.browser.get("/protected")
        self.assertEqual(response.status_code, 401)
        self.assertNotIn("Your site returned", response.text)
        self.client.revoke.assert_called_once()

    def test_session_or_grant_expiring_during_permission_call_denies_content(self):
        for session_expiry in (True, False):
            self.session()

            def permission(*_):
                access = self.access()
                if session_expiry:
                    self.now += 60
                else:
                    access["expires_at"] = datetime.fromtimestamp(self.now, timezone.utc).isoformat()
                return access

            self.client.permission.side_effect = permission
            response = self.browser.get("/protected")
            self.assertEqual(response.status_code, 401 if session_expiry else 403)
            self.assertNotIn("Your site returned", response.text)


if __name__ == "__main__":
    unittest.main()
