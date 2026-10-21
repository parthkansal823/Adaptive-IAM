"""Local expiry must hold even while a live grant check takes time."""
import unittest
from unittest.mock import Mock, patch

from backend.app.store import Store


class GrantSelectionClockTests(unittest.TestCase):
    def test_fallback_expiring_during_preceding_rpc_is_never_checked(self):
        grants = [
            {"id": "replacement", "expires_at": "2026-10-17T12:30:00+00:00"},
            {"id": "older", "expires_at": "2026-10-17T12:01:00+00:00"},
        ]
        db = Mock()
        db.execute.return_value.fetchall.return_value = grants
        clock = ["2026-10-17T12:00:00+00:00"]
        def pending_check(grant):
            clock[0] = grants[1]["expires_at"]
            return {"required": True, "allowed": False, "status": "pending_or_expired"}
        blockchain = Mock(enabled=True, check_grant=Mock(side_effect=pending_check))
        with patch("backend.app.store.stamp", side_effect=lambda: clock[0]):
            grant, chain = Store.active_grant(None, db, "subject", "resource", blockchain)
        self.assertFalse(chain["allowed"])
        self.assertEqual(grant["id"], "replacement")
        self.assertEqual(blockchain.check_grant.call_count, 1)

    def test_grant_expiring_inside_successful_rpc_is_never_returned(self):
        grant = {"id": "confirmed", "expires_at": "2026-10-17T12:01:00+00:00"}
        db = Mock()
        db.execute.return_value.fetchall.return_value = [grant]
        clock = ["2026-10-17T12:00:00+00:00"]
        def confirmed_check(candidate):
            clock[0] = candidate["expires_at"]
            return {"required": True, "allowed": True, "status": "confirmed"}
        blockchain = Mock(enabled=True, check_grant=Mock(side_effect=confirmed_check))
        with patch("backend.app.store.stamp", side_effect=lambda: clock[0]):
            selected, chain = Store.active_grant(None, db, "subject", "resource", blockchain)
        self.assertIsNone(selected)
        self.assertFalse(chain["allowed"])


if __name__ == "__main__":
    unittest.main()
