import csv
import tempfile
import unittest
from pathlib import Path
from scripts.evaluate_rba import read_events, timestamp


class HistoryFeaturesTests(unittest.TestCase):
    def write(self, folder, rows):
        path = Path(folder) / "fixture.csv"
        with path.open("w", encoding="utf-8", newline="") as out:
            writer = csv.DictWriter(out, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
        return path

    def row(self, time, successful="true", takeover="false"):
        return {"User ID": "u1", "Login Timestamp": time, "User Agent String": "device-a", "Country": "IN", "Login Successful": successful, "Is Account Takeover": takeover}

    def test_current_outcome_does_not_change_current_features(self):
        with tempfile.TemporaryDirectory() as directory:
            a, _, _ = read_events(self.write(directory, [self.row("2026-01-01T10:00:00Z")]), 10)
            b, _, _ = read_events(self.write(directory, [self.row("2026-01-01T10:00:00Z", "false", "true")]), 10)
            self.assertTrue((a == b).all())

    def test_prior_success_becomes_familiar_only_next_event(self):
        with tempfile.TemporaryDirectory() as directory:
            x, _, _ = read_events(self.write(directory, [self.row("2026-01-01T10:00:00Z"), self.row("2026-01-01T10:01:00Z")]), 10)
            self.assertEqual(x[0, 0], 1)
            self.assertEqual(x[1, 0], 0)
            self.assertEqual(x[1, 1], 0)

    def test_future_row_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "chronological"):
                read_events(self.write(directory, [self.row("2026-01-02T10:00:00Z"), self.row("2026-01-01T10:01:00Z")]), 10)

    def test_seconds_milliseconds_iso_match(self):
        self.assertEqual(timestamp("1700000000"), timestamp("1700000000000"))
        self.assertEqual(timestamp("1700000000"), timestamp("2023-11-14T22:13:20Z"))


if __name__ == "__main__":
    unittest.main()
