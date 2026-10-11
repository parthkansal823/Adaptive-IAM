import csv
import tempfile
import unittest
from pathlib import Path
from scripts.evaluate_rba import read_events, timestamp, partitions, evaluate


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

    def test_hash_cohorts_are_disjoint_and_stable_for_repeat_users(self):
        users=[f'user-{i%200}' for i in range(1000)]
        first=partitions(users,'user-disjoint')
        second=partitions(users,'user-disjoint')
        self.assertEqual(sorted(i for part in first for i in part),list(range(1000)))
        for i in range(4):
            self.assertTrue((first[i]==second[i]).all())
            self.assertGreater(len(first[i]),0)
            for j in range(i+1,4):
                self.assertFalse({users[k] for k in first[i]} & {users[k] for k in first[j]})

    def test_proxy_label_is_explicit_and_never_a_feature(self):
        with tempfile.TemporaryDirectory() as directory:
            row=self.row('2026-01-01T10:00:00Z')
            row['Is Attack IP']='true'
            path=self.write(directory,[row])
            x,y,_=read_events(path,10)
            xp,yp,_=read_events(path,10,label='Is Attack IP')
            self.assertEqual(y.tolist(),[0])
            self.assertEqual(yp.tolist(),[1])
            self.assertTrue((x==xp).all())

    def test_missing_class_fails_before_training(self):
        with tempfile.TemporaryDirectory() as directory:
            rows=[self.row(str(1700000000+i)) for i in range(100)]
            with self.assertRaisesRegex(ValueError,'partition needs both classes'):
                evaluate(self.write(directory,rows),100)


if __name__ == "__main__":
    unittest.main()
