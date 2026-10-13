import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("release_gate", Path(__file__).parents[2] / "scripts/deploy/check-release.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class ReleaseGateTest(unittest.TestCase):
    def runs(self):
        return [{"path": path, "id": i, "head_sha": "a" * 40, "event": "push",
                 "head_branch": "main", "head_repository": {"full_name": gate.REPOSITORY},
                 "status": "completed", "conclusion": "success"}
                for i, path in enumerate(sorted(gate.REQUIRED))]

    def test_requires_all_checks_on_exact_sha(self):
        self.assertTrue(gate.check_runs(self.runs(), "a" * 40))
        self.assertFalse(gate.check_runs(self.runs(), "b" * 40))
        self.assertFalse(gate.check_runs(self.runs()[:-1], "a" * 40))

    def test_rejects_failed_cancelled_and_skipped_checks(self):
        for conclusion in ("failure", "cancelled", "skipped", "timed_out", "neutral"):
            runs = self.runs()
            runs[0]["conclusion"] = conclusion
            with self.assertRaises(RuntimeError):
                gate.check_runs(runs, "a" * 40)

    def test_ignores_pr_fork_branch_and_scheduled_runs(self):
        for key, value in (("event", "pull_request"), ("event", "schedule"),
                           ("head_branch", "feature"), ("head_repository", {"full_name": "fork/blaksoc"})):
            runs = self.runs()
            runs[0][key] = value
            self.assertFalse(gate.check_runs(runs, "a" * 40))

    def test_waits_for_latest_run_instead_of_old_success(self):
        runs = self.runs()
        runs.append(dict(runs[0], id=100, status="in_progress", conclusion=None))
        self.assertFalse(gate.check_runs(runs, "a" * 40))
        runs[-1].update(status="completed", conclusion="failure")
        with self.assertRaises(RuntimeError):
            gate.check_runs(runs, "a" * 40)

    def test_superseded_commit_is_skipped_before_checking_runs(self):
        with patch.dict(gate.os.environ, {"RELEASE_SHA": "a" * 40}), \
                patch.object(gate, "github", return_value={"object": {"sha": "b" * 40}}) as api, \
                patch.object(gate, "output") as output:
            gate.main()
            self.assertEqual(api.call_count, 1)
            output.assert_called_once_with("a" * 40, False)

    def test_current_successful_commit_can_deploy(self):
        responses = [{"object": {"sha": "a" * 40}}, {"workflow_runs": self.runs()}]
        with patch.dict(gate.os.environ, {"RELEASE_SHA": "a" * 40}), \
                patch.object(gate, "github", side_effect=responses), patch.object(gate, "output") as output:
            gate.main()
            output.assert_called_once_with("a" * 40, True)


if __name__ == "__main__":
    unittest.main()
