"""Unit tests for the matcher, threshold engine, and evaluator."""

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from siemlab.engine import run  # noqa: E402
from siemlab.evaluate import evaluate  # noqa: E402
from siemlab.events import make_event  # noqa: E402
from siemlab.generator import generate  # noqa: E402
from siemlab.rules import Rule, _eval_condition, _match_selection, load_rules_from_dir  # noqa: E402

RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "detections")
T0 = datetime(2026, 9, 3, 8, 0, 0, tzinfo=timezone.utc)


class TestMatching(unittest.TestCase):
    def test_exact_and_list(self):
        ev = {"event_id": 4625, "User": "alice"}
        self.assertTrue(_match_selection(ev, {"event_id": 4625}))
        self.assertTrue(_match_selection(ev, {"event_id": [4624, 4625]}))
        self.assertFalse(_match_selection(ev, {"event_id": 4624}))

    def test_modifiers(self):
        ev = {"Image": "C:\\Windows\\System32\\powershell.exe",
              "CommandLine": "powershell -enc AAAA"}
        self.assertTrue(_match_selection(ev, {"Image|endswith": "\\powershell.exe"}))
        self.assertTrue(_match_selection(ev, {"CommandLine|contains": "-enc"}))
        self.assertTrue(_match_selection(ev, {"Image|startswith": "C:\\Windows"}))
        self.assertTrue(_match_selection(ev, {"CommandLine|re": "-enc\\s+\\w+"}))
        self.assertFalse(_match_selection(ev, {"Image|endswith": "\\cmd.exe"}))

    def test_missing_field_is_no_match(self):
        self.assertFalse(_match_selection({"event_id": 1}, {"User|contains": "x"}))


class TestCondition(unittest.TestCase):
    def test_boolean_logic(self):
        r = {"a": True, "b": False, "c": True}
        self.assertTrue(_eval_condition("a and c", r))
        self.assertFalse(_eval_condition("a and b", r))
        self.assertTrue(_eval_condition("a and not b", r))
        self.assertTrue(_eval_condition("b or c", r))
        self.assertFalse(_eval_condition("not (a or c)", r))

    def test_aggregates(self):
        r = {"sel_1": False, "sel_2": True, "other": False}
        self.assertTrue(_eval_condition("1 of sel_*", r))
        self.assertFalse(_eval_condition("all of sel_*", r))
        self.assertTrue(_eval_condition("1 of them", r))

    def test_unknown_selection_raises(self):
        with self.assertRaises(ValueError):
            _eval_condition("nope", {"a": True})


class TestThreshold(unittest.TestCase):
    def _brute_rule(self):
        return Rule.from_dict({
            "id": "bf", "title": "bf", "attack": ["T1110"],
            "logsource": {"source": "Security"},
            "detection": {"selection": {"event_id": 4625}, "condition": "selection"},
            "threshold": {"group_by": ["host", "User"], "count": 5, "window_seconds": 60},
        })

    def test_fires_once_over_threshold(self):
        rule = self._brute_rule()
        events = [make_event(T0 + timedelta(seconds=i), "H1", "Security", 4625, "T1110",
                             User="alice", IpAddress="1.2.3.4") for i in range(10)]
        alerts = run([rule], events)
        self.assertEqual(len(alerts), 1)
        self.assertGreaterEqual(len(alerts[0].trigger_events), 5)

    def test_below_threshold_is_silent(self):
        rule = self._brute_rule()
        events = [make_event(T0 + timedelta(seconds=i), "H1", "Security", 4625, "T1110",
                             User="alice") for i in range(3)]
        self.assertEqual(run([rule], events), [])

    def test_window_expiry_prevents_fire(self):
        rule = self._brute_rule()
        # Five failures but spaced 30s apart => never 5 within a 60s window.
        events = [make_event(T0 + timedelta(seconds=i * 30), "H1", "Security", 4625, "T1110",
                             User="alice") for i in range(5)]
        self.assertEqual(run([rule], events), [])


class TestEndToEnd(unittest.TestCase):
    def test_full_pipeline_detects_every_technique(self):
        rules = load_rules_from_dir(RULES_DIR)
        events = generate(seed=7, n_incidents=14)
        alerts = run(rules, events)
        report = evaluate(alerts, events)
        # Guaranteed coverage means every technique in the data is caught.
        self.assertEqual(report.technique_recall, 1.0)
        self.assertEqual(report.missed_techniques, [])

    def test_tight_rule_beats_broad_rule(self):
        rules = load_rules_from_dir(RULES_DIR)
        events = generate(seed=7, n_incidents=14)
        report = evaluate(run(rules, events), events)
        tight = report.rule_scores["ps-encoded-command"]
        broad = report.rule_scores["ps-any-execution-BROAD"]
        self.assertGreater(tight.precision, broad.precision)
        self.assertGreater(broad.false_positives, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
