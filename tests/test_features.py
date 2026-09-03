"""Tests for multi-stage incidents, Sigma import, schema export, and the sweep."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from siemlab.engine import run  # noqa: E402
from siemlab.evaluate import evaluate  # noqa: E402
from siemlab.export import export_events, to_ecs, to_ocsf  # noqa: E402
from siemlab.generator import KILL_CHAIN, generate  # noqa: E402
from siemlab.rules import Rule, load_rules_from_dir  # noqa: E402
from siemlab.sigma import _mini_yaml, sigma_to_rule_dict  # noqa: E402
from siemlab.sweep import run_sweep  # noqa: E402

RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "detections")


class TestIncidents(unittest.TestCase):
    def test_incident_has_one_actor_and_at_most_two_hosts(self):
        events = generate(seed=3, n_incidents=6)
        users, hosts = {}, {}
        for e in events:
            if e.get("_incident"):
                users.setdefault(e["_incident"], set()).add(e.get("User"))
                hosts.setdefault(e["_incident"], set()).add(e.get("host"))
        for inc, u in users.items():
            u.discard(None)
            self.assertLessEqual(len(u), 1, f"{inc} has multiple actors")
        # Origin host, plus at most one lateral-movement target.
        for inc, h in hosts.items():
            self.assertLessEqual(len(h), 2, f"{inc} touches too many hosts")

    def test_first_incident_walks_full_kill_chain(self):
        events = generate(seed=3, n_incidents=6)
        stages = [e.get("_stage") for e in events if e.get("_incident") == "INC-001"]
        for stage in KILL_CHAIN:
            self.assertIn(stage, stages)

    def test_evaluator_reports_detection_stage_and_latency(self):
        rules = load_rules_from_dir(RULES_DIR)
        events = generate(seed=3, n_incidents=6)
        report = evaluate(run(rules, events), events)
        self.assertGreater(len(report.incidents), 0)
        self.assertEqual(report.incident_recall, 1.0)
        for inc in report.incidents.values():
            self.assertTrue(inc.detected)
            self.assertIsNotNone(inc.detected_stage)
            self.assertGreaterEqual(inc.time_to_detect, 0.0)

    def test_benign_events_have_no_incident(self):
        events = generate(seed=3, n_incidents=6)
        benign = [e for e in events if e.get("_label") is None]
        self.assertTrue(all(e.get("_incident") is None for e in benign))


class TestSigmaImport(unittest.TestCase):
    SAMPLE = """
title: Encoded PowerShell
id: sig-test-1
description: >
  folded description that spans
  more than one physical line
logsource:
  product: windows
  service: sysmon
  category: process_creation
detection:
  selection:
    EventID: 1
    Image|endswith: '\\powershell.exe'
  enc:
    CommandLine|contains: '-enc'
  condition: selection and enc
level: high
tags:
  - attack.execution
  - attack.t1059.001
"""

    def test_mini_yaml_parses_sigma(self):
        doc = _mini_yaml(self.SAMPLE)
        self.assertEqual(doc["id"], "sig-test-1")
        self.assertEqual(doc["detection"]["condition"], "selection and enc")
        self.assertEqual(doc["detection"]["selection"]["EventID"], 1)
        self.assertIn("attack.t1059.001", doc["tags"])

    def test_conversion_maps_fields_and_tags(self):
        rule = Rule.from_dict(sigma_to_rule_dict(_mini_yaml(self.SAMPLE)))
        self.assertEqual(rule.attack, ["T1059.001"])
        self.assertEqual(rule.logsource, {"source": "Sysmon"})
        # EventID aliased to event_id.
        self.assertEqual(rule.selections["selection"]["event_id"], 1)
        self.assertEqual(rule.condition, "selection and enc")

    def test_converted_rule_actually_fires(self):
        rule = Rule.from_dict(sigma_to_rule_dict(_mini_yaml(self.SAMPLE)))
        event = {
            "source": "Sysmon", "event_id": 1,
            "Image": "C:\\Windows\\System32\\powershell.exe",
            "CommandLine": "powershell.exe -enc ABCDEF",
        }
        self.assertTrue(rule.matches(event))

    def test_yaml_rule_loads_from_detections_dir(self):
        rules = load_rules_from_dir(RULES_DIR)
        ids = {r.id for r in rules}
        self.assertIn("sigma-rundll32-lsass", ids)  # the .yml in detections/


class TestExport(unittest.TestCase):
    def _sample_events(self):
        return generate(seed=5, n_incidents=4)

    def test_ecs_has_timestamp_and_no_private_fields(self):
        for e in self._sample_events():
            doc = to_ecs(e)
            self.assertIn("@timestamp", doc)
            # Ground truth lives under labels, never as top-level _fields.
            self.assertFalse(any(k.startswith("_") for k in doc))
            if e.get("_label"):
                self.assertEqual(doc["labels"]["siemlab"]["label"], e["_label"])

    def test_ocsf_assigns_class_uid(self):
        for e in self._sample_events():
            doc = to_ocsf(e)
            self.assertIn("class_uid", doc)
            self.assertIsInstance(doc["class_uid"], int)

    def test_raw_export_strips_ground_truth(self):
        events = self._sample_events()
        for doc in export_events(events, "raw"):
            self.assertFalse(any(k.startswith("_") for k in doc))

    def test_unknown_schema_raises(self):
        with self.assertRaises(ValueError):
            export_events([], "splunk")


class TestSweep(unittest.TestCase):
    def test_broad_rule_decays_more_than_tight_rule(self):
        rules = load_rules_from_dir(RULES_DIR)
        result = run_sweep(rules, rates=[2.0, 64.0], seed=9, n_incidents=6)
        tight = result.series("cred-lsass-access")
        broad = result.series("ps-any-execution-BROAD")
        # Tight rule holds precision; broad rule is worse and gets worse.
        self.assertGreaterEqual(tight[-1], tight[0] - 1e-9)
        self.assertLess(broad[-1], tight[-1])

    def test_alert_volume_rises_with_noise(self):
        rules = load_rules_from_dir(RULES_DIR)
        result = run_sweep(rules, rates=[2.0, 32.0], seed=9, n_incidents=6)
        self.assertLess(result.points[0].total_alerts, result.points[-1].total_alerts)


if __name__ == "__main__":
    unittest.main(verbosity=2)
