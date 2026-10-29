"""Tests for hard negatives, rule tuning, and the Sigma corpus audit."""

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from siemlab.audit import format_audit, load_sigma_tree, run_audit  # noqa: E402
from siemlab.engine import run  # noqa: E402
from siemlab.evaluate import evaluate  # noqa: E402
from siemlab.generator import generate  # noqa: E402
from siemlab.rules import Rule, UnsupportedRuleError, load_rules_from_dir  # noqa: E402
from siemlab.sigma import sigma_to_rule_dict, _mini_yaml  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TUNED = os.path.join(ROOT, "detections")
UNTUNED = os.path.join(ROOT, "detections-untuned")

# Rules deliberately left untuned as teaching foils are excluded from the
# precision comparison -- they are supposed to be bad.
FOILS = {"ps-any-execution-BROAD"}


class TestHardNegatives(unittest.TestCase):
    def test_hard_negatives_are_present_and_benign(self):
        events = generate(seed=11, n_incidents=6)
        # The signed-rundll32-reads-LSASS near miss: same filename as the
        # attack, different provenance, and definitively not labeled an attack.
        hn = [e for e in events
              if e.get("SourceImage") == "C:\\Windows\\System32\\rundll32.exe"
              and str(e.get("TargetImage", "")).endswith("lsass.exe")]
        self.assertGreater(len(hn), 0, "expected signed-rundll32 hard negatives")
        self.assertTrue(all(e.get("_label") is None for e in hn))

    def test_hard_negatives_are_disableable(self):
        events = generate(seed=11, n_incidents=6, hard_negative_rate=0.0)
        hn = [e for e in events
              if e.get("SourceImage") == "C:\\Windows\\System32\\rundll32.exe"]
        self.assertEqual(hn, [])

    def test_enriched_fields_present(self):
        events = generate(seed=11, n_incidents=6)
        logon = next(e for e in events if e.get("event_id") in (4624, 4625))
        for f in ("TargetUserName", "WorkstationName", "Provider_Name"):
            self.assertIn(f, logon)
        access = next(e for e in events if e.get("event_id") == 10)
        self.assertIn("CallTrace", access)


class TestTuning(unittest.TestCase):
    def _report(self, rules_dir, seed):
        events = generate(seed=seed, n_incidents=8)
        return evaluate(run(load_rules_from_dir(rules_dir), events), events)

    def test_untuned_rules_drown_in_hard_negatives(self):
        rep = self._report(UNTUNED, 1337)
        scored = [s for rid, s in rep.rule_scores.items() if rid not in FOILS]
        self.assertTrue(scored)
        # Every genuine rule should be visibly damaged by the near misses.
        self.assertTrue(all(s.precision < 0.5 for s in scored),
                        f"expected all untuned rules < 50% precision, got "
                        f"{[(s.rule_id, s.precision) for s in scored]}")

    def test_tuning_restores_precision_without_losing_recall(self):
        tuned = self._report(TUNED, 1337)
        untuned = self._report(UNTUNED, 1337)
        for rid, s in tuned.rule_scores.items():
            if rid in FOILS:
                continue
            self.assertGreater(s.precision, untuned.rule_scores[rid].precision,
                               f"{rid} did not improve with tuning")
        # Tuning must not cost coverage.
        self.assertEqual(tuned.technique_recall, 1.0)
        self.assertEqual(tuned.incident_recall, 1.0)

    def test_tuning_generalizes_to_unseen_seeds(self):
        # Filters must key on structure (path, parent, source), not memorized
        # values, or they are just overfitting to one benign draw.
        for seed in (7, 42, 99):
            rep = self._report(TUNED, seed)
            for rid, s in rep.rule_scores.items():
                if rid in FOILS:
                    continue
                self.assertEqual(s.false_positives, 0,
                                 f"{rid} regressed on seed {seed}")
            self.assertEqual(rep.technique_recall, 1.0)


class TestRuleValidation(unittest.TestCase):
    def _rule(self, selection, condition="selection"):
        return Rule.from_dict({
            "id": "t", "title": "t",
            "detection": {"selection": selection, "condition": condition},
        })

    def test_empty_selection_rejected(self):
        # An empty selection matches everything vacuously -- it would look like
        # a rule that detects all attacks. Must never load.
        with self.assertRaises(UnsupportedRuleError):
            self._rule({})

    def test_unsupported_modifier_rejected_at_load(self):
        with self.assertRaises(UnsupportedRuleError):
            self._rule({"CommandLine|base64offset": "x"})

    def test_chained_all_modifier_requires_every_value(self):
        rule = self._rule({"CommandLine|contains|all": ["alpha", "beta"]})
        self.assertTrue(rule.matches({"CommandLine": "alpha and beta"}))
        self.assertFalse(rule.matches({"CommandLine": "alpha only"}))

    def test_plain_list_is_or(self):
        rule = self._rule({"CommandLine|contains": ["alpha", "beta"]})
        self.assertTrue(rule.matches({"CommandLine": "alpha only"}))

    def test_null_means_field_absent(self):
        rule = self._rule({"ParentImage": None})
        self.assertTrue(rule.matches({"Image": "x"}))
        self.assertFalse(rule.matches({"Image": "x", "ParentImage": "y"}))

    def test_keyword_list_selection_rejected(self):
        doc = _mini_yaml(
            "title: kw\nid: kw\nlogsource:\n  service: sysmon\n"
            "detection:\n  keywords:\n    - somestring\n    - another\n"
            "  condition: keywords\n"
        )
        with self.assertRaises(UnsupportedRuleError):
            Rule.from_dict(sigma_to_rule_dict(doc))


class TestAudit(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, name, text):
        path = os.path.join(self.tmp, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return path

    def test_audit_tolerates_broken_rules_and_records_reasons(self):
        self._write("good.yml",
                    "title: Good\nid: good\nlogsource:\n  service: sysmon\n"
                    "detection:\n  selection:\n    EventID: 1\n  condition: selection\n")
        self._write("bad_modifier.yml",
                    "title: Bad\nid: bad\nlogsource:\n  service: sysmon\n"
                    "detection:\n  selection:\n    CommandLine|cidr: 10.0.0.0/8\n"
                    "  condition: selection\n")
        self._write("no_condition.yml",
                    "title: NoCond\nid: nocond\nlogsource:\n  service: sysmon\n"
                    "detection:\n  selection:\n    EventID: 1\n")

        result = load_sigma_tree(self.tmp)
        self.assertEqual(result.discovered, 3)
        self.assertEqual(len(result.loaded), 1)
        self.assertEqual(len(result.skipped), 2)
        self.assertEqual(sum(result.skip_counts.values()), 2)

    def test_audit_scores_corroboration(self):
        # A rule that catches our encoded-PowerShell attack.
        self._write("enc.yml",
                    "title: Enc\nid: enc\nlogsource:\n  service: sysmon\n"
                    "detection:\n  selection:\n    EventID: 1\n"
                    "    CommandLine|contains: '-enc'\n  condition: selection\n"
                    "tags:\n  - attack.t1059.001\n")
        result = load_sigma_tree(self.tmp)
        events = generate(seed=1337, n_incidents=8)
        run_audit(result, events)
        self.assertGreaterEqual(result.n_corroborating, 1)
        self.assertIn("T1059.001", result.corroborated_techniques)
        self.assertIn("CORROBORATION", format_audit(result))

    def test_audit_on_empty_dir_is_not_an_error(self):
        result = load_sigma_tree(self.tmp)
        self.assertEqual(result.discovered, 0)
        self.assertEqual(result.loaded, [])
        run_audit(result, generate(seed=1, n_incidents=2))
        self.assertIn("No community rule fired", format_audit(result))


if __name__ == "__main__":
    unittest.main(verbosity=2)
