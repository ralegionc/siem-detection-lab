"""Scoring: turn alerts + ground-truth labels into detection metrics.

Three questions, in increasing order of how much a SOC lead cares:

1. **Per-rule precision** — of the alerts a rule raised, how many touched a real
   attack event? A rule at 30% precision is drowning the analyst.
2. **Technique recall** — of the ATT&CK techniques present, how many did some
   rule catch? This is coverage.
3. **Incident detection** — of the multi-stage intrusions in the data, how many
   did we catch *at all*, **at which kill-chain stage**, and **how long did the
   attacker dwell** before we saw them?

The third is the one that matters. Catching an intrusion at `initial_access` is
a contained incident; catching the same intrusion at `lateral_movement` is an
incident response. Both count as "detected" in a naive metric — which is exactly
why a naive metric misleads. Mean time to detect (MTTD) and stage-of-detection
separate them.

An alert counts as a true positive if any of its trigger events is an attack
event whose technique the rule *claims* to detect (``rule.attack``), so a rule
gets no credit for coincidentally overlapping some unrelated malicious event.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .engine import Alert
from .generator import KILL_CHAIN


@dataclass
class RuleScore:
    rule_id: str
    title: str
    alerts: int = 0
    true_positives: int = 0
    false_positives: int = 0

    @property
    def precision(self) -> float:
        return self.true_positives / self.alerts if self.alerts else 0.0


@dataclass
class IncidentScore:
    incident_id: str
    start_ts: float
    end_ts: float
    stages: List[str] = field(default_factory=list)
    techniques: List[str] = field(default_factory=list)
    detected_ts: Optional[float] = None
    detected_stage: Optional[str] = None
    detected_by: Optional[str] = None

    @property
    def detected(self) -> bool:
        return self.detected_ts is not None

    @property
    def time_to_detect(self) -> Optional[float]:
        """Seconds of attacker dwell before the first alert landed."""
        if self.detected_ts is None:
            return None
        return self.detected_ts - self.start_ts

    @property
    def stage_index(self) -> Optional[int]:
        if self.detected_stage is None or self.detected_stage not in KILL_CHAIN:
            return None
        return KILL_CHAIN.index(self.detected_stage)

    @property
    def dwell_span(self) -> float:
        return self.end_ts - self.start_ts


@dataclass
class Report:
    rule_scores: Dict[str, RuleScore] = field(default_factory=dict)
    techniques_present: Dict[str, int] = field(default_factory=dict)
    techniques_detected: set = field(default_factory=set)
    incidents: Dict[str, IncidentScore] = field(default_factory=dict)
    total_alerts: int = 0
    total_events: int = 0

    # -- technique level --
    @property
    def technique_recall(self) -> float:
        present = set(self.techniques_present)
        if not present:
            return 0.0
        return len(self.techniques_detected & present) / len(present)

    @property
    def missed_techniques(self) -> List[str]:
        return sorted(set(self.techniques_present) - self.techniques_detected)

    # -- incident level --
    @property
    def incident_recall(self) -> float:
        if not self.incidents:
            return 0.0
        return sum(1 for i in self.incidents.values() if i.detected) / len(self.incidents)

    @property
    def mean_time_to_detect(self) -> Optional[float]:
        ttds = [i.time_to_detect for i in self.incidents.values() if i.detected]
        return sum(ttds) / len(ttds) if ttds else None

    @property
    def median_time_to_detect(self) -> Optional[float]:
        ttds = sorted(i.time_to_detect for i in self.incidents.values() if i.detected)
        if not ttds:
            return None
        mid = len(ttds) // 2
        if len(ttds) % 2:
            return ttds[mid]
        return (ttds[mid - 1] + ttds[mid]) / 2

    def caught_by_stage(self, stage: str) -> float:
        """Fraction of incidents detected at or before ``stage``."""
        if stage not in KILL_CHAIN or not self.incidents:
            return 0.0
        limit = KILL_CHAIN.index(stage)
        hit = sum(
            1 for i in self.incidents.values()
            if i.detected and i.stage_index is not None and i.stage_index <= limit
        )
        return hit / len(self.incidents)

    # -- overall alert quality --
    @property
    def overall_precision(self) -> float:
        tp = sum(s.true_positives for s in self.rule_scores.values())
        return tp / self.total_alerts if self.total_alerts else 0.0


def _alert_is_true_positive(alert: Alert) -> bool:
    """True if the alert landed on an attack event the rule claims to detect."""
    claimed = set(alert.attack)
    for ev in alert.trigger_events:
        label = ev.get("_label")
        if label is None:
            continue
        if not claimed:
            return True  # rule makes no claim; any attack hit counts
        for c in claimed:
            if label == c or label.startswith(c + ".") or c.startswith(label + "."):
                return True
    return False


def _alert_fire_ts(alert: Alert) -> float:
    """When the alert actually fired: the newest event that triggered it."""
    return max((float(e.get("_ts", 0.0)) for e in alert.trigger_events), default=0.0)


def evaluate(alerts: List[Alert], events: List[Dict[str, Any]]) -> Report:
    report = Report(total_alerts=len(alerts), total_events=len(events))

    # Inventory techniques and incidents present in the data.
    for ev in events:
        label = ev.get("_label")
        if label is not None:
            report.techniques_present[label] = report.techniques_present.get(label, 0) + 1

        inc_id = ev.get("_incident")
        if inc_id:
            ts = float(ev.get("_ts", 0.0))
            inc = report.incidents.get(inc_id)
            if inc is None:
                inc = IncidentScore(incident_id=inc_id, start_ts=ts, end_ts=ts)
                report.incidents[inc_id] = inc
            inc.start_ts = min(inc.start_ts, ts)
            inc.end_ts = max(inc.end_ts, ts)
            stage = ev.get("_stage")
            if stage and stage not in inc.stages:
                inc.stages.append(stage)
            if label and label not in inc.techniques:
                inc.techniques.append(label)

    # Score alerts.
    for alert in alerts:
        score = report.rule_scores.get(alert.rule_id)
        if score is None:
            score = RuleScore(rule_id=alert.rule_id, title=alert.rule_title)
            report.rule_scores[alert.rule_id] = score
        score.alerts += 1

        is_tp = _alert_is_true_positive(alert)
        if is_tp:
            score.true_positives += 1
            for c in alert.attack:
                report.techniques_detected.add(c)
            for ev in alert.trigger_events:
                if ev.get("_label"):
                    report.techniques_detected.add(ev["_label"])
        else:
            score.false_positives += 1

        # Incident attribution: only true positives count as catching an
        # intrusion. A rule that fires on benign noise happening to sit near an
        # incident has not detected anything.
        if not is_tp:
            continue
        fire_ts = _alert_fire_ts(alert)
        incident_events = [e for e in alert.trigger_events if e.get("_incident")]
        for ev in incident_events:
            inc = report.incidents.get(ev["_incident"])
            if inc is None:
                continue
            if inc.detected_ts is None or fire_ts < inc.detected_ts:
                inc.detected_ts = fire_ts
                # The stage underway when we caught them: the latest incident
                # event inside the triggering window.
                own = [e for e in incident_events if e.get("_incident") == inc.incident_id]
                latest = max(own, key=lambda e: float(e.get("_ts", 0.0)))
                inc.detected_stage = latest.get("_stage")
                inc.detected_by = alert.rule_id

    return report


def _fmt_duration(seconds: Optional[float]) -> str:
    if seconds is None:
        return "n/a"
    if seconds < 60:
        return f"{seconds:.0f}s"
    if seconds < 3600:
        return f"{seconds / 60:.1f}m"
    return f"{seconds / 3600:.1f}h"


def format_report(report: Report) -> str:
    lines: List[str] = []
    lines.append("=" * 72)
    lines.append("  SIEM DETECTION LAB -- EVALUATION REPORT")
    lines.append("=" * 72)
    lines.append(f"  events analyzed : {report.total_events}")
    lines.append(f"  alerts raised   : {report.total_alerts}")
    lines.append(f"  overall precision: {report.overall_precision:.0%} "
                 f"(share of alerts worth opening)")
    lines.append("")

    # --- rules ---
    lines.append("  PER-RULE PERFORMANCE")
    lines.append("  " + "-" * 68)
    lines.append(f"  {'rule':<36}{'alerts':>8}{'TP':>6}{'FP':>6}{'prec':>8}")
    lines.append("  " + "-" * 68)
    for score in sorted(report.rule_scores.values(), key=lambda s: (-s.precision, s.rule_id)):
        title = (score.title[:33] + "...") if len(score.title) > 36 else score.title
        lines.append(
            f"  {title:<36}{score.alerts:>8}{score.true_positives:>6}"
            f"{score.false_positives:>6}{score.precision:>7.0%}"
        )
    lines.append("  " + "-" * 68)
    lines.append("")

    # --- techniques ---
    lines.append("  TECHNIQUE COVERAGE")
    lines.append(f"    recall: {report.technique_recall:.0%} "
                 f"({len(report.techniques_detected & set(report.techniques_present))}"
                 f"/{len(report.techniques_present)} techniques seen)")
    if report.missed_techniques:
        for t in report.missed_techniques:
            lines.append(f"    MISSED {t}  ({report.techniques_present[t]} event(s))")
    lines.append("")

    # --- incidents ---
    if report.incidents:
        lines.append("  INCIDENT DETECTION  (the number that matters)")
        lines.append(f"    incidents      : {len(report.incidents)}")
        lines.append(f"    detected       : {report.incident_recall:.0%}")
        lines.append(f"    mean time to detect  : {_fmt_duration(report.mean_time_to_detect)}")
        lines.append(f"    median time to detect: {_fmt_duration(report.median_time_to_detect)}")
        lines.append(f"    caught before lateral movement: "
                     f"{report.caught_by_stage('credential_access'):.0%}")
        lines.append("")
        lines.append("  " + "-" * 68)
        lines.append(f"  {'incident':<11}{'stages':>7}{'caught at':>21}{'dwell':>9}  {'by':>18}")
        lines.append("  " + "-" * 68)
        for inc in sorted(report.incidents.values(), key=lambda i: i.incident_id):
            if inc.detected:
                caught = inc.detected_stage or "?"
                ttd = _fmt_duration(inc.time_to_detect)
                by = (inc.detected_by or "")[:18]
            else:
                caught, ttd, by = "-- MISSED --", "-", ""
            lines.append(
                f"  {inc.incident_id:<11}{len(inc.stages):>7}{caught:>21}{ttd:>9}  {by:>18}"
            )
        lines.append("  " + "-" * 68)
    lines.append("=" * 72)
    return "\n".join(lines)
