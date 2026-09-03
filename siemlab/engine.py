"""The detection engine: run rules over an event stream, emit alerts.

Match rules fire per-event. Threshold rules maintain a sliding time window per
(group_by) key and fire when the hit count crosses the configured count. Each
alert records exactly which events triggered it, so the evaluator can decide
whether it landed on real attack events (true positive) or benign noise (false
positive).
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, List, Tuple

from .rules import Rule


@dataclass
class Alert:
    rule_id: str
    rule_title: str
    level: str
    attack: List[str]
    timestamp: str
    host: str
    # The events responsible for this alert (may be several for threshold rules).
    trigger_events: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def trigger_labels(self) -> List[Any]:
        return [e.get("_label") for e in self.trigger_events]


def _group_key(event: Dict[str, Any], fields: List[str]) -> Tuple:
    return tuple(event.get(f) for f in fields)


def run(rules: List[Rule], events: List[Dict[str, Any]]) -> List[Alert]:
    """Evaluate all rules against events (assumed roughly time-ordered)."""
    alerts: List[Alert] = []

    # Per threshold-rule sliding-window state: key -> deque[(ts, event)].
    windows: Dict[str, Dict[Tuple, Deque[Tuple[float, Dict[str, Any]]]]] = defaultdict(
        lambda: defaultdict(deque)
    )
    # Once a group has fired, suppress re-firing until the window drains, so one
    # brute-force burst is one alert rather than one per event past threshold.
    firing: Dict[str, set] = defaultdict(set)

    for event in events:
        ts = float(event.get("_ts", 0.0))
        for rule in rules:
            if not rule.matches(event):
                continue

            if not rule.is_threshold:
                alerts.append(
                    Alert(
                        rule_id=rule.id,
                        rule_title=rule.title,
                        level=rule.level,
                        attack=rule.attack,
                        timestamp=event["timestamp"],
                        host=event.get("host", ""),
                        trigger_events=[event],
                    )
                )
                continue

            # Threshold rule.
            thr = rule.threshold
            key = _group_key(event, thr.group_by)
            win = windows[rule.id][key]
            win.append((ts, event))
            # Evict events older than the window.
            while win and ts - win[0][0] > thr.window_seconds:
                win.popleft()

            if len(win) >= thr.count and key not in firing[rule.id]:
                alerts.append(
                    Alert(
                        rule_id=rule.id,
                        rule_title=rule.title,
                        level=rule.level,
                        attack=rule.attack,
                        timestamp=event["timestamp"],
                        host=event.get("host", ""),
                        trigger_events=[e for _, e in win],
                    )
                )
                firing[rule.id].add(key)
            elif len(win) == 0:
                firing[rule.id].discard(key)
            # Reset the suppression once the burst falls back below threshold.
            if len(win) < thr.count:
                firing[rule.id].discard(key)

    return alerts
