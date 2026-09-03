"""Event schema and helpers.

Events are plain dicts so they serialize straight to JSON lines (the format a
real SIEM ingests). Fields are modeled on Windows Security + Sysmon logs.

Every generated event carries a private ``_label`` key: the ATT&CK technique id
that produced it, or ``None`` for benign baseline noise. The detection engine
never reads ``_label`` — only the evaluator does, to score alerts as
true/false positives. Think of it as ground truth stapled to the packet.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List

# Fields the detection engine is allowed to see. Anything prefixed with "_" is
# ground-truth metadata and is stripped before rules run.
GROUND_TRUTH_PREFIX = "_"


def make_event(
    timestamp: datetime,
    host: str,
    source: str,
    event_id: int,
    label: str | None = None,
    incident: str | None = None,
    stage: str | None = None,
    **fields: Any,
) -> Dict[str, Any]:
    """Build a normalized event record.

    Args:
        timestamp: when the event fired (tz-aware).
        host: the machine that emitted it.
        source: log channel — "Security", "Sysmon", or "PowerShell".
        event_id: Windows/Sysmon event id.
        label: ATT&CK technique id if this event is part of an attack, else None.
        incident: id of the multi-stage intrusion this event belongs to, if any.
        stage: kill-chain stage name ("initial_access", "persistence", ...).
        **fields: channel-specific fields (User, IpAddress, CommandLine, ...).
    """
    ev: Dict[str, Any] = {
        "timestamp": timestamp.astimezone(timezone.utc).isoformat(),
        "_ts": timestamp.timestamp(),  # numeric, for windowing; ground truth-ish helper
        "host": host,
        "source": source,
        "event_id": event_id,
        "_label": label,
        "_incident": incident,
        "_stage": stage,
    }
    ev.update(fields)
    return ev


def visible_fields(event: Dict[str, Any]) -> Dict[str, Any]:
    """Return only the fields a detection rule may match against."""
    return {k: v for k, v in event.items() if not k.startswith(GROUND_TRUTH_PREFIX)}


def is_attack(event: Dict[str, Any]) -> bool:
    return event.get("_label") is not None


def to_jsonl(events: Iterable[Dict[str, Any]]) -> str:
    import json

    return "\n".join(json.dumps(e) for e in events)


def from_jsonl(text: str) -> List[Dict[str, Any]]:
    import json

    out = []
    for line in text.splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    return out
