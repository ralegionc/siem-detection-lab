"""Emit events and alerts in real downstream schemas.

The lab's internal event is a flat, Sysmon-flavored dict — fine for the engine,
but not what a production pipeline expects. Two industry schemas dominate:

* **ECS** (Elastic Common Schema) — what Elastic/Kibana ingests.
* **OCSF** (Open Cybersecurity Schema Framework) — the vendor-neutral standard
  behind Amazon Security Lake and a growing list of tools.

Exporting to these means the generated telemetry isn't a toy format trapped in
this repo: you can pipe it straight into Elastic, or into any OCSF consumer, and
cross-check this lab's detections against a real SIEM's. Ground-truth fields
(``_label``, ``_incident``, ``_stage``) are preserved under a ``labels.siemlab``
namespace so you can still score, but they never collide with schema fields.

These are pragmatic mappings of the fields this lab actually generates, not a
complete implementation of either schema.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List

from .engine import Alert
from .events import visible_fields

# --- ECS ------------------------------------------------------------------

_ECS_CATEGORY = {
    ("Security", 4624): (["authentication"], ["start"]),
    ("Security", 4625): (["authentication"], ["start"]),
    ("Security", 4720): (["iam"], ["creation"]),
    ("Sysmon", 1): (["process"], ["start"]),
    ("Sysmon", 10): (["process"], ["access"]),
    ("Sysmon", 13): (["registry", "configuration"], ["change"]),
}


def _labels(event: Dict[str, Any]) -> Dict[str, Any]:
    out = {}
    for k in ("_label", "_incident", "_stage"):
        if event.get(k) is not None:
            out[k.lstrip("_")] = event[k]
    return out


def to_ecs(event: Dict[str, Any]) -> Dict[str, Any]:
    """Map one internal event to an Elastic Common Schema document."""
    source = event.get("source", "")
    eid = event.get("event_id")
    categories, types = _ECS_CATEGORY.get((source, eid), ([], []))

    doc: Dict[str, Any] = {
        "@timestamp": event.get("timestamp"),
        "event": {
            "code": str(eid),
            "provider": source,
            "category": categories,
            "type": types,
            "module": "siemlab",
        },
        "host": {"name": event.get("host")},
    }
    if event.get("User") is not None:
        doc["user"] = {"name": event["User"]}
    if event.get("IpAddress") is not None:
        doc["source"] = {"ip": event["IpAddress"]}
    if event.get("LogonType") is not None:
        doc.setdefault("winlog", {})["logon"] = {"type": str(event["LogonType"])}
    if event.get("Image") is not None or event.get("CommandLine") is not None:
        proc = {}
        if event.get("Image") is not None:
            proc["executable"] = event["Image"]
        if event.get("CommandLine") is not None:
            proc["command_line"] = event["CommandLine"]
        if event.get("ParentImage") is not None:
            proc["parent"] = {"executable": event["ParentImage"]}
        doc["process"] = proc
    if event.get("TargetImage") is not None:
        doc.setdefault("process", {})["target"] = {"executable": event["TargetImage"]}
    if event.get("TargetObject") is not None:
        doc["registry"] = {"path": event["TargetObject"], "data": {"strings": [event.get("Details")]}}

    labels = _labels(event)
    if labels:
        doc["labels"] = {"siemlab": labels}
    return doc


# --- OCSF -----------------------------------------------------------------
# Minimal mapping onto a couple of OCSF classes. class_uid values follow the
# published OCSF category/class numbering.

_OCSF_AUTH = 3002        # Authentication (category 3: IAM)
_OCSF_PROCESS = 1007     # Process Activity (category 1: System Activity)
_OCSF_REGISTRY = 201007  # Registry Key Activity (approx.)
_OCSF_ACCOUNT = 3001     # Account Change


def to_ocsf(event: Dict[str, Any]) -> Dict[str, Any]:
    """Map one internal event to an OCSF-style event object."""
    source = event.get("source", "")
    eid = event.get("event_id")

    base: Dict[str, Any] = {
        "time": event.get("timestamp"),
        "metadata": {"product": {"name": "siemlab"}, "version": "1.1.0"},
        "device": {"hostname": event.get("host")},
        "severity": "Informational",
    }
    if event.get("User") is not None:
        base["actor"] = {"user": {"name": event["User"]}}

    if source == "Security" and eid in (4624, 4625):
        base["class_uid"] = _OCSF_AUTH
        base["class_name"] = "Authentication"
        base["activity_name"] = "Logon"
        base["status"] = "Success" if eid == 4624 else "Failure"
        if event.get("IpAddress") is not None:
            base["src_endpoint"] = {"ip": event["IpAddress"]}
        if event.get("LogonType") is not None:
            base["logon_type_id"] = event["LogonType"]
    elif source == "Security" and eid == 4720:
        base["class_uid"] = _OCSF_ACCOUNT
        base["class_name"] = "Account Change"
        base["activity_name"] = "Create"
        base["user"] = {"name": event.get("TargetUserName")}
    elif source == "Sysmon" and eid in (1, 10):
        base["class_uid"] = _OCSF_PROCESS
        base["class_name"] = "Process Activity"
        base["activity_name"] = "Launch" if eid == 1 else "Access"
        proc = {}
        if event.get("Image"):
            proc["file"] = {"path": event["Image"]}
        if event.get("CommandLine"):
            proc["cmd_line"] = event["CommandLine"]
        base["process"] = proc
        if event.get("TargetImage"):
            base["target_process"] = {"file": {"path": event["TargetImage"]}}
        if event.get("GrantedAccess"):
            base["granted_access"] = event["GrantedAccess"]
    elif source == "Sysmon" and eid == 13:
        base["class_uid"] = _OCSF_REGISTRY
        base["class_name"] = "Registry Key Activity"
        base["activity_name"] = "Modify"
        base["reg_key"] = {"path": event.get("TargetObject")}
    else:
        base["class_uid"] = 0
        base["class_name"] = "Base Event"

    labels = _labels(event)
    if labels:
        base.setdefault("unmapped", {})["siemlab"] = labels
    return base


# --- alert export ---------------------------------------------------------
def alert_to_ocsf_finding(alert: Alert) -> Dict[str, Any]:
    """Map an alert to an OCSF Detection Finding (class_uid 2004)."""
    return {
        "class_uid": 2004,
        "class_name": "Detection Finding",
        "time": alert.timestamp,
        "severity": alert.level.capitalize(),
        "finding_info": {
            "title": alert.rule_title,
            "uid": alert.rule_id,
            "types": alert.attack,
        },
        "device": {"hostname": alert.host},
        "count": len(alert.trigger_events),
        "metadata": {"product": {"name": "siemlab"}, "version": "1.1.0"},
    }


# --- batch helpers --------------------------------------------------------
_EVENT_EXPORTERS = {"ecs": to_ecs, "ocsf": to_ocsf}


def export_events(events: Iterable[Dict[str, Any]], schema: str) -> List[Dict[str, Any]]:
    schema = schema.lower()
    if schema == "raw":
        return [visible_fields(e) for e in events]
    if schema not in _EVENT_EXPORTERS:
        raise ValueError(f"unknown schema {schema!r} (choose raw, ecs, ocsf)")
    fn = _EVENT_EXPORTERS[schema]
    return [fn(e) for e in events]


def export_events_jsonl(events: Iterable[Dict[str, Any]], schema: str) -> str:
    import json

    return "\n".join(json.dumps(d) for d in export_events(events, schema))
