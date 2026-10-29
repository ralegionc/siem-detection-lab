"""Import genuine Sigma rules (https://github.com/SigmaHQ/sigma).

Sigma is the community standard for shareable, vendor-neutral detections. This
module reads a Sigma YAML rule and converts it into this lab's ``Rule`` model,
so you can point the engine at real-world rules — thousands of them exist — not
just the JSON in ``detections/``.

To honor the lab's zero-dependency promise it uses PyYAML when installed and
otherwise falls back to a small block-YAML parser covering the subset Sigma
rules actually use (indented maps, ``- `` lists, scalars, inline flow lists).

Field alignment: Sigma's ``EventID`` maps to this lab's ``event_id``; other
Sigma field names (``Image``, ``CommandLine``, ``TargetImage``, ...) already
match the generated telemetry. ``|contains|startswith|endswith|re`` modifiers
carry across unchanged. ``tags: [attack.t1059.001]`` becomes ``attack:
["T1059.001"]``. Sigma conditions (``selection and not filter``, ``1 of
selection_*``, ``all of them``) are exactly what the engine's parser accepts.
"""

from __future__ import annotations

import glob
import os
import re
from typing import Any, Dict, List

from .rules import Rule, UnsupportedRuleError

# Sigma field name -> this lab's event field name.
FIELD_ALIASES = {
    "eventid": "event_id",
    "logontype": "LogonType",
}


# --------------------------------------------------------------------------
# Minimal YAML (fallback when PyYAML is unavailable)
# --------------------------------------------------------------------------
def _coerce_scalar(text: str) -> Any:
    t = text.strip()
    if t == "" or t in ("~", "null", "Null", "NULL"):
        return None
    if (t[0], t[-1]) in (('"', '"'), ("'", "'")) and len(t) >= 2:
        return t[1:-1]
    low = t.lower()
    if low == "true":
        return True
    if low == "false":
        return False
    if re.fullmatch(r"-?\d+", t):
        return int(t)
    if re.fullmatch(r"-?\d+\.\d+", t):
        return float(t)
    if t.startswith("[") and t.endswith("]"):  # inline flow list
        inner = t[1:-1].strip()
        if not inner:
            return []
        return [_coerce_scalar(x) for x in _split_flow(inner)]
    if t.startswith("{") and t.endswith("}"):  # inline flow map
        inner = t[1:-1].strip()
        out: Dict[str, Any] = {}
        if inner:
            for pair in _split_flow(inner):
                k, _, v = pair.partition(":")
                out[k.strip()] = _coerce_scalar(v)
        return out
    return t


def _split_flow(text: str) -> List[str]:
    """Split a flow collection body on commas not nested in brackets/quotes."""
    parts, depth, cur, quote = [], 0, [], None
    for ch in text:
        if quote:
            cur.append(ch)
            if ch == quote:
                quote = None
        elif ch in ("'", '"'):
            quote = ch
            cur.append(ch)
        elif ch in "[{":
            depth += 1
            cur.append(ch)
        elif ch in "]}":
            depth -= 1
            cur.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if cur:
        parts.append("".join(cur))
    return [p.strip() for p in parts if p.strip()]


def _mini_yaml(text: str) -> Dict[str, Any]:
    """Parse the Sigma-relevant subset of YAML. Not a general YAML engine."""
    # Strip comments and blank lines, keep (indent, content) pairs.
    lines = []
    for raw in text.splitlines():
        # Drop full-line comments; leave inline '#' inside values alone-ish.
        if raw.strip().startswith("#") or not raw.strip():
            continue
        if raw.strip() in ("---", "..."):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        lines.append((indent, raw.strip()))

    pos = 0

    def parse_block(min_indent: int):
        nonlocal pos
        # Decide list vs map by the first line at this level.
        if pos >= len(lines):
            return None
        indent, content = lines[pos]
        if content.startswith("- "):
            return parse_list(indent)
        return parse_map(indent)

    def consume_block_scalar(indent: int, fold: bool) -> str:
        nonlocal pos
        chunks: List[str] = []
        while pos < len(lines) and lines[pos][0] > indent:
            chunks.append(lines[pos][1])
            pos += 1
        return (" " if fold else "\n").join(chunks)

    def parse_map(indent: int) -> Dict[str, Any]:
        nonlocal pos
        result: Dict[str, Any] = {}
        while pos < len(lines):
            cur_indent, content = lines[pos]
            if cur_indent < indent or content.startswith("- "):
                break
            if cur_indent > indent:
                # Stray over-indented line with no owning key; skip defensively.
                pos += 1
                continue
            key, sep, val = content.partition(":")
            key = key.strip()
            val = val.strip()
            pos += 1
            if val in (">", "|", ">-", "|-", ">+", "|+"):
                # YAML block scalar: gather the more-indented continuation lines.
                result[key] = consume_block_scalar(indent, fold=val.startswith(">"))
            elif val == "":
                # Nested block belongs to this key.
                if pos < len(lines) and lines[pos][0] > indent:
                    result[key] = parse_block(lines[pos][0])
                else:
                    result[key] = None
            else:
                result[key] = _coerce_scalar(val)
        return result

    def parse_list(indent: int) -> List[Any]:
        nonlocal pos
        items: List[Any] = []
        while pos < len(lines):
            cur_indent, content = lines[pos]
            if cur_indent != indent or not content.startswith("- "):
                break
            item = content[2:].strip()
            if ":" in item and not item.startswith(("'", '"', "[", "{")):
                # A list element that is itself a map. Rewrite so parse_map sees
                # the first pair at a virtual deeper indent, then continue.
                lines[pos] = (indent + 2, item)
                items.append(parse_map(indent + 2))
            else:
                items.append(_coerce_scalar(item))
                pos += 1
        return items

    return parse_map(0) if lines else {}


def load_yaml(text: str) -> Dict[str, Any]:
    try:
        import yaml  # type: ignore

        return yaml.safe_load(text)
    except ImportError:
        return _mini_yaml(text)


# --------------------------------------------------------------------------
# Sigma -> Rule conversion
# --------------------------------------------------------------------------
def _map_logsource(logsource: Dict[str, Any]) -> Dict[str, Any]:
    service = str(logsource.get("service", "")).lower()
    category = str(logsource.get("category", "")).lower()
    if service in ("security", "windows-security") or category in (
        "authentication", "logon"
    ):
        return {"source": "Security"}
    if service == "sysmon" or category in (
        "process_creation", "registry_set", "registry_event",
        "image_load", "process_access", "network_connection",
    ):
        return {"source": "Sysmon"}
    if service == "powershell" or "powershell" in category:
        return {"source": "PowerShell"}
    return {}  # match any source


def _alias_selection(sel: Any) -> Any:
    if isinstance(sel, list):
        return [_alias_selection(s) for s in sel]
    if not isinstance(sel, dict):
        return sel
    out: Dict[str, Any] = {}
    for key, val in sel.items():
        base, _, mod = key.partition("|")
        base = FIELD_ALIASES.get(base.lower(), base)
        out[base + ("|" + mod if mod else "")] = val
    return out


def _tags_to_attack(tags: Any) -> List[str]:
    out: List[str] = []
    for tag in tags or []:
        m = re.match(r"attack\.(t\d{4}(?:\.\d{3})?)", str(tag), re.IGNORECASE)
        if m:
            out.append(m.group(1).upper())
    return out


def sigma_to_rule_dict(doc: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a parsed Sigma document into this lab's rule dict."""
    detection = dict(doc.get("detection", {}))
    condition = detection.pop("condition", None)
    if condition is None:
        raise ValueError(f"Sigma rule {doc.get('id')!r} has no detection.condition")
    if isinstance(condition, list):
        # Sigma allows a list of conditions (implicit OR). Join them.
        condition = " or ".join(f"({c})" for c in condition)

    # A Sigma selection whose value is a list-of-maps means "any of these";
    # our engine treats a list value on a field as OR, but a list *selection*
    # needs flattening. We keep only dict selections and alias their fields.
    selections: Dict[str, Any] = {}
    for name, body in detection.items():
        # Sigma "keywords" rules select on bare strings with no field, which a
        # field-based matcher cannot express. Reject rather than silently
        # converting to an empty (match-everything) selection.
        if isinstance(body, list) and not any(isinstance(x, dict) for x in body):
            raise UnsupportedRuleError(
                f"selection '{name}' is a keyword list, not field/value pairs"
            )
        if body is None:
            raise UnsupportedRuleError(f"selection '{name}' is empty")
        aliased = _alias_selection(body)
        if isinstance(aliased, list):
            # Merge list-of-maps into one map with OR'd list values where keys
            # collide; distinct keys just coexist (all must match is rare here).
            merged: Dict[str, Any] = {}
            for entry in aliased:
                if isinstance(entry, dict):
                    for k, v in entry.items():
                        if k in merged:
                            ex = merged[k] if isinstance(merged[k], list) else [merged[k]]
                            add = v if isinstance(v, list) else [v]
                            merged[k] = ex + add
                        else:
                            merged[k] = v
            selections[name] = merged
        elif isinstance(aliased, dict):
            selections[name] = aliased

    detection_out: Dict[str, Any] = dict(selections)
    detection_out["condition"] = condition

    return {
        "id": doc.get("id") or doc.get("title", "sigma-rule"),
        "title": doc.get("title", doc.get("id", "sigma rule")),
        "level": str(doc.get("level", "medium")).lower(),
        "attack": _tags_to_attack(doc.get("tags")),
        "description": doc.get("description", ""),
        "logsource": _map_logsource(doc.get("logsource", {}) or {}),
        "detection": detection_out,
    }


def load_sigma_file(path: str) -> Rule:
    with open(path, "r", encoding="utf-8") as fh:
        doc = load_yaml(fh.read())
    if not isinstance(doc, dict):
        raise ValueError(f"{path}: not a single Sigma document")
    return Rule.from_dict(sigma_to_rule_dict(doc))


def load_sigma_dir(path: str) -> List[Rule]:
    rules: List[Rule] = []
    for pattern in ("*.yml", "*.yaml"):
        for fp in sorted(glob.glob(os.path.join(path, pattern))):
            try:
                rules.append(load_sigma_file(fp))
            except (KeyError, ValueError) as exc:
                raise ValueError(f"failed to load Sigma rule {fp}: {exc}") from exc
    return rules
