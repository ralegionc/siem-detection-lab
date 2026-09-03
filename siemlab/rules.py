"""Sigma-inspired rule model and matcher.

A rule is a JSON document. Rules come in two flavors:

1. **Match rules** — every event that satisfies ``detection`` becomes an alert.
2. **Threshold rules** — events satisfying ``detection`` are grouped by
   ``threshold.group_by`` and only fire once a group accumulates
   ``threshold.count`` hits inside ``threshold.window_seconds`` (a sliding
   window). This is how you catch brute force without alerting on every single
   failed logon.

Field matching supports Sigma-style modifiers on the key::

    {"CommandLine|contains": "-enc"}      substring
    {"Image|endswith": "\\powershell.exe"} suffix
    {"Image|startswith": "C:\\Temp"}       prefix
    {"User|re": "^svc_"}                    regex
    {"event_id": 4625}                       exact
    {"event_id": [4625, 4771]}               list == OR

Within one selection dict, all keys must match (AND). A list *value* is OR.

The ``condition`` string composes named selections with ``and``/``or``/``not``
and parentheses, plus ``1 of them`` / ``all of them`` and wildcard forms like
``1 of sel_*``. It is deliberately a subset of real Sigma — enough to express
the detections in this lab without pulling in a full parser.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

_MODIFIERS = ("contains", "startswith", "endswith", "re")


def _match_field(event_val: Any, expected: Any, modifier: Optional[str]) -> bool:
    """Match a single event value against one expected value/modifier."""
    if isinstance(expected, list):
        return any(_match_field(event_val, e, modifier) for e in expected)

    if event_val is None:
        return False

    if modifier is None:
        # Exact match. Compare as strings when types differ so 4625 == "4625".
        if isinstance(event_val, bool) or isinstance(expected, bool):
            return event_val == expected
        if isinstance(event_val, (int, float)) and isinstance(expected, (int, float)):
            return event_val == expected
        return str(event_val).lower() == str(expected).lower()

    sval = str(event_val).lower()
    sexp = str(expected).lower()
    if modifier == "contains":
        return sexp in sval
    if modifier == "startswith":
        return sval.startswith(sexp)
    if modifier == "endswith":
        return sval.endswith(sexp)
    if modifier == "re":
        return re.search(str(expected), str(event_val), re.IGNORECASE) is not None
    raise ValueError(f"unknown modifier: {modifier}")


def _split_key(key: str) -> tuple[str, Optional[str]]:
    if "|" in key:
        base, mod = key.split("|", 1)
        if mod not in _MODIFIERS:
            raise ValueError(f"unknown field modifier '{mod}' in key '{key}'")
        return base, mod
    return key, None


def _match_selection(event: Dict[str, Any], selection: Dict[str, Any]) -> bool:
    for key, expected in selection.items():
        base, mod = _split_key(key)
        if not _match_field(event.get(base), expected, mod):
            return False
    return True


# --- condition evaluation -------------------------------------------------

_TOKEN_RE = re.compile(r"\(|\)|\band\b|\bor\b|\bnot\b|[A-Za-z0-9_\*]+", re.IGNORECASE)


def _resolve_wildcard(name: str, selection_names: List[str]) -> List[str]:
    if "*" in name:
        return [s for s in selection_names if fnmatch.fnmatch(s, name)]
    return [s for s in selection_names if s == name]


def _eval_condition(
    condition: str,
    selection_results: Dict[str, bool],
) -> bool:
    """Evaluate a Sigma-lite condition string against per-selection booleans."""
    names = list(selection_results.keys())

    # Expand the aggregate helpers into plain boolean expressions first.
    cond = condition.strip()
    cond = re.sub(r"\ball of them\b", "(" + " and ".join(names) + ")" if names else "False", cond, flags=re.I)
    cond = re.sub(r"\b1 of them\b", "(" + " or ".join(names) + ")" if names else "False", cond, flags=re.I)

    def expand_x_of(m: re.Match) -> str:
        qty, pat = m.group(1), m.group(2)
        matched = _resolve_wildcard(pat, names)
        if not matched:
            return "False"
        joiner = " or " if qty == "1" else " and "
        return "(" + joiner.join(matched) + ")"

    cond = re.sub(r"\b(1|all) of ([A-Za-z0-9_]*\*)", expand_x_of, cond, flags=re.I)

    tokens = _TOKEN_RE.findall(cond)
    pos = 0

    def peek() -> Optional[str]:
        return tokens[pos] if pos < len(tokens) else None

    def advance() -> str:
        nonlocal pos
        tok = tokens[pos]
        pos += 1
        return tok

    # Recursive descent: expr = or_expr
    def parse_or() -> bool:
        val = parse_and()
        while peek() and peek().lower() == "or":
            advance()
            val = parse_and() or val
        return val

    def parse_and() -> bool:
        val = parse_not()
        while peek() and peek().lower() == "and":
            advance()
            val = parse_not() and val
        return val

    def parse_not() -> bool:
        if peek() and peek().lower() == "not":
            advance()
            return not parse_not()
        return parse_atom()

    def parse_atom() -> bool:
        tok = peek()
        if tok == "(":
            advance()
            val = parse_or()
            if peek() != ")":
                raise ValueError(f"unbalanced parentheses in condition: {condition!r}")
            advance()
            return val
        tok = advance()
        low = tok.lower()
        if low in ("true", "false"):
            return low == "true"
        if tok not in selection_results:
            raise ValueError(f"unknown selection '{tok}' in condition: {condition!r}")
        return selection_results[tok]

    result = parse_or()
    if pos != len(tokens):
        raise ValueError(f"trailing tokens in condition: {condition!r}")
    return result


@dataclass
class Threshold:
    group_by: List[str]
    count: int
    window_seconds: float


@dataclass
class Rule:
    id: str
    title: str
    level: str = "medium"
    attack: List[str] = field(default_factory=list)
    description: str = ""
    logsource: Dict[str, Any] = field(default_factory=dict)
    selections: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    condition: str = ""
    threshold: Optional[Threshold] = None

    @property
    def is_threshold(self) -> bool:
        return self.threshold is not None

    def logsource_matches(self, event: Dict[str, Any]) -> bool:
        for key, val in self.logsource.items():
            if str(event.get(key, "")).lower() != str(val).lower():
                return False
        return True

    def matches(self, event: Dict[str, Any]) -> bool:
        """True if the event satisfies the rule's condition (ignores threshold)."""
        if not self.logsource_matches(event):
            return False
        results = {name: _match_selection(event, sel) for name, sel in self.selections.items()}
        return _eval_condition(self.condition, results)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Rule":
        detection = dict(data.get("detection", {}))
        condition = detection.pop("condition", None)
        if condition is None:
            raise ValueError(f"rule {data.get('id')!r} has no detection.condition")
        selections = {k: v for k, v in detection.items() if isinstance(v, dict)}
        if not selections:
            raise ValueError(f"rule {data.get('id')!r} has no selections")

        thr = None
        if "threshold" in data:
            t = data["threshold"]
            thr = Threshold(
                group_by=list(t.get("group_by", [])),
                count=int(t["count"]),
                window_seconds=float(t["window_seconds"]),
            )

        return cls(
            id=data["id"],
            title=data.get("title", data["id"]),
            level=data.get("level", "medium"),
            attack=list(data.get("attack", [])),
            description=data.get("description", ""),
            logsource=dict(data.get("logsource", {})),
            selections=selections,
            condition=condition,
            threshold=thr,
        )


def load_rules_from_dir(path: str) -> List[Rule]:
    """Load every rule in a directory: native JSON plus Sigma YAML (.yml/.yaml)."""
    import glob
    import json
    import os

    rules: List[Rule] = []
    for fp in sorted(glob.glob(os.path.join(path, "*.json"))):
        with open(fp, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        try:
            rules.append(Rule.from_dict(data))
        except (KeyError, ValueError) as exc:
            raise ValueError(f"failed to load rule {fp}: {exc}") from exc

    # Sigma YAML rules, if any live alongside the JSON. Imported lazily so the
    # core engine has no dependency on the Sigma module.
    if glob.glob(os.path.join(path, "*.yml")) or glob.glob(os.path.join(path, "*.yaml")):
        from .sigma import load_sigma_dir

        rules.extend(load_sigma_dir(path))
    return rules
