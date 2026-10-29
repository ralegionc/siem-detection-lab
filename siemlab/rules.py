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

# Value modifiers this engine implements. Real Sigma defines more
# (base64offset, cidr, windash, expand, ...); rules using those are rejected at
# load time with a named reason rather than silently mismatching -- see
# UnsupportedRuleError and the `sigma-audit` command.
_MATCH_MODIFIERS = ("contains", "startswith", "endswith", "re", "cased")
_QUANTIFIER_MODIFIERS = ("all",)
_MODIFIERS = _MATCH_MODIFIERS + _QUANTIFIER_MODIFIERS


class UnsupportedRuleError(ValueError):
    """A rule uses a Sigma feature this engine does not implement."""


def _match_field(event_val: Any, expected: Any, modifier: Optional[str],
                 require_all: bool = False) -> bool:
    """Match a single event value against one expected value/modifier.

    A list of expected values is OR by default; with the Sigma ``|all``
    modifier it becomes AND (every listed value must match).
    """
    if isinstance(expected, list):
        combine = all if require_all else any
        return combine(_match_field(event_val, e, modifier) for e in expected)

    # Sigma uses a null value to mean "this field must be absent".
    if expected is None:
        return event_val is None

    if event_val is None:
        return False

    if modifier == "cased":
        return str(event_val) == str(expected)

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


def _split_key(key: str) -> tuple[str, Optional[str], bool]:
    """Split ``Field|mod|mod`` into (field, match_modifier, require_all).

    Sigma allows chained modifiers, e.g. ``CommandLine|contains|all``.
    """
    if "|" not in key:
        return key, None, False
    base, *mods = key.split("|")
    match_mod: Optional[str] = None
    require_all = False
    for mod in mods:
        low = mod.lower()
        if low in _QUANTIFIER_MODIFIERS:
            require_all = True
        elif low in _MATCH_MODIFIERS:
            if match_mod is not None:
                raise UnsupportedRuleError(
                    f"multiple match modifiers ('{match_mod}', '{low}') in key '{key}'"
                )
            match_mod = low
        else:
            raise UnsupportedRuleError(f"unsupported field modifier '{mod}' in key '{key}'")
    return base, match_mod, require_all


def _match_selection(event: Dict[str, Any], selection: Dict[str, Any]) -> bool:
    for key, expected in selection.items():
        base, mod, require_all = _split_key(key)
        if not _match_field(event.get(base), expected, mod, require_all):
            return False
    return True


# --- condition evaluation -------------------------------------------------

_TOKEN_RE = re.compile(r"\(|\)|\band\b|\bor\b|\bnot\b|[A-Za-z0-9_\*]+", re.IGNORECASE)


def _resolve_wildcard(name: str, selection_names: List[str]) -> List[str]:
    if "*" in name:
        return [s for s in selection_names if fnmatch.fnmatch(s, name)]
    return [s for s in selection_names if s == name]


# Expanding and tokenizing a condition depends only on the condition string and
# the set of selection names -- never on the event. Doing it per event made rule
# evaluation quadratic in the worst case; caching it is what makes auditing
# thousands of real Sigma rules against a full event stream tractable.
_TOKEN_CACHE: Dict[tuple, List[str]] = {}


def _condition_tokens(condition: str, names: List[str]) -> List[str]:
    key = (condition, tuple(names))
    cached = _TOKEN_CACHE.get(key)
    if cached is None:
        cached = _tokenize_condition(condition, names)
        _TOKEN_CACHE[key] = cached
    return cached


def _tokenize_condition(condition: str, names: List[str]) -> List[str]:
    """Expand aggregate helpers, then tokenize. Event-independent."""
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
    return _TOKEN_RE.findall(cond)


def _eval_condition(condition: str, selection_results: Dict[str, bool]) -> bool:
    """Evaluate a Sigma-lite condition string against per-selection booleans."""
    tokens = _condition_tokens(condition, list(selection_results.keys()))
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

        # Validate eagerly: a rule that uses an unimplemented Sigma feature must
        # fail at load with a named reason, not silently mismatch at run time or
        # explode halfway through an event stream.
        for name, sel in selections.items():
            # An empty selection matches every event vacuously, which would turn
            # the rule into a firehose that appears to detect everything. Always
            # a conversion artifact, never intent.
            if not sel:
                raise UnsupportedRuleError(
                    f"selection '{name}' has no field/value pairs "
                    f"(keyword-list or unsupported selection form)"
                )
            for key in sel:
                _split_key(key)  # raises UnsupportedRuleError

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
