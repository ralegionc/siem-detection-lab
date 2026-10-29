"""Audit this lab's telemetry against the real SigmaHQ rule corpus.

This exists to answer the hardest question you can ask a project like this:
**the attacks and the detections were written by the same person, so how do you
know either is realistic?**

The answer is to bring in detections written by people who have never seen this
generator. If thousands of community rules — authored against real Windows
estates, real malware, real incident reports — fire on this synthetic telemetry
and land on the events labeled as attacks, that is independent corroboration
that the telemetry resembles what it claims to. If they *don't* fire, that is a
finding about the generator, and reporting it is more valuable than a clean
score.

Two useful outputs fall out of the same run:

* **Corroboration** — community rules that independently caught our attacks.
* **A compatibility report** — which Sigma features this engine does not yet
  implement, counted and named, because a rule skipped for `base64offset` is a
  gap in the engine, not evidence about the data.

Fetch the corpus first (see ``scripts/fetch_sigma.py``), then::

    python -m siemlab sigma-audit
"""

from __future__ import annotations

import glob
import os
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from .engine import run as run_engine
from .rules import Rule, UnsupportedRuleError

# Why a rule could not be loaded. Named, because "1200 rules skipped" is not a
# finding -- "1200 rules skipped, 900 of them for one unimplemented modifier" is.
SKIP_UNSUPPORTED_MODIFIER = "unsupported field modifier"
SKIP_NO_CONDITION = "no detection.condition"
SKIP_BAD_CONDITION = "condition not parseable"
SKIP_CORRELATION = "correlation rule (multi-event)"
SKIP_PARSE = "YAML parse error"
SKIP_OTHER = "other"


@dataclass
class SkippedRule:
    path: str
    category: str
    detail: str


@dataclass
class AuditResult:
    discovered: int = 0
    loaded: List[Rule] = field(default_factory=list)
    skipped: List[SkippedRule] = field(default_factory=list)

    # Populated by run_audit().
    fired: Dict[str, int] = field(default_factory=dict)          # rule_id -> alert count
    hit_attack: Dict[str, int] = field(default_factory=dict)     # rule_id -> alerts on attacks
    benign_only: Dict[str, int] = field(default_factory=dict)    # rule_id -> FP-only alert count
    rule_titles: Dict[str, str] = field(default_factory=dict)
    corroborated_techniques: Dict[str, set] = field(default_factory=lambda: defaultdict(set))
    total_events: int = 0
    attack_events: int = 0

    @property
    def skip_counts(self) -> Counter:
        return Counter(s.category for s in self.skipped)

    @property
    def n_corroborating(self) -> int:
        """Community rules that landed on at least one labeled attack event."""
        return len(self.hit_attack)


def load_sigma_tree(
    root: str,
    max_rules: Optional[int] = None,
    progress: Optional[Callable[[int, int], None]] = None,
) -> AuditResult:
    """Recursively load every Sigma rule under ``root``, tolerating failures.

    Unlike ``load_sigma_dir``, this never raises on a bad rule: it records why
    the rule was skipped and moves on. The skip breakdown is a deliverable.
    """
    from .sigma import load_sigma_file  # local import: keeps core engine light

    result = AuditResult()
    files = sorted(glob.glob(os.path.join(root, "**", "*.yml"), recursive=True))
    result.discovered = len(files)

    for i, path in enumerate(files):
        if max_rules is not None and len(result.loaded) >= max_rules:
            break
        if progress and i % 250 == 0:
            progress(i, len(files))
        try:
            result.loaded.append(load_sigma_file(path))
        except UnsupportedRuleError as exc:
            result.skipped.append(SkippedRule(path, SKIP_UNSUPPORTED_MODIFIER, str(exc)))
        except ValueError as exc:
            msg = str(exc)
            low = msg.lower()
            if "no detection.condition" in low:
                cat = SKIP_NO_CONDITION
            elif "unknown selection" in low or "condition" in low:
                cat = SKIP_BAD_CONDITION
            elif "correlation" in low:
                cat = SKIP_CORRELATION
            else:
                cat = SKIP_OTHER
            result.skipped.append(SkippedRule(path, cat, msg))
        except Exception as exc:  # malformed YAML, encoding issues, ...
            result.skipped.append(SkippedRule(path, SKIP_PARSE, f"{type(exc).__name__}: {exc}"))

    return result


def run_audit(result: AuditResult, events: List[Dict[str, Any]]) -> AuditResult:
    """Run every loaded community rule over the telemetry and score corroboration."""
    result.total_events = len(events)
    result.attack_events = sum(1 for e in events if e.get("_label") is not None)

    alerts = run_engine(result.loaded, events)

    for alert in alerts:
        rid = alert.rule_id
        result.rule_titles[rid] = alert.rule_title
        result.fired[rid] = result.fired.get(rid, 0) + 1

        labels = [e.get("_label") for e in alert.trigger_events if e.get("_label")]
        if labels:
            result.hit_attack[rid] = result.hit_attack.get(rid, 0) + 1
            for lab in labels:
                result.corroborated_techniques[lab].add(rid)

    for rid, count in result.fired.items():
        if rid not in result.hit_attack:
            result.benign_only[rid] = count

    return result


def format_audit(result: AuditResult, top_n: int = 10) -> str:
    lines: List[str] = []
    lines.append("=" * 74)
    lines.append("  SIGMA CORPUS AUDIT -- do independent rules corroborate this telemetry?")
    lines.append("=" * 74)
    lines.append(f"  rules discovered : {result.discovered}")
    lines.append(f"  rules loaded     : {len(result.loaded)}")
    lines.append(f"  rules skipped    : {len(result.skipped)}")
    lines.append("")

    if result.skipped:
        lines.append("  ENGINE COMPATIBILITY  (why rules could not be loaded)")
        lines.append("  " + "-" * 70)
        for cat, n in result.skip_counts.most_common():
            share = n / result.discovered if result.discovered else 0
            lines.append(f"    {cat:<34}{n:>6}  ({share:.0%} of corpus)")
        lines.append("  " + "-" * 70)
        lines.append("  These are gaps in THIS engine, not facts about the data.")
        lines.append("")

    lines.append("  CORROBORATION")
    lines.append(f"    events analyzed          : {result.total_events} "
                 f"({result.attack_events} labeled attack)")
    lines.append(f"    community rules that fired: {len(result.fired)}")
    lines.append(f"    ...landing on real attacks: {result.n_corroborating}")
    lines.append("")

    if result.corroborated_techniques:
        lines.append("  TECHNIQUES INDEPENDENTLY CORROBORATED")
        lines.append("  " + "-" * 70)
        for tech in sorted(result.corroborated_techniques):
            rids = result.corroborated_techniques[tech]
            sample = sorted(rids)[:2]
            shown = ", ".join(result.rule_titles.get(r, r)[:28] for r in sample)
            more = f" (+{len(rids) - len(sample)} more)" if len(rids) > len(sample) else ""
            lines.append(f"    {tech:<12}{len(rids):>4} rule(s)  e.g. {shown}{more}")
        lines.append("  " + "-" * 70)
        lines.append("")
    else:
        lines.append("  No community rule fired on a labeled attack event.")
        lines.append("  That is a finding about the generator's realism, not a pass.")
        lines.append("")

    if result.benign_only:
        lines.append(f"  NOISIEST COMMUNITY RULES ON OUR BENIGN BASELINE (top {top_n})")
        lines.append("  These fired without ever touching an attack: either our benign")
        lines.append("  layer is unrealistic, or these rules are genuinely noisy.")
        lines.append("  " + "-" * 70)
        worst: List[Tuple[str, int]] = sorted(
            result.benign_only.items(), key=lambda kv: -kv[1]
        )[:top_n]
        for rid, n in worst:
            title = result.rule_titles.get(rid, rid)
            lines.append(f"    {n:>6}  {title[:60]}")
        lines.append("  " + "-" * 70)
    lines.append("=" * 74)
    return "\n".join(lines)
