"""Noise-injection sweep: find where each rule starts drowning.

A rule's precision is not a fixed property — it depends on how much benign
traffic surrounds the attack. A rule that looks perfect on a quiet test set can
fall apart in a busy environment where its selection also matches everyday
activity. The only way to know is to sweep the noise floor and watch.

This sweeps the benign event rate across a range, holds the attacks fixed, and
records per-rule precision and overall alert volume at each level. The output is
a plain-text table plus an ASCII precision-vs-noise chart — no plotting library,
so it runs anywhere. The shape you're looking for: tight rules hold a flat line
near 100%; broad rules decay toward zero as the noise climbs. That decay curve
is the argument for tightening a detection, made quantitative.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from .engine import run as run_engine
from .evaluate import evaluate
from .generator import generate
from .rules import Rule


@dataclass
class SweepPoint:
    rate: float
    total_alerts: int
    overall_precision: float
    rule_precision: Dict[str, float] = field(default_factory=dict)
    rule_fp: Dict[str, int] = field(default_factory=dict)
    incident_recall: float = 0.0


@dataclass
class SweepResult:
    rates: List[float]
    points: List[SweepPoint]
    rule_titles: Dict[str, str]

    def series(self, rule_id: str) -> List[float]:
        return [p.rule_precision.get(rule_id, float("nan")) for p in self.points]


def run_sweep(
    rules: List[Rule],
    rates: List[float],
    seed: int = 1337,
    duration_seconds: int = 6 * 3600,
    n_incidents: int = 8,
    progress: Optional[Callable[[float], None]] = None,
) -> SweepResult:
    points: List[SweepPoint] = []
    titles: Dict[str, str] = {}

    for rate in rates:
        if progress:
            progress(rate)
        # Same seed + same attacks across the sweep; only the benign rate moves,
        # so any change in precision is attributable to noise alone.
        events = generate(
            seed=seed,
            duration_seconds=duration_seconds,
            baseline_rate_per_min=rate,
            n_incidents=n_incidents,
        )
        report = evaluate(run_engine(rules, events), events)
        pt = SweepPoint(
            rate=rate,
            total_alerts=report.total_alerts,
            overall_precision=report.overall_precision,
            incident_recall=report.incident_recall,
        )
        for rid, score in report.rule_scores.items():
            pt.rule_precision[rid] = score.precision
            pt.rule_fp[rid] = score.false_positives
            titles[rid] = score.title
        points.append(pt)

    return SweepResult(rates=list(rates), points=points, rule_titles=titles)


def _sparkline(values: List[float]) -> str:
    """Render a 0..1 series as a unicode-free ASCII bar strip."""
    ramp = " .:-=+*#%@"  # 10 levels, low -> high
    out = []
    for v in values:
        if v != v:  # NaN: rule never fired at this noise level
            out.append(" ")
            continue
        idx = min(len(ramp) - 1, max(0, int(round(v * (len(ramp) - 1)))))
        out.append(ramp[idx])
    return "".join(out)


def format_sweep(result: SweepResult) -> str:
    lines: List[str] = []
    lines.append("=" * 74)
    lines.append("  NOISE-INJECTION SWEEP  (precision vs. benign event rate)")
    lines.append("=" * 74)
    header_rates = "  ".join(f"{r:g}" for r in result.rates)
    lines.append(f"  benign events/min sweept: {header_rates}")
    lines.append("")

    # Volume + overall precision at each rate.
    lines.append(f"  {'rate/min':>9}{'alerts':>9}{'overall prec':>15}{'incident recall':>18}")
    lines.append("  " + "-" * 68)
    for p in result.points:
        lines.append(
            f"  {p.rate:>9g}{p.total_alerts:>9}{p.overall_precision:>14.0%}"
            f"{p.incident_recall:>17.0%}"
        )
    lines.append("  " + "-" * 68)
    lines.append("")

    # Per-rule precision decay chart.
    lines.append("  PER-RULE PRECISION as noise climbs  (low ' '  ->  high '@')")
    lines.append("  " + "-" * 68)
    lines.append(f"  {'rule':<38}{'chart':<12}{'start':>7}{'end':>7}")
    lines.append("  " + "-" * 68)
    for rid in sorted(result.rule_titles):
        series = result.series(rid)
        title = result.rule_titles[rid]
        title = (title[:35] + "...") if len(title) > 38 else title
        strip = _sparkline(series)
        start = next((v for v in series if v == v), float("nan"))
        end = next((v for v in reversed(series) if v == v), float("nan"))
        s = "  --" if start != start else f"{start:>6.0%}"
        e = "  --" if end != end else f"{end:>6.0%}"
        lines.append(f"  {title:<38}{strip:<12}{s:>7}{e:>7}")
    lines.append("  " + "-" * 68)
    lines.append("  Read left->right as the environment gets noisier. A rule whose")
    lines.append("  strip fades from '@' toward ' ' is losing precision to false")
    lines.append("  positives and needs tightening.")
    lines.append("=" * 74)
    return "\n".join(lines)


def to_csv(result: SweepResult) -> str:
    """Machine-readable sweep output for plotting elsewhere."""
    import io

    rule_ids = sorted(result.rule_titles)
    buf = io.StringIO()
    header = ["rate", "total_alerts", "overall_precision", "incident_recall"]
    header += [f"prec:{r}" for r in rule_ids]
    buf.write(",".join(header) + "\n")
    for p in result.points:
        row = [f"{p.rate:g}", str(p.total_alerts),
               f"{p.overall_precision:.4f}", f"{p.incident_recall:.4f}"]
        for rid in rule_ids:
            v = p.rule_precision.get(rid)
            row.append("" if v is None else f"{v:.4f}")
        buf.write(",".join(row) + "\n")
    return buf.getvalue()
