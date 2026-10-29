"""Command-line interface.

    python -m siemlab generate --out data/events.jsonl
    python -m siemlab detect   --events data/events.jsonl --rules detections
    python -m siemlab evaluate --events data/events.jsonl --rules detections
    python -m siemlab run       # generate + detect + evaluate in one shot
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List

from . import __version__
from .engine import Alert, run as run_engine
from .evaluate import evaluate, format_report
from .events import from_jsonl, to_jsonl
from .export import export_events_jsonl
from .generator import generate
from .rules import load_rules_from_dir

DEFAULT_RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "detections")


def _load_events(path: str):
    with open(path, "r", encoding="utf-8") as fh:
        return from_jsonl(fh.read())


def _alerts_to_json(alerts: List[Alert]) -> str:
    out = []
    for a in alerts:
        out.append({
            "rule_id": a.rule_id,
            "rule_title": a.rule_title,
            "level": a.level,
            "attack": a.attack,
            "timestamp": a.timestamp,
            "host": a.host,
            "trigger_count": len(a.trigger_events),
        })
    return json.dumps(out, indent=2)


def cmd_generate(args: argparse.Namespace) -> int:
    events = generate(
        seed=args.seed,
        duration_seconds=args.duration,
        baseline_rate_per_min=args.rate,
        n_incidents=args.incidents,
        dwell_range=(args.dwell_min, args.dwell_max),
    )
    schema = getattr(args, "schema", "labeled")
    if schema == "labeled":
        # Internal format: keeps the _label/_incident/_stage ground truth so the
        # file can be scored later by `detect`/`evaluate`.
        text = to_jsonl(events)
    else:
        # Downstream schema (raw/ecs/ocsf) for piping into a real SIEM.
        text = export_events_jsonl(events, schema)
    if args.out:
        os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print(f"wrote {len(events)} events ({schema}) -> {args.out}")
    else:
        print(text)
    return 0


def cmd_detect(args: argparse.Namespace) -> int:
    rules = load_rules_from_dir(args.rules)
    events = _load_events(args.events)
    alerts = run_engine(rules, events)
    print(f"loaded {len(rules)} rules, {len(events)} events -> {len(alerts)} alerts",
          file=sys.stderr)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(_alerts_to_json(alerts))
        print(f"wrote alerts -> {args.out}", file=sys.stderr)
    else:
        print(_alerts_to_json(alerts))
    return 0


def cmd_evaluate(args: argparse.Namespace) -> int:
    rules = load_rules_from_dir(args.rules)
    events = _load_events(args.events)
    alerts = run_engine(rules, events)
    report = evaluate(alerts, events)
    print(format_report(report))
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    rules = load_rules_from_dir(args.rules)
    events = generate(
        seed=args.seed,
        duration_seconds=args.duration,
        baseline_rate_per_min=args.rate,
        n_incidents=args.incidents,
        dwell_range=(args.dwell_min, args.dwell_max),
    )
    alerts = run_engine(rules, events)
    report = evaluate(alerts, events)
    print(format_report(report))
    return 0


def cmd_sweep(args: argparse.Namespace) -> int:
    from .sweep import format_sweep, run_sweep, to_csv

    rules = load_rules_from_dir(args.rules)
    if args.rates:
        rates = [float(x) for x in args.rates.split(",")]
    else:
        lo, hi, step = args.rate_min, args.rate_max, args.rate_step
        rates, r = [], lo
        while r <= hi + 1e-9:
            rates.append(round(r, 6))
            r += step
    print(f"sweeping {len(rates)} noise levels over {len(rules)} rules...", file=sys.stderr)
    result = run_sweep(
        rules, rates, seed=args.seed,
        duration_seconds=args.duration, n_incidents=args.incidents,
        progress=lambda r: print(f"  rate={r:g}/min", file=sys.stderr),
    )
    if args.csv:
        with open(args.csv, "w", encoding="utf-8") as fh:
            fh.write(to_csv(result))
        print(f"wrote sweep CSV -> {args.csv}", file=sys.stderr)
    print(format_sweep(result))
    return 0


def cmd_sigma_audit(args: argparse.Namespace) -> int:
    from .audit import format_audit, load_sigma_tree, run_audit

    if not os.path.isdir(args.sigma_dir):
        print(f"error: {args.sigma_dir} not found.\n"
              f"Fetch the corpus first:  python scripts/fetch_sigma.py",
              file=sys.stderr)
        return 2

    print(f"loading Sigma rules from {args.sigma_dir} ...", file=sys.stderr)
    result = load_sigma_tree(
        args.sigma_dir, max_rules=args.max_rules,
        progress=lambda i, n: print(f"  {i}/{n}", file=sys.stderr),
    )
    print(f"loaded {len(result.loaded)} rules; running against telemetry ...",
          file=sys.stderr)
    events = generate(
        seed=args.seed, duration_seconds=args.duration,
        baseline_rate_per_min=args.rate, n_incidents=args.incidents,
    )
    run_audit(result, events)
    print(format_audit(result))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="siemlab", description="SIEM detection-engineering lab")
    p.add_argument("--version", action="version", version=f"siemlab {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    def add_gen_opts(sp):
        sp.add_argument("--seed", type=int, default=1337)
        sp.add_argument("--duration", type=int, default=6 * 3600, help="seconds of telemetry")
        sp.add_argument("--rate", type=float, default=12.0, help="benign events per minute")
        sp.add_argument("--incidents", type=int, default=8,
                        help="number of multi-stage intrusions")
        sp.add_argument("--dwell-min", type=float, default=120.0,
                        help="min seconds an attacker waits between kill-chain stages")
        sp.add_argument("--dwell-max", type=float, default=900.0,
                        help="max seconds an attacker waits between kill-chain stages")

    g = sub.add_parser("generate", help="emit telemetry as JSONL")
    add_gen_opts(g)
    g.add_argument("--out", default="data/events.jsonl")
    g.add_argument("--schema", default="labeled",
                   choices=["labeled", "raw", "ecs", "ocsf"],
                   help="output schema: 'labeled' keeps ground truth for scoring; "
                        "raw/ecs/ocsf are for piping into a real SIEM")
    g.set_defaults(func=cmd_generate)

    d = sub.add_parser("detect", help="run rules over events, emit alerts")
    d.add_argument("--events", required=True)
    d.add_argument("--rules", default=DEFAULT_RULES_DIR)
    d.add_argument("--out", default=None)
    d.set_defaults(func=cmd_detect)

    e = sub.add_parser("evaluate", help="score rules against ground truth")
    e.add_argument("--events", required=True)
    e.add_argument("--rules", default=DEFAULT_RULES_DIR)
    e.set_defaults(func=cmd_evaluate)

    r = sub.add_parser("run", help="generate + detect + evaluate")
    add_gen_opts(r)
    r.add_argument("--rules", default=DEFAULT_RULES_DIR)
    r.set_defaults(func=cmd_run)

    s = sub.add_parser("sweep", help="vary the benign noise rate; chart precision decay")
    s.add_argument("--seed", type=int, default=1337)
    s.add_argument("--duration", type=int, default=6 * 3600)
    s.add_argument("--incidents", type=int, default=8)
    s.add_argument("--rules", default=DEFAULT_RULES_DIR)
    s.add_argument("--rates", default=None,
                   help="explicit comma-separated rates, e.g. 2,8,16,32,64")
    s.add_argument("--rate-min", type=float, default=2.0)
    s.add_argument("--rate-max", type=float, default=64.0)
    s.add_argument("--rate-step", type=float, default=10.0)
    s.add_argument("--csv", default=None, help="also write sweep results to this CSV")
    s.set_defaults(func=cmd_sweep)

    a = sub.add_parser(
        "sigma-audit",
        help="run the real SigmaHQ corpus against this telemetry (realism check)")
    a.add_argument("--sigma-dir", default=os.path.join("vendor", "sigma", "rules", "windows"),
                   help="path to a SigmaHQ rules tree (see scripts/fetch_sigma.py)")
    a.add_argument("--max-rules", type=int, default=None,
                   help="cap the number of rules loaded (for a quick pass)")
    a.add_argument("--seed", type=int, default=1337)
    a.add_argument("--duration", type=int, default=6 * 3600)
    a.add_argument("--rate", type=float, default=12.0)
    a.add_argument("--incidents", type=int, default=8)
    a.set_defaults(func=cmd_sigma_audit)

    return p


def main(argv: List[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
