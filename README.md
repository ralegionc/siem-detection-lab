# SIEM Detection Lab

A self-contained detection-engineering playground. It **generates labeled,
multi-stage attack telemetry**, runs **Sigma-compatible detection rules** over
it, and **scores those rules honestly** — per-rule precision, ATT&CK technique
recall, and (the number that actually matters) **incident detection with mean
time-to-detect and stage-of-detection**.

The point isn't to reimplement Splunk. It's to practice the loop a detection
engineer lives in: *write a rule → measure how much real attack it catches →
measure how much analyst time it wastes → tighten it.* Because the telemetry is
labeled with ground truth, every alert is scored automatically.

Zero required dependencies. Pure Python standard library. Clone and run.

```bash
python -m siemlab run
```

```
========================================================================
  SIEM DETECTION LAB -- EVALUATION REPORT
========================================================================
  events analyzed : 4361
  alerts raised   : 909
  overall precision: 4% (share of alerts worth opening)

  PER-RULE PERFORMANCE
  --------------------------------------------------------------------
  rule                                  alerts    TP    FP    prec
  --------------------------------------------------------------------
  LSASS memory access                        6     6     0   100%
  RDP logon from external address            4     4     0   100%
  PowerShell encoded command                 3     3     0   100%
  Rundll32 accessing LSASS                   6     6     0   100%
  ...
  Any PowerShell execution (intenti...     880     3   877     0%
  --------------------------------------------------------------------

  TECHNIQUE COVERAGE
    recall: 100% (7/7 techniques seen)

  INCIDENT DETECTION  (the number that matters)
    incidents      : 8
    detected       : 100%
    mean time to detect  : 1s
    caught before lateral movement: 75%
  --------------------------------------------------------------------
  incident    stages            caught at    dwell                  by
  --------------------------------------------------------------------
  INC-001          6       initial_access      11s  auth-brute-force-s
  INC-003          2     lateral_movement       0s  lateral-rdp-extern
  INC-005          2    credential_access       0s   cred-lsass-access
  ...
========================================================================
```

Look at the `Any PowerShell execution` row: 880 alerts, 3 real catches, **0%
precision**. It catches the same encoded payload the tight `PowerShell encoded
command` rule does — and buries it under 877 false alarms. Same detection,
1/100th the signal. That gap is the entire discipline, and this lab lets you
*measure* it instead of hand-waving.

Then look at the incident table. Every intrusion was detected — but **INC-003
wasn't caught until lateral movement**, after the attacker had already pivoted
to another host. "Detected" isn't binary; *when* you detect decides whether it's
a contained incident or a breach. The lab scores that too.

## Why this exists

Most "I built a SIEM detection" projects stop at *the rule fired*. The
interesting questions are the ones a SOC lead asks next:

- **Coverage** — of the techniques an adversary used, how many did we catch at
  all? (technique recall)
- **Signal quality** — of the alerts we raised, how many were worth opening?
  (per-rule precision)
- **Speed** — how far into the kill chain did the attacker get before we saw
  them? (time-to-detect, stage-of-detection)
- **Robustness** — does that precision *hold* when the environment gets noisy,
  or does the rule fall apart under real traffic volume? (the noise sweep)

A rule that fires on everything has perfect recall and is useless. A rule that
never fires has perfect precision and is useless. The job is the trade-off, and
you can't tune a trade-off you don't measure.

## How it works

```
 generator.py  ->  events.jsonl  ->   engine.py   ->   alerts  ->  evaluate.py
 (multi-stage      (what a SIEM      (Sigma-lite      (with       (precision +
  incidents)        ingests)          rule matcher)    provenance)  MTTD + recall)
                         |
                    export.py -> ECS / OCSF -> a real SIEM
```

1. **Generate** (`siemlab/generator.py`) — a reproducible event stream: a benign
   baseline (normal logons, routine PowerShell, legit scheduled tasks, network
   shares) plus **multi-stage intrusions**. A single intruder brute-forces a
   host, runs an encoded payload, dumps credentials, installs persistence, then
   moves laterally — with realistic **dwell time** between stages. Not every
   intrusion starts at the front of the chain (an attacker with valid creds
   skips brute force), which is exactly the case that slips a naive rule and
   inflates dwell. Every event is stamped with technique, incident id, and
   kill-chain stage.

2. **Detect** (`siemlab/engine.py` + `siemlab/rules.py`) — a Sigma-inspired
   matcher. Field modifiers (`|contains`, `|startswith`, `|endswith`, `|re`),
   named selections composed with `and`/`or`/`not` and `1 of them` / `all of
   them`, and **threshold rules** with sliding time windows (so a brute-force
   burst is one alert, not one per failed logon).

3. **Evaluate** (`siemlab/evaluate.py`) — because ground truth is stapled to
   every event, each alert is scored automatically. Per-rule precision,
   technique recall, and **incident-level** metrics: was the intrusion caught,
   at which stage, and after how much dwell (MTTD).

4. **Export** (`siemlab/export.py`) — emit the same telemetry as **ECS** (Elastic
   Common Schema) or **OCSF** (Open Cybersecurity Schema Framework) so you can
   pipe it into a real SIEM and cross-check.

## Four things worth a look

### Multi-stage incidents + time-to-detect
Attacks are intrusions, not isolated events. The evaluator answers "did we catch
this *intrusion*, at which kill-chain stage, and how long did it dwell" — the
questions that separate a contained incident from a full IR.

### Real Sigma rules load directly
Drop a `.yml` [Sigma](https://github.com/SigmaHQ/sigma) rule into `detections/`
and it just works — [`detections/sigma_susp_rundll32.yml`](detections/sigma_susp_rundll32.yml)
is one, loaded natively alongside the JSON rules. `EventID` maps to `event_id`,
`tags: [attack.t1003.001]` becomes the ATT&CK mapping, and Sigma conditions
parse as-is. Uses PyYAML if installed, and a **bundled minimal YAML parser** if
not — so the zero-dependency promise holds.

### Export to ECS / OCSF
```bash
python -m siemlab generate --schema ecs  --out data/events.ecs.jsonl
python -m siemlab generate --schema ocsf --out data/events.ocsf.jsonl
```
Ground-truth labels are preserved under `labels.siemlab` (ECS) / `unmapped`
(OCSF), so the exported stream is both ingestible *and* still scorable.

### Noise-injection sweep
The killer question: does a rule's precision **survive real traffic volume**?
```bash
python -m siemlab sweep --rates 2,8,16,32,64,128
```
```
  PER-RULE PRECISION as noise climbs  (low ' '  ->  high '@')
  --------------------------------------------------------------------
  rule                                  chart         start    end
  --------------------------------------------------------------------
  LSASS memory access                   @@@@@@         100%   100%
  Brute force followed by success       @@@@@*         100%    67%
  Any PowerShell execution (intention...                 4%     0%
  --------------------------------------------------------------------
```
Read left-to-right as the environment gets noisier. Tight rules hold a flat line
near 100%. The broad PowerShell rule is a near-blank strip. And the brute-force
threshold rule **realistically decays 100% -> 67%** — benign failed logons
occasionally cluster past its threshold under load. That decay curve is the
quantitative argument for tightening a detection. `--csv out.csv` writes the raw
numbers for plotting elsewhere.

## Detections included

| Rule | ATT&CK | Technique | Format |
|------|--------|-----------|--------|
| Brute force followed by success | T1110 | Brute Force (threshold rule) | JSON |
| PowerShell encoded command | T1059.001 | Command & Scripting Interpreter | JSON |
| LSASS memory access | T1003.001 | OS Credential Dumping | JSON |
| Registry Run key persistence | T1547.001 | Boot/Logon Autostart | JSON |
| Scheduled task creation | T1053.005 | Scheduled Task | JSON |
| RDP logon from external address | T1021.001 | Remote Services | JSON |
| Local account created | T1136.001 | Create Account | JSON |
| Rundll32 accessing LSASS | T1003.001 | OS Credential Dumping | **Sigma YAML** |
| *Any PowerShell execution* | T1059.001 | **deliberately broad** — teaching foil | JSON |

## Usage

```bash
# One-shot: generate + detect + evaluate
python -m siemlab run

# Stages separately
python -m siemlab generate --out data/events.jsonl --seed 1337 --incidents 8
python -m siemlab detect   --events data/events.jsonl --rules detections
python -m siemlab evaluate --events data/events.jsonl --rules detections

# Export for a real SIEM
python -m siemlab generate --schema ecs  --out data/events.ecs.jsonl
python -m siemlab generate --schema ocsf --out data/events.ocsf.jsonl

# Sweep the noise floor
python -m siemlab sweep --rate-min 2 --rate-max 128 --rate-step 20 --csv sweep.csv

# Tune the scenario
python -m siemlab run --duration 28800 --rate 20 --incidents 12 \
    --dwell-min 300 --dwell-max 1800 --seed 42
```

## Write your own detection

JSON — drop a file in `detections/`:

```json
{
  "id": "my-rule",
  "title": "Office spawning a shell",
  "level": "high",
  "attack": ["T1059.003"],
  "logsource": {"source": "Sysmon"},
  "detection": {
    "selection": {
      "event_id": 1,
      "ParentImage|endswith": "\\winword.exe",
      "Image|endswith": "\\cmd.exe"
    },
    "condition": "selection"
  }
}
```

...or **Sigma YAML** — the same directory accepts real Sigma rules. Re-run
`python -m siemlab run` and read your rule's row. Too many false positives? Add a
`filter` selection and change the condition to `selection and not filter`, then
run `sweep` to confirm it holds under load. That edit-measure loop is the whole
exercise.

## Tests

```bash
python -m unittest discover -s tests -v
```

25 tests: the field matcher, condition parser, sliding-window thresholds,
multi-stage incident scoring, Sigma import (both the PyYAML and bundled-parser
paths), ECS/OCSF export, and the noise sweep's decay invariant.

## Project layout

```
SIEM Detection Lab/
  siemlab/
    events.py       normalized event schema + ground-truth labeling
    generator.py    multi-stage ATT&CK intrusions + benign baseline
    rules.py        Sigma-inspired rule model, matcher, condition parser
    engine.py       runs rules over events, sliding-window thresholds
    evaluate.py     precision / recall / MTTD / stage-of-detection
    sigma.py        import real Sigma YAML (PyYAML or bundled fallback)
    export.py       ECS + OCSF schema exporters
    sweep.py        noise-injection precision-decay sweep
    cli.py          generate / detect / evaluate / run / sweep
  detections/       rules as JSON and Sigma YAML (edit these)
  tests/            unit + end-to-end tests
```

## Optional

PyYAML is used if present (faster, fully spec-compliant Sigma parsing) but is not
required — the bundled parser covers the Sigma subset. To install it anyway:

```bash
pip install pyyaml
```
