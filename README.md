# SIEM Detection Lab

[![tests](https://github.com/ralegionc/siem-detection-lab/actions/workflows/tests.yml/badge.svg)](https://github.com/ralegionc/siem-detection-lab/actions/workflows/tests.yml)
![python](https://img.shields.io/badge/python-3.9%2B-blue)
![dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)

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
  events analyzed : 4652
  alerts raised   : 881
  overall precision: 4% (share of alerts worth opening)

  PER-RULE PERFORMANCE
  --------------------------------------------------------------------
  rule                                  alerts    TP    FP    prec
  --------------------------------------------------------------------
  LSASS memory access                        4     4     0   100%
  RDP logon from external address            7     7     0   100%
  PowerShell encoded command                 3     3     0   100%
  Rundll32 accessing LSASS                   4     4     0   100%
  ...
  Any PowerShell execution (intenti...     851     3   848     0%
  --------------------------------------------------------------------

  TECHNIQUE COVERAGE
    recall: 100% (7/7 techniques seen)

  INCIDENT DETECTION  (the number that matters)
    incidents      : 8
    detected       : 100%
    mean time to detect  : 2s
    caught before lateral movement: 50%
  --------------------------------------------------------------------
  incident    stages            caught at    dwell                  by
  --------------------------------------------------------------------
  INC-001          6       initial_access      10s  auth-brute-force-s
  INC-003          2     lateral_movement       0s  lateral-rdp-extern
  INC-005          2          persistence       0s  persist-schtasks-c
  ...
========================================================================
```

Look at the `Any PowerShell execution` row: 851 alerts, 3 real catches, **0%
precision**. It catches the same encoded payload the tight `PowerShell encoded
command` rule does — and buries it under 848 false alarms. Same detection,
1/100th the signal. That gap is the entire discipline, and this lab lets you
*measure* it instead of hand-waving.

Then look at the incident table. Every intrusion was detected — but **INC-003
wasn't caught until lateral movement**, after the attacker had already pivoted
to another host. "Detected" isn't binary; *when* you detect decides whether it's
a contained incident or a breach. The lab scores that too.

## The hard part: benign activity that looks like an attack

A detection that only has to tell an attack apart from *obviously not an attack*
has an easy job, and a lab that only tests that is rigged. So the benign baseline
deliberately includes **hard negatives** — legitimate activity that trips each
rule for real:

| Hard negative | Why it's benign | Which rule it breaks |
|---|---|---|
| Backup agent opens LSASS with `0x1410` | EDR and backup tools do this hourly | LSASS memory access |
| **Signed** `System32\rundll32.exe` opens LSASS | Same filename as the attack, different provenance | Rundll32 accessing LSASS |
| Management agent runs `-EncodedCommand` | Intune/SCCM ship base64 payloads | PowerShell encoded command |
| `msiexec` runs `schtasks /create` | Installers create tasks constantly | Scheduled task creation |
| Installer writes a Run key | OneDrive/Teams register autostart | Run key persistence |
| Helpdesk creates an account | Onboarding | Local account created |
| Admin RDPs from the office's public IP | External, but expected | RDP from external address |
| Service account with a stale password retries | Identical shape to brute force | Brute force |

Point the **untuned** rules at that and they collapse:

```bash
python -m siemlab run --rules detections-untuned   # the "before"
python -m siemlab run                              # the tuned "after"
```

| Rule | Untuned | Tuned | False positives |
|---|---|---|---|
| RDP logon from external address | 16% | **100%** | 36 → 0 |
| Rundll32 accessing LSASS *(Sigma)* | 13% | **100%** | 27 → 0 |
| Registry Run key persistence | 12% | **100%** | 28 → 0 |
| PowerShell encoded command | 8% | **100%** | 33 → 0 |
| Scheduled task creation | 8% | **100%** | 37 → 0 |
| Local account created | 7% | **100%** | 41 → 0 |
| LSASS memory access | 6% | **100%** | 60 → 0 |
| Brute force followed by success | 6% | **100%** | 33 → 0 |
| *Any PowerShell execution (foil)* | 0% | 0% | 848 → 848 |

Technique and incident recall stay at **100% throughout** — the tuning costs no
coverage. Both rule sets ship, so the before/after is reproducible rather than a
claim.

The filters that fix this are the interesting part, because none of them key on
a memorized value:

- **Provenance, not filename.** The signed `rundll32` case can't be separated by
  name — only by where the binary lives. That's also why filename-only matching
  is trivially evaded.
- **Parent process, not the flag.** `-EncodedCommand` isn't suspicious; a
  management agent spawning it is expected, `cmd.exe` spawning it is not.
- **Where the autostart points**, not that a Run key was touched.
- **Source address**, not "external".

Because they're structural, they generalize: precision holds at 100% across
unseen seeds (the test suite asserts this on seeds 7, 42 and 99), so this is
tuning rather than overfitting to one benign draw.

## Does that precision survive a noisy network?

A rule's precision isn't a fixed property — it depends on how much benign
traffic surrounds the attack. So sweep the noise floor and watch. Hold the
attacks fixed, raise the benign rate 64x, and chart what happens:

```bash
python -m siemlab sweep --rates 2,8,16,32,64,128                          # tuned
python -m siemlab sweep --rates 2,8,16,32,64,128 --rules detections-untuned
```

**Untuned rules** — every one bleeds out as the environment gets busier:

```
  PER-RULE PRECISION as noise climbs  (low '.'  ->  high '@'; blank = no alerts)
  --------------------------------------------------------------------
  rule                                  chart         start    end
  --------------------------------------------------------------------
  Registry Run key persistence          %.:...          83%     1%
  RDP logon from external address       +:::..          54%     1%
  Brute force followed by success       +::...          50%     1%
  PowerShell encoded command            +::...          50%     2%
  Rundll32 accessing LSASS              =::...          36%     2%
  Local account created                 =:.:..          33%     1%
  LSASS memory access                   -.:...          24%     1%
  --------------------------------------------------------------------
```

**Tuned rules** — flat, all the way out:

```
  Brute force followed by success       @@@@@@         100%   100%
  LSASS memory access                   @@@@@@         100%   100%
  RDP logon from external address       @@@@@@         100%   100%
  Local account created                 @@@@@@         100%   100%
  PowerShell encoded command            @@@@@@         100%   100%
  Rundll32 accessing LSASS              @@@@@@         100%   100%
  Any PowerShell execution (intention...                 3%     0%
```

That contrast is the argument for structural filters, made quantitative. The
untuned rules aren't merely *less* precise — they degrade with load, so they
look acceptable in a quiet test environment and become unusable in production.
The tuned versions don't degrade at all, because what they key on (binary
provenance, parent process, source address) doesn't get more common when traffic
does. Only the deliberately-broad foil stays flat on the floor.

Worth noting what stays constant: **incident recall is 100% at every noise
level**. Noise doesn't cost coverage here, it costs the analyst's attention.
Those are different failures, and collapsing them into one "accuracy" number
hides the one that actually burns out a SOC. `--csv out.csv` writes the raw
numbers for plotting.

## "You wrote both the attacks and the rules" — so audit against strangers' rules

That's the fair objection to any lab like this, and the honest answer is to
bring in detections written by people who have never seen this generator. The
[SigmaHQ](https://github.com/SigmaHQ/sigma) corpus is ~2,400 Windows rules
authored against real estates, real malware, and real incident reports.

```bash
python scripts/fetch_sigma.py     # shallow sparse clone -> vendor/ (gitignored)
python -m siemlab sigma-audit
```

```
  rules discovered : 2409
  rules loaded     : 2289
  rules skipped    :  120

  ENGINE COMPATIBILITY  (why rules could not be loaded)
    unsupported field modifier           120  (5% of corpus)

  CORROBORATION
    events analyzed          : 4652 (54 labeled attack)
    community rules that fired: 8
    ...landing on real attacks: 8

  TECHNIQUES INDEPENDENTLY CORROBORATED
    T1053.005      3 rule(s)  e.g. Windows Shell/Scripting Proc, Suspicious Schtasks Schedule (+1 more)
    T1059.001      2 rule(s)  e.g. Non Interactive PowerShell P, Suspicious Execution of Powe
    T1136.001      1 rule(s)  e.g. Local User Creation
    T1547.001      2 rule(s)  e.g. New RUN Key Pointing to Susp, CurrentVersion Autorun Keys
```

**What passes:** the engine loads **95% of the real corpus** (2289/2409), so
Sigma compatibility is not a toy claim. And **8 community rules fired, all 8 of
them on labeled attack events — zero false corroboration**. Rules like *"New RUN
Key Pointing to Suspicious Folder"* and *"Scheduled Task Creation Via Schtasks"*,
written by strangers, independently catch this generator's attacks. That's real
evidence the telemetry resembles what it claims to.

**What doesn't, and why.** Only **4 of 7** techniques are corroborated. T1110,
T1003.001 and T1021.001 are not, and the reason is worth stating precisely
because it's a limitation of the generator, not a rounding error:

- Community LSASS rules key on **named tooling** — `comsvcs.dll` minidump,
  procdump, HandleKatz handle duplication, specific `GrantedAccess` masks and
  `CallTrace` offsets. This lab's credential-dumping event is behaviorally
  *generic* ("some process opened lsass with `0x1410`"), so tool-specific rules
  correctly decline to fire.
- Real RDP lateral-movement rules want network-connection telemetry
  (`DestPort`, `Initiated`, `SourceAddress`) that this generator doesn't model.
- Brute-force rules key on Security-channel details beyond what's simulated.

The audit already drove one fix: it showed most community rules couldn't
*evaluate* at all because events were too field-sparse, so the generator now
emits the companion fields real records carry (`TargetUserName`,
`WorkstationName`, `OriginalFileName`, `CallTrace`, `Hashes`, `IntegrityLevel`,
`Provider_Name`, ...) — 16 fields to 34, which lifted corroboration from 6 rules
to 8. Reproducing specific attacker tooling is the next step, and that gap is
the honest headline rather than a number tuned until it looked good.

The corpus is **not vendored** — it's upstream content under its own license
that changes constantly, and pinning a stale copy would defeat the purpose of
auditing against rules maintained by other people.

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
- **Honesty** — is the benign data hard enough that precision means anything?
  (hard negatives)
- **Independence** — do detections written by people who've never seen this
  generator agree that these are attacks? (the SigmaHQ audit)

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

## The pieces

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
Does a rule's precision **survive real traffic volume**? Sweep the benign event
rate, hold the attacks fixed, and chart the decay — see
[the sweep section above](#does-that-precision-survive-a-noisy-network) for the
tuned-vs-untuned comparison.
```bash
python -m siemlab sweep --rates 2,8,16,32,64,128 --csv sweep.csv
```

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

Everything in `detections/` is the **tuned** version. The naive originals live in
`detections-untuned/` so the before/after above reproduces on demand.

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

# Audit against the real SigmaHQ corpus (realism check)
python scripts/fetch_sigma.py
python -m siemlab sigma-audit
python -m siemlab sigma-audit --max-rules 300     # quick pass

# Reproduce the untuned "before" state
python -m siemlab run --rules detections-untuned

# Turn hard negatives off entirely (shows how flattering that is)
python -c "from siemlab.generator import generate; generate(hard_negative_rate=0.0)"

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

40 tests: the field matcher, condition parser, sliding-window thresholds,
multi-stage incident scoring, Sigma import (both the PyYAML and bundled-parser
paths), ECS/OCSF export, the noise sweep's decay invariant, hard-negative
presence, the tuned-beats-untuned precision gap, tuning generalization to unseen
seeds, rule validation (empty selections and unsupported modifiers must be
rejected, never silently matched), and the audit's graceful handling of broken
rules.

CI runs them on every push across Python 3.9 / 3.11 / 3.13, **twice per version**
— once with PyYAML installed and once without — because the zero-dependency
claim is only real if the bundled YAML fallback is actually exercised. It also
smoke-tests every CLI subcommand and validates that the ECS and OCSF exports
parse as JSON. See [`.github/workflows/tests.yml`](.github/workflows/tests.yml).

## Project layout

```
siem-detection-lab/
  .github/workflows/  CI: tests on 3.9/3.11/3.13, with and without PyYAML
  siemlab/
    events.py       normalized event schema + ground-truth labeling
    generator.py    multi-stage ATT&CK intrusions + benign baseline
    rules.py        Sigma-inspired rule model, matcher, condition parser
    engine.py       runs rules over events, sliding-window thresholds
    evaluate.py     precision / recall / MTTD / stage-of-detection
    sigma.py        import real Sigma YAML (PyYAML or bundled fallback)
    export.py       ECS + OCSF schema exporters
    sweep.py        noise-injection precision-decay sweep
    audit.py        run the real SigmaHQ corpus against our telemetry
    cli.py          generate / detect / evaluate / run / sweep / sigma-audit
  detections/         tuned rules -- JSON and Sigma YAML (edit these)
  detections-untuned/ the naive originals, kept so the before/after reproduces
  scripts/            fetch_sigma.py -- pull the SigmaHQ corpus into vendor/
  tests/              unit + end-to-end tests
```

## Optional

PyYAML is used if present (faster, fully spec-compliant Sigma parsing) but is not
required — the bundled parser covers the Sigma subset. To install it anyway:

```bash
pip install pyyaml
```
