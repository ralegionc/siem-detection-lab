"""Synthetic telemetry generator.

Produces a reproducible, labeled event stream: a benign baseline (normal logons,
routine PowerShell, legit scheduled tasks, network shares) plus injected attack
activity drawn from ATT&CK. The benign layer deliberately overlaps the attack
surface — legitimate PowerShell, occasional failed logons, real schtasks usage —
so detection rules face genuine false-positive pressure instead of a toy stream
where anything unusual is malicious.

Attacks are emitted as **multi-stage incidents**, not isolated events. A single
intruder brute-forces a host, executes an encoded payload, dumps credentials,
installs persistence, then moves laterally — with realistic **dwell time**
between stages. Every attack event is stamped with its technique (``_label``),
its incident id (``_incident``), and its kill-chain stage (``_stage``).

That structure is what lets the evaluator ask the question a SOC actually cares
about: not "did some rule fire" but "did we catch this *intrusion*, at which
stage, and how long did it dwell before we saw it."
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from .events import make_event

HOSTS = ["WKS-01", "WKS-02", "WKS-03", "SRV-DC01", "SRV-FILE01", "SRV-APP01"]
SERVERS = ["SRV-DC01", "SRV-APP01", "SRV-FILE01"]
USERS = ["alice", "bob", "carol", "dave", "svc_backup", "svc_sql", "admin"]
INTERNAL_IPS = [f"10.0.1.{i}" for i in range(10, 60)]
EXTERNAL_IPS = ["185.220.101.4", "45.155.205.233", "193.42.33.19"]

# The kill chain an incident walks, in order.
KILL_CHAIN = [
    "initial_access",
    "execution",
    "credential_access",
    "persistence",
    "lateral_movement",
    "account_manipulation",
]


@dataclass
class AttackContext:
    """Shared identity for one intrusion, so its stages hang together."""

    incident: str
    host: str
    user: str
    src_ip: str


class TelemetryGenerator:
    def __init__(self, seed: int = 1337, start: datetime | None = None):
        self.rng = random.Random(seed)
        self.start = start or datetime(2026, 9, 3, 8, 0, 0, tzinfo=timezone.utc)
        self.events: List[Dict[str, Any]] = []

    # -- helpers ----------------------------------------------------------
    def _at(self, offset_seconds: float) -> datetime:
        return self.start + timedelta(seconds=offset_seconds)

    def _add(self, ev: Dict[str, Any]) -> None:
        self.events.append(ev)

    # -- benign baseline --------------------------------------------------
    def _benign_baseline(self, duration_seconds: int, rate_per_min: float) -> None:
        n = int((duration_seconds / 60.0) * rate_per_min)
        for _ in range(n):
            t = self._at(self.rng.uniform(0, duration_seconds))
            self._benign_event(t)

    def _benign_event(self, t: datetime) -> None:
        roll = self.rng.random()
        host = self.rng.choice(HOSTS)
        user = self.rng.choice(USERS)

        if roll < 0.45:
            # Successful interactive/network logon.
            self._add(make_event(
                t, host, "Security", 4624,
                User=user, LogonType=self.rng.choice([2, 3, 7]),
                IpAddress=self.rng.choice(INTERNAL_IPS),
            ))
        elif roll < 0.55:
            # Occasional benign failed logon (fat-fingered password).
            self._add(make_event(
                t, host, "Security", 4625,
                User=user, LogonType=2,
                IpAddress=self.rng.choice(INTERNAL_IPS),
            ))
        elif roll < 0.75:
            # Routine PowerShell (admin scripts, no encoded blob).
            cmd = self.rng.choice([
                "powershell.exe -File C:\\Scripts\\backup.ps1",
                "powershell.exe Get-Service",
                "powershell.exe -Command Get-ChildItem C:\\Users",
                "powershell.exe -NoProfile -File C:\\Ops\\healthcheck.ps1",
            ])
            self._add(make_event(
                t, host, "Sysmon", 1,
                User=user, Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                ParentImage="C:\\Windows\\explorer.exe", CommandLine=cmd,
            ))
        elif roll < 0.85:
            # Legit scheduled task usage (query only, not /create).
            self._add(make_event(
                t, host, "Sysmon", 1,
                User="admin", Image="C:\\Windows\\System32\\schtasks.exe",
                ParentImage="C:\\Windows\\System32\\cmd.exe",
                CommandLine="schtasks.exe /query /fo LIST",
            ))
        elif roll < 0.95:
            # Benign registry writes (not the Run key).
            self._add(make_event(
                t, host, "Sysmon", 13,
                User=user, TargetObject="HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Settings",
                Details="1",
            ))
        else:
            # Benign network share access.
            self._add(make_event(
                t, host, "Security", 4624,
                User=self.rng.choice(["svc_backup", "svc_sql"]), LogonType=3,
                IpAddress=self.rng.choice(INTERNAL_IPS),
            ))

    # -- attack stages ----------------------------------------------------
    # Each returns the offset (seconds) of its final event, so the next stage
    # can dwell forward from there.

    def brute_force(self, t0: float, ctx: AttackContext) -> float:
        """T1110 — brute force ending in a successful logon."""
        n_fail = self.rng.randint(8, 20)
        t = t0
        for _ in range(n_fail):
            self._add(make_event(
                self._at(t), ctx.host, "Security", 4625, "T1110", ctx.incident, "initial_access",
                User=ctx.user, LogonType=3, IpAddress=ctx.src_ip,
            ))
            t += self.rng.uniform(1, 3)
        t += 2
        self._add(make_event(
            self._at(t), ctx.host, "Security", 4624, "T1110", ctx.incident, "initial_access",
            User=ctx.user, LogonType=3, IpAddress=ctx.src_ip,
        ))
        return t

    def encoded_powershell(self, t0: float, ctx: AttackContext) -> float:
        """T1059.001 — encoded PowerShell command (obfuscated payload)."""
        blob = "".join(
            self.rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123456789+/") for _ in range(120)
        )
        self._add(make_event(
            self._at(t0), ctx.host, "Sysmon", 1, "T1059.001", ctx.incident, "execution",
            User=ctx.user,
            Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            ParentImage="C:\\Windows\\System32\\cmd.exe",
            CommandLine=f"powershell.exe -nop -w hidden -enc {blob}",
        ))
        return t0

    def lsass_dump(self, t0: float, ctx: AttackContext) -> float:
        """T1003.001 — LSASS memory access (credential dumping)."""
        self._add(make_event(
            self._at(t0), ctx.host, "Sysmon", 10, "T1003.001", ctx.incident, "credential_access",
            User=ctx.user,
            SourceImage="C:\\Temp\\rundll32.exe",
            TargetImage="C:\\Windows\\System32\\lsass.exe",
            GrantedAccess="0x1410",
        ))
        return t0

    def run_key_persistence(self, t0: float, ctx: AttackContext) -> float:
        """T1547.001 — Registry Run key persistence."""
        self._add(make_event(
            self._at(t0), ctx.host, "Sysmon", 13, "T1547.001", ctx.incident, "persistence",
            User=ctx.user,
            TargetObject="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
            Details="C:\\Users\\Public\\update.exe",
        ))
        return t0

    def malicious_scheduled_task(self, t0: float, ctx: AttackContext) -> float:
        """T1053.005 — persistence via schtasks /create."""
        self._add(make_event(
            self._at(t0), ctx.host, "Sysmon", 1, "T1053.005", ctx.incident, "persistence",
            User=ctx.user,
            Image="C:\\Windows\\System32\\schtasks.exe",
            ParentImage="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            CommandLine="schtasks.exe /create /tn Updater /tr C:\\Users\\Public\\update.exe "
                        "/sc onlogon /ru SYSTEM",
        ))
        return t0

    def rdp_lateral(self, t0: float, ctx: AttackContext) -> float:
        """T1021.001 — RDP logon from an external address onto a server."""
        target = self.rng.choice(SERVERS)
        self._add(make_event(
            self._at(t0), target, "Security", 4624, "T1021.001", ctx.incident, "lateral_movement",
            User=ctx.user, LogonType=10, IpAddress=ctx.src_ip,
        ))
        return t0

    def new_account(self, t0: float, ctx: AttackContext) -> float:
        """T1136.001 — local account creation for durable access."""
        self._add(make_event(
            self._at(t0), ctx.host, "Security", 4720, "T1136.001", ctx.incident,
            "account_manipulation",
            User=ctx.user, TargetUserName="backup_svc2",
        ))
        return t0

    # Stage name -> the handlers that can satisfy it.
    def _stage_handlers(self) -> Dict[str, List[Callable[[float, AttackContext], float]]]:
        return {
            "initial_access": [self.brute_force],
            "execution": [self.encoded_powershell],
            "credential_access": [self.lsass_dump],
            "persistence": [self.run_key_persistence, self.malicious_scheduled_task],
            "lateral_movement": [self.rdp_lateral],
            "account_manipulation": [self.new_account],
        }

    # -- incidents --------------------------------------------------------
    def incident(
        self,
        incident_id: str,
        t0: float,
        stages: List[str],
        dwell_range: Tuple[float, float] = (120.0, 900.0),
    ) -> float:
        """Emit one multi-stage intrusion, dwelling between stages.

        Returns the offset of the final event in the chain.
        """
        ctx = AttackContext(
            incident=incident_id,
            host=self.rng.choice(HOSTS),
            user=self.rng.choice(USERS),
            src_ip=self.rng.choice(EXTERNAL_IPS),
        )
        handlers = self._stage_handlers()
        t = t0
        for stage in stages:
            options = handlers.get(stage)
            if not options:
                continue
            handler = self.rng.choice(options)
            t = handler(t, ctx)
            t += self.rng.uniform(*dwell_range)  # dwell before the next move
        return t

    # -- orchestration ----------------------------------------------------
    def generate(
        self,
        duration_seconds: int = 6 * 3600,
        baseline_rate_per_min: float = 12.0,
        n_incidents: int = 5,
        dwell_range: Tuple[float, float] = (120.0, 900.0),
    ) -> List[Dict[str, Any]]:
        self.events = []
        self._benign_baseline(duration_seconds, baseline_rate_per_min)

        # The first incident walks the whole kill chain, guaranteeing every
        # technique (and therefore every rule) is exercised at least once.
        # The rest are partial intrusions: an attacker who got caught early, or
        # one who skipped a step. Those are the realistic ones.
        for i in range(max(1, n_incidents)):
            inc_id = f"INC-{i + 1:03d}"
            if i == 0:
                stages = list(KILL_CHAIN)
            else:
                # A contiguous slice of the chain. Not every intrusion starts at
                # the front: an attacker with already-valid credentials skips
                # initial access entirely, which is precisely the case that
                # slips past a brute-force rule and inflates dwell time.
                begin = self.rng.randint(0, len(KILL_CHAIN) - 2)
                depth = self.rng.randint(2, len(KILL_CHAIN) - begin)
                stages = KILL_CHAIN[begin:begin + depth]
            # Leave room for the chain to finish inside the capture window.
            latest_start = max(0.0, duration_seconds - len(stages) * dwell_range[1] - 300)
            t0 = self.rng.uniform(0, latest_start) if latest_start > 0 else 0.0
            self.incident(inc_id, t0, stages, dwell_range)

        self.events.sort(key=lambda e: e["_ts"])
        return self.events


def generate(
    seed: int = 1337,
    duration_seconds: int = 6 * 3600,
    baseline_rate_per_min: float = 12.0,
    n_incidents: int = 5,
    dwell_range: Tuple[float, float] = (120.0, 900.0),
) -> List[Dict[str, Any]]:
    return TelemetryGenerator(seed=seed).generate(
        duration_seconds=duration_seconds,
        baseline_rate_per_min=baseline_rate_per_min,
        n_incidents=n_incidents,
        dwell_range=dwell_range,
    )
