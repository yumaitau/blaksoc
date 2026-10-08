"""Local guardrails for every write Hermes asks for, and the run ledger that records each outcome.

blakSOC enforces its own rules server-side; these checks never rely on that, and never on the model.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from . import sanitize

# Hard ceilings: configuration can lower these, never raise them.
HARD_CAPS = {"close": 10, "noise_rule": 5, "purge": 10, "annotate": 50}
BLOCKING_SEVERITIES = ("high", "critical")
MAX_NOISE_RULE_DAYS = 30
MAX_CLOSE_ALERTS = 5000

# Ledger statuses
EXECUTED = "executed"        # blakSOC accepted the write
DRY_RUN = "dry_run"          # recorded only (dry-run mode, or blakSOC's act switch is off)
REFUSED = "refused"          # blakSOC answered with a definitive refusal
HELD = "held"                # a local guardrail stopped it; nothing was sent
FAILED = "failed"            # transport/5xx: the write's outcome is unknown


def clamp_caps(configured: dict) -> dict:
    caps = {}
    for kind, ceiling in HARD_CAPS.items():
        value = configured.get(kind, ceiling)
        caps[kind] = max(0, min(int(value), ceiling))
    return caps


def pattern_ref(pattern: dict) -> str:
    """Opaque, PII-free label used in the report and memory."""
    return f"{pattern.get('source', '?')} rule {pattern.get('ruleId', '?')} / tenant {pattern.get('tenantRef', '?')}"


def pattern_key(pattern: dict) -> str:
    return f"{pattern.get('tenantRef', '-')}:{pattern.get('source', '-')}:{pattern.get('ruleId', '-')}"


class Held(Exception):
    pass


@dataclass
class Entry:
    kind: str
    pattern_id: str
    ref: str
    status: str
    reason: str
    detail: str = ""
    affected: Optional[int] = None


@dataclass
class Ledger:
    entries: list = field(default_factory=list)
    switch_off: bool = False

    def add(self, entry: Entry) -> Entry:
        self.entries.append(entry)
        return entry

    def counts(self) -> dict:
        out = {s: 0 for s in (EXECUTED, DRY_RUN, REFUSED, HELD, FAILED)}
        for entry in self.entries:
            out[entry.status] += 1
        return out

    def by_kind(self) -> dict:
        out = {}
        for entry in self.entries:
            out.setdefault(entry.kind, {}).setdefault(entry.status, 0)
            out[entry.kind][entry.status] += 1
        return out

    def used(self, kind: str) -> int:
        """Slots consumed against a cap: anything that passed local guardrails."""
        return sum(1 for e in self.entries if e.kind == kind and e.status != HELD)

    def seen(self, kind: str, pattern_id: str) -> bool:
        return any(e.kind == kind and e.pattern_id == pattern_id and e.status != HELD for e in self.entries)


class Guard:
    def __init__(self, patterns: list, caps: dict, blocked_keys: set, ledger: Ledger):
        self.patterns = {p["patternId"]: p for p in patterns}
        self.caps = clamp_caps(caps)
        self.blocked_keys = set(blocked_keys)
        self.ledger = ledger

    def check(self, kind: str, pattern_id, reason) -> dict:
        """Return the pattern when the write may proceed; raise Held with a plain reason otherwise."""
        if kind not in HARD_CAPS:
            raise Held(f"unknown action kind {kind!r}")
        pattern = self.patterns.get(pattern_id) if isinstance(pattern_id, str) else None
        if pattern is None:
            raise Held("patternId is not one of this run's patterns")
        if not isinstance(reason, str) or len(reason.strip()) < 10:
            raise Held("a reason of at least 10 characters is required")
        limit = 1000 if kind == "annotate" else 500
        if len(reason) > limit:
            raise Held(f"reason/text must be at most {limit} characters")
        leaks = sanitize.find_pii(reason)
        if leaks:
            raise Held("reason/text contains identifier-like content (" + ", ".join(leaks) + "); describe patterns only")
        severity = pattern.get("severity", {})
        if any(severity.get(level, 0) > 0 for level in BLOCKING_SEVERITIES):
            raise Held("pattern includes high or critical alerts; Hermes never acts on these")
        if pattern.get("analystOverrides", 0) > 0:
            raise Held("analysts have overridden this pattern; leave it to them")
        if kind != "annotate" and pattern_key(pattern) in self.blocked_keys:
            raise Held("analysts undid or reopened an earlier Hermes action on this pattern")
        if kind == "close":
            d30 = pattern.get("dispositions", {}).get("d30", {})
            if d30.get("escalated", 0) > 0 or pattern.get("incidentsOpened", 0) > 0:
                raise Held("pattern was escalated or opened an incident recently")
        if kind == "noise_rule" and (pattern.get("noiseRule") or {}).get("status") == "active":
            raise Held("pattern already has an active noise rule")
        if self.ledger.seen(kind, pattern_id):
            raise Held(f"{kind} already recorded for this pattern in this run")
        if self.ledger.used(kind) >= self.caps[kind]:
            raise Held(f"per-run cap reached ({self.caps[kind]} {kind})")
        return pattern
