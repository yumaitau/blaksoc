"""The blakSOC tuning toolset Hermes is given, alongside its memory tool and nothing else.

Tools are registered in-process into Hermes' tool registry under the toolset name `blaksoc_tuning`
(Hermes v0.20 treats a registry-only toolset name as valid). Reads return the controller's sanitised
snapshot, never a fresh fetch with model-chosen parameters. Writes pass policy.Guard first, are
recorded in the ledger, and reach blakSOC only when dry-run is off and the act switch is on.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Callable

from . import api, policy, report, sanitize

TOOLSET = "blaksoc_tuning"
CONFIDENCE = ("low", "medium", "high")
_STRING = {"type": "string"}
_PATTERN_ID = {"type": "string", "description": "patternId exactly as returned by get_patterns"}

SCHEMAS = {
    "get_patterns": {
        "description": (
            "Read this week's anonymised alert patterns from blakSOC (counts and distributions only). "
            "sort=volume (default) or false_positive; limit up to 40; offset for paging. Also returns fleet "
            "co-firing and, per pattern, whether local guardrails allow acting on it."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "sort": {"type": "string", "enum": ["volume", "false_positive"]},
                "limit": {"type": "integer", "minimum": 1, "maximum": 40},
                "offset": {"type": "integer", "minimum": 0},
            },
            "additionalProperties": False,
        },
    },
    "get_past_actions": {
        "description": (
            "Read Hermes' earlier actions and their outcomes (affected alerts, undoneAt, reopenedCount). "
            "Undone or reopened actions mean analysts disagreed."
        ),
        "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    "annotate_pattern": {
        "description": "Add a note to a pattern for analysts. The safe choice when unsure. No identifiers in text.",
        "parameters": {
            "type": "object",
            "properties": {
                "patternId": _PATTERN_ID,
                "text": {"type": "string", "maxLength": 1000},
                "confidence": {"type": "string", "enum": list(CONFIDENCE)},
            },
            "required": ["patternId", "text", "confidence"],
            "additionalProperties": False,
        },
    },
    "close_pattern_alerts": {
        "description": (
            "Close this pattern's open alerts as noise. Only for low/medium-severity patterns analysts "
            "mostly closed as false positive, not escalated. Explain why in reason."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "patternId": _PATTERN_ID,
                "reason": {"type": "string", "maxLength": 500},
                "maxAlerts": {"type": "integer", "minimum": 1, "maximum": policy.MAX_CLOSE_ALERTS},
            },
            "required": ["patternId", "reason"],
            "additionalProperties": False,
        },
    },
    "create_noise_rule": {
        "description": "Route future alerts of this pattern to the passive lane for up to 30 days. Explain why.",
        "parameters": {
            "type": "object",
            "properties": {
                "patternId": _PATTERN_ID,
                "reason": {"type": "string", "maxLength": 500},
                "expiresInDays": {"type": "integer", "minimum": 1, "maximum": policy.MAX_NOISE_RULE_DAYS},
            },
            "required": ["patternId", "reason", "expiresInDays"],
            "additionalProperties": False,
        },
    },
    "purge_pattern_noise": {
        "description": (
            "Delete alerts of this pattern that Hermes closed at least 7 days ago and no analyst reopened. "
            "blakSOC selects the alerts. Explain why in reason."
        ),
        "parameters": {
            "type": "object",
            "properties": {"patternId": _PATTERN_ID, "reason": {"type": "string", "maxLength": 500}},
            "required": ["patternId", "reason"],
            "additionalProperties": False,
        },
    },
    "submit_weekly_report": {
        "description": (
            "Submit the weekly Markdown report once, at the end. It must contain these headings: "
            + "; ".join(report.REQUIRED_HEADINGS)
            + ". Counts and pattern references (source, rule id, tenantRef, patternId) only: no titles, "
            "hostnames, usernames, IP or email addresses, URLs or customer names."
        ),
        "parameters": {
            "type": "object",
            "properties": {"markdown": {"type": "string", "maxLength": report.MAX_MODEL_REPORT}},
            "required": ["markdown"],
            "additionalProperties": False,
        },
    },
}
TOOL_NAMES = tuple(SCHEMAS)
WRITE_KINDS = {
    "annotate_pattern": "annotate",
    "close_pattern_alerts": "close",
    "create_noise_rule": "noise_rule",
    "purge_pattern_noise": "purge",
}


def fp_share(pattern: dict):
    d30 = pattern.get("dispositions", {}).get("d30", {})
    decided = sum(d30.get(k, 0) for k in ("falsePositive", "resolved", "escalated"))
    return round(d30.get("falsePositive", 0) / decided, 3) if decided >= 5 else None


class Toolset:
    def __init__(self, *, client: api.TuningClient, snapshot: dict, actions: list, guard: policy.Guard,
                 ledger: policy.Ledger, dry_run: bool, run_id: str, log: Callable = lambda *a, **k: None):
        self.client = client
        self.snapshot = snapshot
        self.actions = actions
        self.guard = guard
        self.ledger = ledger
        self.dry_run = dry_run
        self.run_id = run_id
        self.log = log
        self.report_markdown = None
        self.calls = 0

    # -- registration --

    def register(self, registry) -> None:
        for name, schema in SCHEMAS.items():
            registry.register(
                name=name,
                toolset=TOOLSET,
                schema={"name": name, **schema},
                handler=lambda args, _name=name, **_kw: self.dispatch(_name, args),
                description=schema["description"],
            )

    def dispatch(self, name: str, args: Any) -> str:
        self.calls += 1
        if not isinstance(args, dict):
            return _err("arguments must be an object")
        allowed = set(SCHEMAS[name]["parameters"].get("properties", {}))
        extra = set(args) - allowed
        if extra:
            return _err("unknown arguments: " + ", ".join(sorted(extra)))
        try:
            return json.dumps(getattr(self, name)(**args), ensure_ascii=False)
        except TypeError as error:
            return _err("invalid arguments: " + str(error)[:200])
        except Exception as error:  # one bad call must not end the weekly run
            return _err(f"{type(error).__name__}: could not run {name}")

    # -- reads --

    def eligibility(self, pattern: dict) -> dict:
        out = {}
        for kind in ("annotate", "close", "noise_rule", "purge"):
            try:
                self.guard.check(kind, pattern["patternId"], "eligibility probe text")
                out[kind] = "allowed"
            except policy.Held as held:
                out[kind] = "blocked: " + str(held)
        return out

    def get_patterns(self, sort: str = "volume", limit: int = 20, offset: int = 0) -> dict:
        if sort not in ("volume", "false_positive") or not isinstance(limit, int) or not isinstance(offset, int):
            return {"error": "sort must be volume or false_positive; limit and offset integers"}
        limit = max(1, min(limit, 40))
        patterns = list(self.snapshot["patterns"])
        if sort == "volume":
            patterns.sort(key=lambda p: p["counts"].get("total", 0), reverse=True)
        else:
            patterns.sort(key=lambda p: (fp_share(p) or 0, p["counts"].get("total", 0)), reverse=True)
        page = patterns[max(0, offset): max(0, offset) + limit]
        return {
            "totalPatterns": len(patterns),
            "patterns": [dict(p, falsePositiveShare30d=fp_share(p), guardrails=self.eligibility(p)) for p in page],
            "fleet": sorted(self.snapshot["fleet"], key=lambda f: (f.get("tenantsAffected", 0), f.get("total", 0)),
                            reverse=True)[:20],
            "dryRun": self.dry_run,
            "remainingCaps": {k: self.guard.caps[k] - self.ledger.used(k) for k in self.guard.caps},
        }

    def get_past_actions(self) -> dict:
        return {"actions": self.actions[-100:], "note": "undoneAt or reopenedCount > 0 means analysts disagreed"}

    # -- writes --

    def annotate_pattern(self, patternId=None, text=None, confidence=None) -> dict:
        if confidence not in CONFIDENCE:
            return {"error": "confidence must be low, medium or high"}
        return self._write("annotate", patternId, text,
                           lambda key: self.client.annotate(patternId, text.strip(), confidence, idempotency_key=key))

    def close_pattern_alerts(self, patternId=None, reason=None, maxAlerts=None) -> dict:
        if maxAlerts is not None and (isinstance(maxAlerts, bool) or not isinstance(maxAlerts, int)
                                      or not 1 <= maxAlerts <= policy.MAX_CLOSE_ALERTS):
            return {"error": f"maxAlerts must be 1..{policy.MAX_CLOSE_ALERTS}"}
        return self._write("close", patternId, reason,
                           lambda key: self.client.close(patternId, reason.strip(), maxAlerts, idempotency_key=key))

    def create_noise_rule(self, patternId=None, reason=None, expiresInDays=None) -> dict:
        if isinstance(expiresInDays, bool) or not isinstance(expiresInDays, int) \
                or not 1 <= expiresInDays <= policy.MAX_NOISE_RULE_DAYS:
            return {"error": f"expiresInDays must be 1..{policy.MAX_NOISE_RULE_DAYS}"}
        return self._write("noise_rule", patternId, reason,
                           lambda key: self.client.noise_rule(patternId, reason.strip(), expiresInDays, idempotency_key=key))

    def purge_pattern_noise(self, patternId=None, reason=None) -> dict:
        return self._write("purge", patternId, reason, lambda key: self.client.purge(patternId, idempotency_key=key))

    def _write(self, kind: str, pattern_id, reason, call: Callable) -> dict:
        ref = "unknown pattern"
        try:
            pattern = self.guard.check(kind, pattern_id, reason)
            ref = policy.pattern_ref(pattern)
        except policy.Held as held:
            self.ledger.add(policy.Entry(kind, str(pattern_id)[:100], ref, policy.HELD,
                                         sanitize.scrub(sanitize.clean_text(reason or "", 300)), str(held)))
            self.log("action_held", kind=kind, reason=str(held))
            return {"status": policy.HELD, "message": str(held)}
        reason_text = reason.strip()
        if self.dry_run or self.ledger.switch_off:
            why = "dry-run mode" if self.dry_run else "blakSOC 'Allow Hermes to act' switch is off"
            self.ledger.add(policy.Entry(kind, pattern_id, ref, policy.DRY_RUN, reason_text, why))
            self.log("action_dry_run", kind=kind, pattern=pattern_id)
            return {"status": policy.DRY_RUN, "message": f"recorded only ({why}); nothing changed in blakSOC"}
        key = hashlib.sha256(f"{self.run_id}:{kind}:{pattern_id}".encode()).hexdigest()[:32]
        try:
            result = call(key)
        except api.Conflict as conflict:
            # 409 on an act endpoint: the global switch is off. Treat the rest of the run as dry-run.
            self.ledger.switch_off = True
            self.ledger.add(policy.Entry(kind, pattern_id, ref, policy.DRY_RUN, reason_text,
                                         "blakSOC 'Allow Hermes to act' switch is off (409)"))
            self.log("act_switch_off", kind=kind, status=conflict.status)
            return {"status": policy.DRY_RUN, "message": "blakSOC's act switch is off; recorded as dry-run. "
                                                         "Further writes this run are recorded only."}
        except api.Refused as refused:
            message = sanitize.scrub(sanitize.clean_text(refused.message or refused.code, 300))
            self.ledger.add(policy.Entry(kind, pattern_id, ref, policy.REFUSED, reason_text,
                                         f"{refused.status} {refused.code}: {message}".strip()))
            self.log("action_refused", kind=kind, status=refused.status, code=refused.code)
            return {"status": policy.REFUSED, "message": message or refused.code}
        except api.Unavailable as error:
            self.ledger.add(policy.Entry(kind, pattern_id, ref, policy.FAILED, reason_text,
                                         f"blakSOC unavailable ({error.status} {error.code}); outcome unknown"))
            self.log("action_failed", kind=kind, status=error.status, code=error.code)
            return {"status": policy.FAILED, "message": "blakSOC unavailable; do not retry this action this run"}
        affected = result.get("affected") if isinstance(result, dict) else None
        affected = affected if isinstance(affected, int) and not isinstance(affected, bool) else None
        self.ledger.add(policy.Entry(kind, pattern_id, ref, policy.EXECUTED, reason_text, "", affected))
        self.log("action_executed", kind=kind, pattern=pattern_id, affected=affected)
        return {"status": policy.EXECUTED, "affected": affected}

    # -- report --

    def submit_weekly_report(self, markdown=None) -> dict:
        problems = report.check_model_report(markdown)
        if problems:
            return {"status": "rejected", "problems": problems}
        self.report_markdown = markdown
        return {"status": "accepted", "message": "report stored; the controller submits it with action counts"}


def _err(message: str) -> str:
    return json.dumps({"error": message})
