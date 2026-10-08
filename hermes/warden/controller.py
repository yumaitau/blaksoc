"""Deterministic controller for one hourly Hermes run (CronJob entry point: python -m warden).

1. Read config; refuse to start on anything unsafe (non-AU model or region, bad URL or credential).
2. Fetch patterns, past actions and memory from blakSOC; abort before any model call if a response
   carries identifying fields; strip everything not allowlisted.
3. Derive outcome lessons (undone / reopened actions) and the pattern keys they block.
4. Write Hermes' memory file and config, register the tuning toolset, run one AIAgent with only the
   memory and blaksoc_tuning toolsets, under a turn, token and wall-clock budget.
5. Write memory back (validated, outcome lessons guaranteed), submit the report with the controller's
   record of every action, and exit non-zero with one clear log line on any failure.
"""

from __future__ import annotations

import json
import os
import sys
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Optional

from . import api, memory, policy, report, sanitize
from .toolset import TOOL_NAMES, TOOLSET, Toolset

EXIT_OK, EXIT_CONFIG, EXIT_PII, EXIT_API, EXIT_AGENT = 0, 2, 3, 4, 5
AU_REGIONS = ("ap-southeast-2", "ap-southeast-4")
NON_AU_PROFILE_PREFIXES = ("us", "us-gov", "eu", "apac", "global", "jp", "ca", "uk")
DEFAULT_MODEL = "au.anthropic.claude-sonnet-4-5-20250929-v1:0"
SYSTEM_PROMPT = (Path(__file__).with_name("SYSTEM.md")).read_text(encoding="utf-8")


def log(event: str, level: str = "info", **fields) -> None:
    line = {"ts": datetime.now(timezone.utc).isoformat(), "level": level, "component": "hermes", "event": event}
    line.update(fields)
    print(json.dumps(line, ensure_ascii=False, default=str), flush=True)


def _int_env(env, key, default, low, high):
    raw = env.get(key, "")
    try:
        value = int(raw) if str(raw).strip() else default
    except ValueError:
        raise api.ConfigError(f"{key} must be an integer") from None
    if not low <= value <= high:
        raise api.ConfigError(f"{key} must be between {low} and {high}")
    return value


@dataclass
class Config:
    base_url: str
    credential: api.Credential
    dry_run: bool
    model: str
    region: str
    days: int
    caps: dict
    max_turns: int
    max_tokens: int
    max_output_tokens: int
    run_seconds: int
    lookback_days: int
    home: Path
    http_timeout: int

    @classmethod
    def from_env(cls, env=None) -> "Config":
        env = os.environ if env is None else env
        model = env.get("HERMES_MODEL", "").strip() or DEFAULT_MODEL
        prefix = model.split(".", 1)[0]
        if prefix in NON_AU_PROFILE_PREFIXES or not model.replace(".", "").replace("-", "").replace(":", "").isalnum():
            raise api.ConfigError("HERMES_MODEL must be an Australian (au.) inference profile or in-region model id")
        region = env.get("HERMES_BEDROCK_REGION", "ap-southeast-2").strip()
        if region not in AU_REGIONS:
            raise api.ConfigError("HERMES_BEDROCK_REGION must be ap-southeast-2 or ap-southeast-4")
        caps = {
            "close": _int_env(env, "HERMES_CAP_CLOSE", 10, 0, policy.HARD_CAPS["close"]),
            "noise_rule": _int_env(env, "HERMES_CAP_NOISE_RULES", 5, 0, policy.HARD_CAPS["noise_rule"]),
            "purge": _int_env(env, "HERMES_CAP_PURGE", 10, 0, policy.HARD_CAPS["purge"]),
            "annotate": _int_env(env, "HERMES_CAP_ANNOTATIONS", 50, 0, policy.HARD_CAPS["annotate"]),
        }
        return cls(
            base_url=api.check_base_url(env.get("BLAKSOC_API_URL", "")),
            credential=api.Credential.parse(env.get("HERMES_BLAKSOC_TOKEN", "")),
            # Anything but an explicit "false" keeps dry-run on.
            dry_run=env.get("HERMES_DRY_RUN", "true").strip().lower() != "false",
            model=model,
            region=region,
            days=_int_env(env, "HERMES_PATTERN_DAYS", 7, 1, 30),
            caps=caps,
            max_turns=_int_env(env, "HERMES_MAX_TURNS", 40, 1, 150),
            max_tokens=_int_env(env, "HERMES_MAX_TOKENS", 400_000, 10_000, 3_000_000),
            max_output_tokens=_int_env(env, "HERMES_MAX_OUTPUT_TOKENS", 4096, 256, 32_000),
            run_seconds=_int_env(env, "HERMES_RUN_SECONDS", 1200, 60, 7200),
            lookback_days=_int_env(env, "HERMES_OUTCOME_LOOKBACK_DAYS", 90, 7, 365),
            home=Path(env.get("HERMES_HOME", "/hermes-home")),
            http_timeout=_int_env(env, "HERMES_HTTP_TIMEOUT", 20, 1, 120),
        )


@dataclass
class AgentOutcome:
    ok: bool
    error: str = ""
    tokens: int = 0
    turns: int = 0


def write_hermes_config(cfg: Config) -> None:
    """Profile config read by Hermes at agent init: built-in memory only, no user profile, no providers,
    no tool-search bridge (it would add tool_search/tool_describe/tool_call around the tuning tools)."""
    cfg.home.mkdir(parents=True, exist_ok=True)
    (cfg.home / "config.yaml").write_text(
        "# Written by the Hermes Warden controller for one run.\n"
        "memory:\n"
        "  memory_enabled: true\n"
        "  user_profile_enabled: false\n"
        f"  memory_char_limit: {memory.CHAR_BUDGET}\n"
        "  provider: ''\n"
        "tools:\n"
        "  tool_search:\n"
        "    enabled: 'off'  # expose the tuning tools directly, not behind tool_search/tool_call\n",
        encoding="utf-8",
    )


def hermes_runner(cfg: Config, toolset: Toolset, task: str) -> AgentOutcome:
    """Run the real Hermes AIAgent. Imported lazily: unit tests use a fake runner."""
    from run_agent import AIAgent  # Hermes v0.20, /opt/hermes on PYTHONPATH
    from tools.registry import registry

    toolset.register(registry)
    budget = {"exceeded": False}
    holder = {}

    def step(api_calls, _prev_tools):
        agent = holder.get("agent")
        if agent is not None and getattr(agent, "session_total_tokens", 0) > cfg.max_tokens and not budget["exceeded"]:
            budget["exceeded"] = True
            agent.interrupt("Token budget exhausted for this run")

    agent = AIAgent(
        model=cfg.model,
        provider="bedrock",
        base_url=f"https://bedrock-runtime.{cfg.region}.amazonaws.com",
        api_key="aws-sdk",  # Bedrock signs with the boto3 default chain (EKS Pod Identity); no key exists
        enabled_toolsets=["memory", TOOLSET],
        disabled_toolsets=[],
        max_iterations=cfg.max_turns,
        max_tokens=cfg.max_output_tokens,
        quiet_mode=True,
        skip_context_files=True,
        load_soul_identity=False,
        skip_memory=True,  # no external memory provider; the memory toolset still loads MEMORY.md
        skip_background_review=True,
        save_trajectories=False,
        checkpoints_enabled=False,
        run_budget_seconds=cfg.run_seconds,
        session_id="hermes-warden-" + uuid.uuid4().hex[:12],
        platform="blaksoc-hermes",
        step_callback=step,
    )
    holder["agent"] = agent
    try:
        names = set(getattr(agent, "valid_tool_names", set()) or set())
        allowed = {"memory", *TOOL_NAMES}
        if not names or names - allowed or not set(TOOL_NAMES) <= names:
            raise RuntimeError("Hermes tool surface differs from memory + blaksoc_tuning: " + ", ".join(sorted(names - allowed)))
        result = agent.run_conversation(task, system_message=SYSTEM_PROMPT)
        tokens = int(getattr(agent, "session_total_tokens", 0) or 0)
        turns = int(result.get("api_calls", 0) or 0) if isinstance(result, dict) else 0
        if budget["exceeded"]:
            return AgentOutcome(False, "token budget exceeded", tokens, turns)
        if not isinstance(result, dict) or result.get("error") or result.get("completed") is False:
            return AgentOutcome(False, "Hermes did not complete the run", tokens, turns)
        return AgentOutcome(True, "", tokens, turns)
    finally:
        try:
            agent.close()
        except Exception:  # noqa: BLE001 - closing must not mask the run's outcome
            pass


def task_message(cfg: Config, snapshot: dict, actions: list, outcome_summary: dict) -> str:
    mode = "DRY RUN (writes are recorded only)" if cfg.dry_run else "LIVE (blakSOC may still refuse)"
    return (
        f"Hourly noise review for the last {cfg.days} days. Mode: {mode}.\n"
        f"Patterns available: {len(snapshot['patterns'])}; fleet rules: {len(snapshot['fleet'])}; "
        f"earlier actions: {len(actions)} (undone {outcome_summary['undone']}, reopened {outcome_summary['reopened']}).\n"
        f"Per-run caps: close {cfg.caps['close']}, noise rules {cfg.caps['noise_rule']}, purge {cfg.caps['purge']}, "
        f"annotations {cfg.caps['annotate']}.\n"
        "Review patterns with get_patterns and get_past_actions, act conservatively, keep a few lessons in "
        "memory, then call submit_weekly_report once."
    )


def run(cfg: Config, client: api.TuningClient, runner: Callable = hermes_runner,
        now: Optional[datetime] = None) -> int:
    now = now or datetime.now(timezone.utc)
    started = time.monotonic()
    run_id = uuid.uuid4().hex
    period_start = (now - timedelta(days=cfg.days)).isoformat()
    period_end = now.isoformat()
    log("run_start", run=run_id, dryRun=cfg.dry_run, model=cfg.model, region=cfg.region, days=cfg.days)

    # 1. Read. Nothing below reaches the model until all three responses pass.
    try:
        snapshot = sanitize.patterns_response(client.patterns(cfg.days), log=lambda e, **f: log(e, "warn", **f))
        stored = sanitize.memory_response(client.memory(), log=lambda e, **f: log(e, "warn", **f))
        since = (now - timedelta(days=min(cfg.lookback_days, stored["retentionDays"]))).isoformat()
        actions = sanitize.actions_response(client.actions(since), log=lambda e, **f: log(e, "warn", **f))
        actions = memory.fresh(actions, now, stored["retentionDays"])
    except sanitize.PiiAbort as abort:
        log("run_aborted", "error", reason="blakSOC response contained prohibited fields", keys=abort.keys)
        return EXIT_PII
    except sanitize.ShapeError as error:
        log("run_aborted", "error", reason="blakSOC response has an unexpected shape", detail=str(error)[:200])
        return EXIT_API
    except api.ApiError as error:
        log("run_aborted", "error", reason="blakSOC API unavailable or refused", status=error.status, code=error.code)
        return EXIT_API

    # 2. Outcome lessons: deterministic, never the model's to write or remove.
    new_outcomes, blocked, outcome_summary = memory.outcome_lessons(actions, snapshot["patterns"])
    stored_notes = memory.fresh(stored["notes"], now, stored["retentionDays"])
    known = {memory._norm(n["text"]) for n in new_outcomes}
    outcomes = new_outcomes + [n for n in stored_notes if n.get("kind") == "outcome" and memory._norm(n["text"]) not in known]
    blocked |= memory.blocked_from_notes(outcomes)
    lessons = [n["text"] for n in stored_notes if n.get("kind") == "model"]
    # Analysts' notes guide the model but stay theirs: blakSOC keeps them, and they are never saved as Hermes notes.
    human = [n["text"] for n in stored_notes if n.get("kind") == "human"]
    human_keys = {memory._norm(t) for t in human}
    start_notes = memory.merge(human + lessons, outcomes)
    write_hermes_config(cfg)
    memory.write_file(cfg.home, start_notes)
    log("memory_loaded", notes=len(start_notes), outcomeLessons=len(outcomes), blockedPatterns=len(blocked))

    # 3. Agent run with the restricted toolset.
    ledger = policy.Ledger()
    guard = policy.Guard(snapshot["patterns"], cfg.caps, blocked, ledger)
    toolset = Toolset(client=client, snapshot=snapshot, actions=actions, guard=guard, ledger=ledger,
                      dry_run=cfg.dry_run, run_id=run_id, log=log)
    try:
        outcome = runner(cfg, toolset, task_message(cfg, snapshot, actions, outcome_summary))
    except Exception as error:  # noqa: BLE001 - any agent failure still gets a report and memory write
        outcome = AgentOutcome(False, f"{type(error).__name__}: {str(error)[:200]}")
    failure = outcome.error
    if outcome.ok and toolset.report_markdown is None:
        failure = "Hermes did not submit a run report"

    # 4. Memory write-back: validated entries plus every outcome lesson.
    exit_code = EXIT_OK if not failure else EXIT_AGENT
    notes = memory.preserve_ids(memory.merge(memory.read_file(cfg.home), outcomes, exclude=human_keys), stored_notes)
    try:
        try:
            client.put_memory(stored["version"], notes)
        except api.Conflict:
            # Someone edited memory in blakSOC during the run: keep theirs, add ours, retry once.
            latest = sanitize.memory_response(client.memory())
            latest_notes = memory.fresh(latest["notes"], now, latest["retentionDays"])
            theirs = [n["text"] for n in latest_notes if n.get("kind") == "model"]
            human_keys |= {memory._norm(n["text"]) for n in latest_notes if n.get("kind") == "human"}
            entries = memory.rebase_entries(memory.read_file(cfg.home), stored["notes"], latest_notes)
            # Outcome copies in MEMORY.md must not become fresh model lessons after their expiry.
            outcome_texts = {memory._norm(n["text"]) for n in outcomes}
            entries = [e for e in entries if memory._norm(e) not in outcome_texts]
            kept_outcome_texts = set(memory.rebase_entries([n["text"] for n in outcomes], stored["notes"], latest_notes))
            retry_outcomes = [n for n in memory.fresh(outcomes, now, latest["retentionDays"]) if n["text"] in kept_outcome_texts]
            retry_outcomes += [n for n in latest_notes if n.get("kind") == "outcome"]
            notes = memory.preserve_ids(memory.merge(theirs + entries, retry_outcomes, exclude=human_keys), latest_notes)
            client.put_memory(latest["version"], notes)
        log("memory_saved", notes=len(notes))
    except (api.ApiError, sanitize.ShapeError, sanitize.PiiAbort) as error:
        log("memory_save_failed", "error", detail=str(error)[:200])
        exit_code = exit_code or EXIT_API

    # 5. Report, always: the controller's record is useful even when the model failed.
    run_stats = report.stats(ledger, patterns=len(snapshot["patterns"]), stripped=snapshot["stripped"],
                             dry_run=cfg.dry_run, outcomes=outcome_summary, model_ok=not failure,
                             memory_notes=len(notes))
    run_stats.update(tokens=outcome.tokens, turns=outcome.turns, seconds=round(time.monotonic() - started))
    markdown = report.build(model_markdown=toolset.report_markdown, ledger=ledger, run_stats=run_stats,
                            period_start=period_start, period_end=period_end, failure=failure)
    try:
        client.submit_report(period_start, period_end, markdown, report.api_stats(run_stats), idempotency_key="report-" + run_id)
        log("report_submitted", actions=run_stats["actions"], dryRun=cfg.dry_run, switchOff=ledger.switch_off)
    except api.ApiError as error:
        log("report_submit_failed", "error", status=error.status, code=error.code)
        exit_code = exit_code or EXIT_API

    if exit_code == EXIT_AGENT:
        log("run_failed", "error", reason=failure, actions=run_stats["actions"])
    elif exit_code:
        log("run_failed", "error", reason="could not save results to blakSOC", actions=run_stats["actions"])
    else:
        log("run_finished", actions=run_stats["actions"], tokens=outcome.tokens, turns=outcome.turns)
    return exit_code


def main(argv=None) -> int:
    try:
        cfg = Config.from_env()
        client = api.TuningClient(cfg.base_url, cfg.credential, timeout=cfg.http_timeout)
    except api.ConfigError as error:
        log("run_aborted", "error", reason="configuration", detail=str(error))
        return EXIT_CONFIG
    return run(cfg, client)


if __name__ == "__main__":
    sys.exit(main())
