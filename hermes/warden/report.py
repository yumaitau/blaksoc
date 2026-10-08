"""Run report: validate Hermes' Markdown, add the controller's own record, prove it is PII-free."""

from __future__ import annotations

from . import policy, sanitize

REQUIRED_HEADINGS = (
    "## What was noisy",
    "## What Hermes did",
    "## Held back",
    "## Analyst feedback",
    "## Wazuh tuning recommendations",
)
MAX_MODEL_REPORT = 20_000
MAX_REPORT = 60_000


def check_model_report(markdown) -> list:
    if not isinstance(markdown, str) or not markdown.strip():
        return ["markdown must be a non-empty string"]
    problems = []
    if len(markdown) > MAX_MODEL_REPORT:
        problems.append(f"report longer than {MAX_MODEL_REPORT} characters")
    missing = [h for h in REQUIRED_HEADINGS if h.lower() not in markdown.lower()]
    if missing:
        problems.append("missing headings: " + "; ".join(missing))
    leaks = sanitize.find_pii(markdown)
    if leaks:
        problems.append("identifier-like content found (" + ", ".join(leaks) + "); refer to patterns by "
                        "source, rule id, tenantRef or patternId only")
    if "<" in markdown and ">" in markdown and any(t in markdown.lower() for t in ("<script", "<iframe", "<img")):
        problems.append("HTML is not allowed")
    return problems


def stats(ledger: policy.Ledger, *, patterns: int, stripped: int, dry_run: bool, outcomes: dict,
          model_ok: bool, memory_notes: int) -> dict:
    counts = ledger.counts()
    return {
        "patternsReviewed": patterns,
        "fieldsStripped": stripped,
        "dryRun": dry_run,
        "actSwitchOff": ledger.switch_off,
        "actions": {
            "executed": counts[policy.EXECUTED],
            "dryRun": counts[policy.DRY_RUN],
            "refused": counts[policy.REFUSED],
            "heldBack": counts[policy.HELD],
            "failed": counts[policy.FAILED],
        },
        "byKind": ledger.by_kind(),
        "outcomes": outcomes,
        "modelCompleted": model_ok,
        "memoryNotes": memory_notes,
    }


def api_stats(run_stats: dict) -> dict:
    """The counts blakSOC stores with a report; the full breakdown is in the report's own table."""
    actions = run_stats["actions"]
    return {
        "executed": actions["executed"],
        "refused": actions["refused"] + actions["failed"],
        "dryRun": actions["dryRun"],
        "patternsReviewed": run_stats["patternsReviewed"],
    }


def _cell(text: str, limit: int = 160) -> str:
    return sanitize.scrub(sanitize.clean_text(text, limit)).replace("|", "/").replace("\n", " ")


def build(*, model_markdown, ledger: policy.Ledger, run_stats: dict, period_start: str, period_end: str,
          failure: str = "") -> str:
    a = run_stats["actions"]
    mode = (
        "DRY RUN: Hermes recorded what it would do; nothing was changed in blakSOC."
        if run_stats["dryRun"]
        else "blakSOC's \"Allow Hermes to act\" switch was OFF: writes were refused (409) and recorded as dry-run."
        if run_stats["actSwitchOff"]
        else "LIVE: actions marked executed were applied in blakSOC."
    )
    lines = [
        f"# Hermes noise review report — {period_start[:10]} to {period_end[:10]}",
        "",
        f"> {mode}",
        "",
    ]
    if failure:
        lines += [f"> Run problem: {sanitize.scrub(sanitize.clean_text(failure, 300))}", ""]
    if model_markdown:
        body = model_markdown.strip()
        if body.startswith("# "):
            body = body.split("\n", 1)[1] if "\n" in body else ""
        lines += [body.strip(), ""]
    else:
        lines += [
            "Hermes did not complete an analysis this week. The controller's record below lists every action "
            "it attempted; nothing else was changed.",
            "",
        ]
    lines += [
        "## Controller record",
        "",
        f"Patterns reviewed: {run_stats['patternsReviewed']}. Actions executed: {a['executed']}; "
        f"dry-run: {a['dryRun']}; refused by blakSOC: {a['refused']}; held back by guardrails: {a['heldBack']}; "
        f"failed (outcome unknown): {a['failed']}.",
        "",
    ]
    outcomes = run_stats.get("outcomes", {})
    if outcomes:
        lines += [
            f"Earlier actions reviewed: {outcomes.get('reviewed', 0)}; undone by analysts: "
            f"{outcomes.get('undone', 0)}; with reopened alerts: {outcomes.get('reopened', 0)}.",
            "",
        ]
    if ledger.entries:
        lines += ["| Action | Pattern | Status | Reason | blakSOC / guardrail |", "|---|---|---|---|---|"]
        for e in ledger.entries[:150]:
            affected = f" ({e.affected} alerts)" if e.affected is not None else ""
            lines.append(f"| {e.kind} | {_cell(e.ref, 80)} | {e.status}{affected} | {_cell(e.reason)} | {_cell(e.detail)} |")
        lines.append("")
    lines += ["Counts and patterns only: this report contains no alert titles, hosts, users, addresses or customer names."]
    markdown = "\n".join(lines)
    for _ in range(3):
        markdown = sanitize.scrub(markdown)
        if not sanitize.find_pii(markdown):
            return markdown[:MAX_REPORT]
    raise ValueError("report still contains identifier-like content after redaction")
