"""Memory sync between blakSOC (durable store) and Hermes' built-in memory file for one run.

Run start: notes from GET /api/v1/tuning/memory plus fresh outcome lessons are written to
$HERMES_HOME/memories/MEMORY.md, which Hermes loads as its frozen memory snapshot; its memory tool can
add, replace or remove entries during the run. Run end: the file is read back, every entry is
validated (length, identifiers redacted, de-duplicated), outcome lessons are re-added if the model
removed them, the set is capped, and the result is PUT back with the version that was read.

Outcome lessons are written by the controller, never the model: an action analysts undid or whose
alerts they reopened becomes "[outcome] … do not auto-close this pattern", and that pattern key is
blocked for close / noise rule / purge in policy.Guard.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import policy, sanitize

ENTRY_DELIMITER = "\n§\n"  # Hermes tools/memory_tool.py
OUTCOME_PREFIX = "[outcome] "
MAX_NOTES = 40
MAX_NOTE_CHARS = 400
CHAR_BUDGET = 6000          # also Hermes' memory_char_limit (controller.write_config)
OUTCOME_RETENTION_DAYS = 180


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip().lower())


def outcome_lessons(actions: list, patterns: list) -> tuple[list, set, dict]:
    """(notes, blocked pattern keys, summary counts) from past actions. Deterministic."""
    by_id = {p["patternId"]: p for p in patterns}
    notes, blocked = [], set()
    summary = {"reviewed": len(actions), "undone": 0, "reopened": 0}
    for action in actions:
        undone = action.get("undoneAt")
        reopened = action.get("reopenedCount", 0) or 0
        if not undone and reopened <= 0:
            continue
        summary["undone" if undone else "reopened"] += 1
        pattern = by_id.get(action.get("patternId"), {})
        ident = {
            "tenantRef": action.get("tenantRef") or pattern.get("tenantRef", "-"),
            "source": action.get("source") or pattern.get("source", "-"),
            "ruleId": action.get("ruleId") or pattern.get("ruleId", "-"),
        }
        blocked.add(policy.pattern_key(ident))
        what = f"undid it on {undone[:10]}" if undone else f"reopened {reopened} of its alerts"
        kind = action.get("kind", "action")
        when = (action.get("createdAt") or "")[:10]
        notes.append({
            "kind": "outcome",
            "text": f"{OUTCOME_PREFIX}{policy.pattern_ref(ident)} (key {policy.pattern_key(ident)}): analysts "
                    f"{what} after Hermes' {kind} of {when}. Analysts disagreed; do not auto-close this pattern, "
                    "annotate instead.",
            "createdAt": action.get("createdAt"),
        })
    return notes, blocked, summary


def blocked_from_notes(notes: list) -> set:
    """Pattern keys already recorded as analyst disagreements in stored outcome notes."""
    keys = set()
    for note in notes:
        if note.get("kind") == "outcome":
            match = re.search(r"\(key ([A-Za-z0-9_.:-]+)\)", note.get("text", ""))
            if match:
                keys.add(match.group(1))
    return keys


def fresh(notes: list, now: datetime) -> list:
    """Drop outcome notes older than the retention window (model lessons are curated by the model)."""
    cutoff = now - timedelta(days=OUTCOME_RETENTION_DAYS)
    out = []
    for note in notes:
        created = note.get("createdAt")
        if note.get("kind") == "outcome" and created:
            try:
                if datetime.fromisoformat(created.replace("Z", "+00:00")).astimezone(timezone.utc) < cutoff:
                    continue
            except ValueError:
                pass
        out.append(note)
    return out


def write_file(home: Path, notes: list) -> Path:
    directory = Path(home) / "memories"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "MEMORY.md"
    path.write_text(ENTRY_DELIMITER.join(n["text"] for n in notes), encoding="utf-8")
    (directory / "USER.md").write_text("", encoding="utf-8")
    return path


def read_file(home: Path) -> list:
    path = Path(home) / "memories" / "MEMORY.md"
    if not path.is_file():
        return []
    raw = path.read_text(encoding="utf-8", errors="replace")
    return [e.strip() for e in raw.split(ENTRY_DELIMITER) if e.strip()]


def merge(entries: list, outcomes: list, exclude: set = frozenset()) -> list:
    """Validated note list for PUT: outcome notes first (never dropped for the model), then lessons.
    `exclude` holds normalised texts of analysts' notes: they are shown to the model but never written back."""
    seen, notes = set(exclude), []
    outcome_texts = {_norm(o["text"]) for o in outcomes}
    for outcome in outcomes:
        key = _norm(outcome["text"])
        if key not in seen:
            seen.add(key)
            notes.append({"kind": "outcome", "text": outcome["text"][:MAX_NOTE_CHARS * 2],
                          **({"createdAt": outcome["createdAt"]} if outcome.get("createdAt") else {})})
    for entry in entries:
        text = sanitize.scrub(sanitize.clean_text(entry, MAX_NOTE_CHARS))
        if _norm(text) in outcome_texts:
            continue
        if text.startswith(OUTCOME_PREFIX.strip()):
            # Only the controller writes outcome notes; a model copy becomes an ordinary lesson.
            text = text[len(OUTCOME_PREFIX.strip()):].strip()
        key = _norm(text)
        if len(text) < 10 or key in seen:
            continue
        seen.add(key)
        notes.append({"kind": "model", "text": text})
    kept, used = [], 0
    for note in notes:
        size = len(note["text"]) + len(ENTRY_DELIMITER)
        if len(kept) >= MAX_NOTES or (used + size > CHAR_BUDGET and note["kind"] != "outcome"):
            continue
        kept.append(note)
        used += size
    return kept
