import { piiKind, stripControl } from "./pii";

/** The tuning agent's memory: limits, validation and the change summary the audit trail keeps. Pure. */

export const MEMORY_MAX_NOTES = 500;
export const MEMORY_MAX_CHARS = 2000;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** A note as the agent sends it: an `id` updates that note, none creates one. `human` entries are ignored. */
export type MemoryNoteInput = { id?: string | null; kind: "model" | "outcome" | "human"; text: string };
export type AgentNote = { id: string | null; kind: "model" | "outcome"; text: string };
export type StoredNote = { id: string; kind: string; text: string };

/** Why `text` may not go into memory, or null. Never echoes the text. */
export function noteProblem(text: string): string | null {
  if (!text) return "is empty";
  if (text.length > MEMORY_MAX_CHARS) return `is longer than ${MEMORY_MAX_CHARS} characters`;
  const kind = piiKind(text);
  if (kind) return `looks like it contains ${kind === "ipv4" || kind === "ipv6" ? "an IP address" : kind === "email" ? "an email address" : "a host name"}; memory holds patterns, never customer identifiers`;
  return null;
}

/**
 * The agent's notes to keep, cleaned, or the first problem (index and why). Analysts' (`human`) notes are not
 * the agent's to change, so entries of that kind are dropped here and the stored ones are kept as they are.
 */
export function checkMemoryNotes(notes: MemoryNoteInput[]): { ok: true; notes: AgentNote[] } | { ok: false; message: string } {
  const out: AgentNote[] = [];
  const ids = new Set<string>();
  for (const [i, n] of notes.entries()) {
    if (n.kind === "human") continue;
    if (n.id != null) {
      if (!UUID.test(n.id)) return { ok: false, message: `notes.${i}.id is not a note id.` };
      if (ids.has(n.id)) return { ok: false, message: `notes.${i}.id appears twice.` };
      ids.add(n.id);
    }
    const text = stripControl(n.text).trim();
    const problem = noteProblem(text);
    if (problem) return { ok: false, message: `notes.${i}.text ${problem}.` };
    out.push({ id: n.id ?? null, kind: n.kind, text });
  }
  if (out.length > MEMORY_MAX_NOTES) return { ok: false, message: `At most ${MEMORY_MAX_NOTES} notes.` };
  return { ok: true, notes: out };
}

/** Counts only: the audit trail records how memory changed, not what it says. `before` holds the agent's notes. */
export function memoryDiff(before: readonly StoredNote[], after: readonly AgentNote[]) {
  const old = new Map(before.map((n) => [n.id, n]));
  let added = 0;
  let changed = 0;
  let unchanged = 0;
  for (const n of after) {
    const o = n.id ? old.get(n.id) : undefined;
    if (!o) added++;
    else if (o.text !== n.text || o.kind !== n.kind) changed++;
    else unchanged++;
  }
  const kept = new Set(after.map((n) => n.id).filter(Boolean));
  const removed = before.filter((n) => !kept.has(n.id)).length;
  return { added, removed, changed, unchanged };
}
