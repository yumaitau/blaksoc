import { describeAuditEntry, redactAuditDetail, type AuditNames, type DescribableAuditEntry } from "./describe";

export type AuditCsvRow = {
  entry: DescribableAuditEntry & { id: number; at: Date; actorId: string | null; ip: string | null; hash: string | null };
  actorName: string | null;
  actorEmail?: string | null;
  tenantName: string | null;
};

/**
 * Quoted CSV cell. A leading =, +, -, @, tab or CR is prefixed with ' so a spreadsheet shows the
 * text instead of evaluating it (audit fields carry user-supplied names and notes).
 */
export function csvCell(v: unknown): string {
  const s = v === null || v === undefined ? "" : String(v);
  const safe = /^[=+\-@\t\r]/.test(s) ? `'${s}` : s;
  return `"${safe.replace(/"/g, '""')}"`;
}

const HEADER = ["id", "time_utc", "actor_kind", "actor", "actor_email", "actor_id", "customer", "action", "summary", "target_type", "target_id", "ip", "detail", "hash"];

/** The audit trail as CSV, with the same wording and redaction as the page. */
export function auditCsv(rows: readonly AuditCsvRow[], names: AuditNames = {}): string {
  const lines = [HEADER.map(csvCell).join(",")];
  for (const { entry: e, actorName, actorEmail, tenantName } of rows) {
    const { summary } = describeAuditEntry(e, names);
    lines.push(
      [
        e.id,
        e.at.toISOString(),
        e.actorKind,
        actorName ?? "",
        actorEmail ?? "",
        e.actorId ?? "",
        tenantName ?? (e.tenantId ? e.tenantId : "platform"),
        e.action,
        summary,
        e.targetType ?? "",
        e.targetId ?? "",
        e.ip ?? "",
        e.detail === null || e.detail === undefined ? "" : JSON.stringify(redactAuditDetail(e.detail)),
        e.hash ?? "",
      ].map(csvCell).join(","),
    );
  }
  return `${lines.join("\r\n")}\r\n`;
}
