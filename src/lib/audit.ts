import { sql } from "drizzle-orm";
import type { DbOrTx } from "@/db/client";
import { auditLog } from "@/db/schema";

export type AuditEntry = {
  actorId: string | null;
  actorKind: "user" | "system" | "playbook" | "ai";
  tenantId: string | null;
  action: string;
  targetType?: string;
  targetId?: string;
  ip?: string | null;
  detail?: Record<string, unknown>;
};

/** Append to the hash-chained audit log. Call inside the same transaction as the change it records. */
export async function audit(tx: DbOrTx, entry: AuditEntry): Promise<void> {
  await tx.insert(auditLog).values({
    actorId: entry.actorId,
    actorKind: entry.actorKind,
    tenantId: entry.tenantId,
    action: entry.action,
    targetType: entry.targetType,
    targetId: entry.targetId,
    ip: entry.ip ?? null,
    detail: entry.detail ?? null,
  });
}

export async function verifyAuditChain(tx: DbOrTx): Promise<{ ok: boolean; checked: number; firstBadId: number | null }> {
  const rows = await tx.execute<{ ok: boolean; checked: string; first_bad_id: string | null }>(sql`select * from audit_log_verify()`);
  const r = rows[0]!;
  return { ok: r.ok, checked: Number(r.checked), firstBadId: r.first_bad_id ? Number(r.first_bad_id) : null };
}
