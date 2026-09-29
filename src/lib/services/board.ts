import { and, desc, eq, sql } from "drizzle-orm";
import { adminDb, type Tx } from "@/db/client";
import { withScope } from "@/db/scope";
import { boardBriefs, integrations, notificationDeliveries, onboardingDrafts, tenants } from "@/db/schema";
import { systemScope, type AccessContext } from "@/lib/auth/access";
import { audit } from "@/lib/audit";
import { EmailNotifier } from "@/lib/connectors/au-notify";
import { notifier } from "@/lib/connectors/instances";
import type { Notification } from "@/lib/connectors/notify";
import { env } from "@/lib/env";
import { boardPeriodKey, boardProse, cleanPreamble, parseBoardImage, type BoardSpan, BoardBriefError } from "@/lib/reports/board";
import { buildReport, saveReport } from "@/lib/reports/generate";
import { inTenant } from "./common";

export { BoardBriefError };

export async function setBoardBrief(
  ctx: AccessContext,
  tenantId: string,
  patch: { preamble?: string | null; image?: { mime: string; data: string } | null; span?: BoardSpan },
) {
  const preamble = patch.preamble === undefined ? undefined : cleanPreamble(patch.preamble);
  const image = patch.image === undefined ? undefined : patch.image === null ? null : parseBoardImage(patch.image.mime, patch.image.data);
  if (patch.span !== undefined && patch.span !== "month" && patch.span !== "quarter") throw new BoardBriefError("span");
  return inTenant(ctx, "report:generate", tenantId, async (tx) => {
    const [prev] = await tx.select().from(boardBriefs).where(eq(boardBriefs.tenantId, tenantId));
    const next = {
      tenantId,
      preamble: preamble === undefined ? prev?.preamble ?? null : preamble,
      imageMime: image === undefined ? prev?.imageMime ?? null : image?.mime ?? null,
      imageData: image === undefined ? prev?.imageData ?? null : image?.data ?? null,
      span: patch.span ?? (prev?.span === "quarter" ? "quarter" : "month"),
      updatedAt: new Date(),
    };
    await tx.insert(boardBriefs).values(next).onConflictDoUpdate({
      target: boardBriefs.tenantId,
      set: { preamble: next.preamble, imageMime: next.imageMime, imageData: next.imageData, span: next.span, updatedAt: next.updatedAt },
    });
    return next;
  });
}

async function boardContact(tenantId: string): Promise<string | null> {
  const [draft] = await adminDb()
    .select({ contacts: onboardingDrafts.contacts })
    .from(onboardingDrafts)
    .where(and(eq(onboardingDrafts.tenantId, tenantId), eq(onboardingDrafts.status, "complete")))
    .orderBy(desc(onboardingDrafts.updatedAt))
    .limit(1);
  const board = draft?.contacts?.board;
  if (!board || board.channel !== "email") return null;
  const value = board.value.trim();
  if (!value.includes("@") || /\s/.test(value)) return null;
  return value;
}

async function sendBoard(tx: Tx, tenantId: string, note: Notification) {
  const [row] = await tx
    .select()
    .from(integrations)
    .where(and(eq(integrations.tenantId, tenantId), eq(integrations.provider, "email"), eq(integrations.enabled, true)))
    .limit(1);
  if (row) {
    const live = notifier(row);
    if (live) return live.deliver(note);
  }
  return new EmailNotifier(
    { host: "fixture.invalid", port: 587, from: "board@blaksoc.local", mode: "fixture" },
    { username: "fixture", password: "fixture" },
  ).deliver(note);
}

export async function deliverBoardSummary(tenantId: string, now = new Date()) {
  const contact = await boardContact(tenantId);
  if (!contact) return { sent: false as const, reason: "no-board-email" as const };
  const [brief] = await adminDb().select({ span: boardBriefs.span }).from(boardBriefs).where(eq(boardBriefs.tenantId, tenantId));
  const span: BoardSpan = brief?.span === "quarter" ? "quarter" : "month";
  const period = boardPeriodKey(now, span);
  const [already] = await adminDb()
    .select({ id: notificationDeliveries.id })
    .from(notificationDeliveries)
    .where(and(
      eq(notificationDeliveries.tenantId, tenantId),
      eq(notificationDeliveries.channel, "email"),
      eq(notificationDeliveries.destination, contact),
      eq(notificationDeliveries.status, "sent"),
      sql`${notificationDeliveries.detail}->>'kind' = 'board_summary'`,
      sql`${notificationDeliveries.detail}->>'period' = ${period}`,
    ));
  if (already) return { sent: false as const, reason: "already" as const };

  return withScope(systemScope(tenantId), async (tx) => {
    const content = await buildReport(tx, tenantId, "board_summary", { end: now, span });
    const report = await saveReport(tx, tenantId, "board_summary", content, null);
    let receipt: { status: "sent" | "failed"; providerRef: string | null; detail: string };
    try {
      receipt = await sendBoard(tx, tenantId, {
        event: "report.board_summary",
        tenant: { id: tenantId, name: content.tenantName },
        title: `Board summary for ${content.tenantName}`,
        url: `${env().APP_URL}/reports/${report.id}`,
        summary: boardProse(content.sections).slice(0, 4000),
        to: contact,
      });
    } catch (err) {
      receipt = { status: "failed", providerRef: null, detail: err instanceof Error ? err.message : "send failed" };
    }
    await tx.insert(notificationDeliveries).values({
      tenantId,
      provider: "email",
      channel: "email",
      destination: contact,
      status: receipt.status,
      providerRef: receipt.providerRef,
      detail: { kind: "board_summary", period, span, reportId: report.id, detail: receipt.detail },
    });
    await audit(tx, {
      actorId: null,
      actorKind: "system",
      tenantId,
      action: "report.board_deliver",
      targetType: "report",
      targetId: report.id,
      detail: { destination: contact, period, status: receipt.status },
    });
    if (receipt.status !== "sent") return { sent: false as const, reason: "failed" as const, destination: contact };
    return { sent: true as const, reportId: report.id, destination: contact };
  });
}

/** Worker sweep. Tests call deliverBoardSummary for one tenant instead. */
export async function runDueBoardSummaries(now = new Date()) {
  const rows = await adminDb().select({ id: tenants.id }).from(tenants).where(eq(tenants.kind, "customer"));
  const out: { tenantId: string; result: string }[] = [];
  for (const row of rows) {
    try {
      const result = await deliverBoardSummary(row.id, now);
      out.push({ tenantId: row.id, result: result.sent ? "sent" : result.reason });
    } catch (err) {
      out.push({ tenantId: row.id, result: err instanceof Error ? err.message : "failed" });
    }
  }
  return out;
}
