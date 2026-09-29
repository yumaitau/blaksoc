/**
 * Incident response plans are versioned exports. Exercises show on the board
 * and on the Essential Eight PDF. Advisory review is not recorded here.
 */
import { randomUUID } from "node:crypto";
import { inflateSync } from "node:zlib";
import { inArray } from "drizzle-orm";
import { afterAll, describe, expect, it } from "vitest";
import { adminDb } from "@/db/client";
import { tenants } from "@/db/schema";
import { withScope } from "@/db/scope";
import type { AccessContext } from "@/lib/auth/access";
import { systemScope } from "@/lib/auth/access";
import { answerIds } from "@/lib/essential-eight/requirements";
import { buildReport } from "@/lib/reports/generate";
import { AccessDenied } from "@/lib/services/common";
import { assessmentPdf, submitEssentialEight } from "@/lib/services/essential-eight";
import { completeExercise, exportIrPlan, IrError, saveIrPlan } from "@/lib/services/ir";

const created: string[] = [];

function staff(tenantId: string, slug: string): AccessContext {
  return {
    principal: { userId: "ir-admin", name: "Clinic Admin", email: "ir@example.invalid", isBreakGlass: false },
    isPlatform: false,
    grants: [{ roleKey: "customer_admin", tenantId, permissions: new Set(["report:generate"]) }],
    tenantIds: [tenantId],
    tenants: [{ id: tenantId, slug, name: "River Clinic", kind: "customer" }],
  };
}

function pdfPlain(bytes: Uint8Array) {
  const raw = Buffer.from(bytes);
  const latin = raw.toString("latin1");
  let out = "";
  const marker = /stream\r?\n/g;
  let match: RegExpExecArray | null;
  while ((match = marker.exec(latin))) {
    const start = match.index + match[0].length;
    const end = latin.indexOf("endstream", start);
    let chunk: Buffer = raw.subarray(start, end);
    if (chunk[chunk.length - 1] === 0x0a) chunk = chunk.subarray(0, -1);
    try {
      chunk = Buffer.from(inflateSync(chunk));
    } catch {
      // already plain
    }
    out += chunk.toString("latin1").replace(/<([0-9A-Fa-f\s]+)>/g, (_, hex: string) => Buffer.from(hex.replace(/\s/g, ""), "hex").toString("latin1"));
  }
  return out;
}

afterAll(async () => {
  if (created.length) await adminDb().delete(tenants).where(inArray(tenants.id, created));
});

describe("incident response plan", () => {
  it("versions the plan, exports both files, and reports a finished exercise", async () => {
    const slug = `ir-${randomUUID().slice(0, 8)}`;
    const [tenant] = await adminDb().insert(tenants).values({ slug, name: "River Clinic", kind: "customer" }).returning();
    created.push(tenant!.id);
    const ctx = staff(tenant!.id, slug);
    const first = await saveIrPlan(ctx, tenant!.id, {
      culturalProtocol: "Elders speak before a public line",
      bank: "Clinic account 100",
      insurer: "Cover note A",
      itProvider: "Local IT",
    });
    const second = await saveIrPlan(ctx, tenant!.id, {
      culturalProtocol: "Elders speak before a public line",
      bank: "Clinic account 200",
      insurer: "Cover note A",
      itProvider: "Local IT",
    });
    expect(first.version).toBe(1);
    expect(second.version).toBe(2);

    const older = await exportIrPlan(ctx, tenant!.id, 1, "docx");
    const newer = await exportIrPlan(ctx, tenant!.id, 2, "pdf");
    const docx = Buffer.from(older.bytes).toString("utf8");
    const pdf = pdfPlain(newer.bytes);
    expect(Buffer.from(newer.bytes).subarray(0, 4).toString()).toBe("%PDF");
    expect(docx).toContain("Clinic account 100");
    expect(docx).not.toContain("Clinic account 200");
    expect(docx).toContain("River Clinic");
    expect(docx).toContain("has not been reviewed by an advisory group");
    expect(docx).toContain("BEC payment fraud");
    expect(docx).toContain("Ransomware at a remote site");
    expect(docx).toContain("Lost laptop with client records");
    expect(docx).toContain("Leaked cultural material");
    expect(pdf).toContain("Clinic account 200");
    expect(pdf).toContain("has not been reviewed");

    const when = new Date("2026-06-01T00:00:00.000Z");
    await completeExercise(ctx, tenant!.id, "bec-payment", { notes: "Called the known number", lessons: "Stop the payment first" }, when);
    const board = await withScope(systemScope(tenant!.id), (tx) => buildReport(tx, tenant!.id, "board_summary", { end: when }));
    expect(board.sections.find((section) => section.heading === "Practice")?.body).toBe("One tabletop exercise was finished in this time.");

    const answers = Object.fromEntries(answerIds().map((id) => [id, "no"]));
    const assessed = await submitEssentialEight(ctx, tenant!.id, { answers, owner: "Ava Chen", cadenceDays: 90, assessedAt: when });
    const e8 = pdfPlain(await assessmentPdf(ctx, tenant!.id, assessed.id));
    expect(e8).toContain("Finished: BEC payment fraud.");

    const other = staff(randomUUID(), "other");
    await expect(saveIrPlan(other, tenant!.id, { culturalProtocol: "", bank: "", insurer: "", itProvider: "" })).rejects.toBeInstanceOf(AccessDenied);
    await expect(completeExercise(ctx, tenant!.id, "missing-scene", { notes: "", lessons: "" }, when)).rejects.toBeInstanceOf(IrError);
  });
});
