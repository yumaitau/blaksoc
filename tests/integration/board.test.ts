import { randomUUID } from "node:crypto";
import { inflateSync } from "node:zlib";
import { and, eq, inArray } from "drizzle-orm";
import { PDFDocument } from "pdf-lib";
import { afterAll, describe, expect, it } from "vitest";
import { adminDb } from "@/db/client";
import { withScope } from "@/db/scope";
import { alerts, assets, cveIntel, e8Assessments, incidents, notificationDeliveries, onboardingDrafts, reports, responseActions, tenants, vulnerabilities } from "@/db/schema";
import type { AccessContext } from "@/lib/auth/access";
import type { Permission } from "@/lib/auth/permissions";
import { systemScope } from "@/lib/auth/access";
import type { AssessmentResult } from "@/lib/essential-eight/score";
import { STRATEGIES } from "@/lib/essential-eight/requirements";
import { boardProse, readingAgeYears } from "@/lib/reports/board";
import { toPdf } from "@/lib/reports/export";
import { buildReport } from "@/lib/reports/generate";
import { deliverBoardSummary, setBoardBrief } from "@/lib/services/board";
import { AccessDenied } from "@/lib/services/common";

const PNG = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==";
const created: string[] = [];
const cves: string[] = [];
const end = new Date("2026-06-01T00:00:00.000Z");

function person(channel: "email" | "phone", value: string) {
  return { name: "Pat", channel, value };
}

function customer(tenantId: string, permissions: Permission[]): AccessContext {
  return {
    principal: { userId: "board-customer", name: "Clinic Admin", email: "clinic@example.invalid", isBreakGlass: false },
    isPlatform: false,
    grants: [{ roleKey: "customer_admin", tenantId, permissions: new Set(permissions) }],
    tenantIds: [tenantId],
    tenants: [{ id: tenantId, slug: "board", name: "River Clinic", kind: "customer" }],
  };
}

async function freshTenant() {
  const slug = `board-${randomUUID().slice(0, 8)}`;
  const [row] = await adminDb().insert(tenants).values({ slug, name: "River Clinic", kind: "customer" }).returning();
  created.push(row!.id);
  return row!;
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
  if (cves.length) await adminDb().delete(cveIntel).where(inArray(cveIntel.cve, cves));
});

describe("board summary", () => {
  it("builds a plain one-pager from records, with evidence links, a large PDF and slides", async () => {
    const tenant = await freshTenant();
    const cve = `CVE-2099-${randomUUID().slice(0, 8)}`;
    cves.push(cve);
    const db = adminDb();
    const [open] = await db.insert(incidents).values({ tenantId: tenant.id, title: "Stolen mail", severity: "critical", status: "OPEN", createdAt: new Date("2026-05-10T00:00:00.000Z") }).returning();
    await db.insert(incidents).values({ tenantId: tenant.id, title: "Old mail", severity: "critical", status: "CLOSED", createdAt: new Date("2026-05-11T00:00:00.000Z"), closedAt: new Date("2026-05-12T00:00:00.000Z") });
    await db.insert(alerts).values([
      { tenantId: tenant.id, source: "health", externalId: `health:${randomUUID()}`, title: "Quiet PC", severity: "medium", status: "NEW", occurredAt: end },
      { tenantId: tenant.id, source: "health", externalId: `health:${randomUUID()}`, title: "False quiet", severity: "medium", status: "FALSE_POSITIVE", occurredAt: end },
    ]);
    await db.insert(cveIntel).values({ cve, kev: true }).onConflictDoUpdate({ target: cveIntel.cve, set: { kev: true } });
    const [asset] = await db.insert(assets).values({ tenantId: tenant.id, kind: "endpoint", name: "Front desk" }).returning();
    await db.insert(vulnerabilities).values({ tenantId: tenant.id, assetId: asset!.id, cve, packageName: "desk", status: "open" });
    await db.insert(responseActions).values([
      { tenantId: tenant.id, action: "isolate_endpoint", target: {}, destructive: true, status: "SUCCEEDED", requestedByKind: "playbook", createdAt: new Date("2026-05-20T00:00:00.000Z") },
      { tenantId: tenant.id, action: "disable_identity", target: {}, destructive: true, status: "SUCCEEDED", requestedByKind: "playbook", createdAt: new Date("2026-01-01T00:00:00.000Z") },
    ]);
    const result = {
      disclaimer: "x",
      model: "test",
      assessedAt: "2026-05-01T00:00:00.000Z",
      cadenceDays: 90,
      nextDue: "2026-08-01T00:00:00.000Z",
      owner: "Director",
      telemetry: {},
      ratings: STRATEGIES.map((row, index) => ({ strategy: row.id, label: row.label, level: index === 0 ? 0 : 1, telemetry: "", lines: [] })),
      remediation: [],
      previous: null,
      trend: Object.fromEntries(STRATEGIES.map((row) => [row.id, "first"])),
    } as unknown as AssessmentResult;
    await db.insert(e8Assessments).values({
      tenantId: tenant.id,
      assessedAt: new Date("2026-05-01T00:00:00.000Z"),
      cadenceDays: 90,
      nextDue: new Date("2026-08-01T00:00:00.000Z"),
      owner: "Director",
      answers: {},
      result,
    });

    const denied = customer(tenant.id, ["report:read"]);
    await expect(setBoardBrief(denied, tenant.id, { span: "quarter" })).rejects.toBeInstanceOf(AccessDenied);
    await setBoardBrief(customer(tenant.id, ["report:generate"]), tenant.id, {
      span: "quarter",
      preamble: "Organisational cybersecurity transformation leverages synergistic paradigms.",
      image: { mime: "image/png", data: PNG },
    });

    const content = await withScope(systemScope(tenant.id), (tx) => buildReport(tx, tenant.id, "board_summary", { end, span: "quarter" }));
    expect(content.audience).toBe("board");
    expect(content.light).toBe("now");
    expect(content.image?.mime).toBe("image/png");
    expect(new Date(content.period.start).getTime()).toBe(end.getTime() - 90 * 86_400_000);
    expect(readingAgeYears(boardProse(content.sections))).toBeLessThanOrEqual(12);
    const body = content.sections.map((section) => section.body ?? "").join(" ");
    expect(body).toContain("Open serious problems: 1");
    expect(body).toContain("Open health warnings: 1");
    expect(body).toContain("Open flaws attackers use: 1");
    expect(body).toContain("took a PC off the net");
    expect(body).not.toContain("turned off an account");
    expect(body).toContain("lowest level is 0 of 3");
    expect(body).not.toContain("No check is on file");
    expect(content.sections.some((section) => /transparency/i.test(section.heading))).toBe(false);
    expect(content.sections.find((section) => section.heading === "What happened")?.links?.map((link) => link.href)).toEqual([`/soc/incidents/${open!.id}`]);
    expect(content.sections.find((section) => section.heading === "Overall status")?.links?.map((link) => link.href)).toEqual(["/soc/alerts", "/vulnerabilities"]);
    expect(content.sections.find((section) => section.heading === "Note from your group")?.scored).toBe(false);
    expect(content.sections.find((section) => section.heading === "Essential Eight progress")?.table?.rows[0]).toEqual(["Update programs", 0, "First check"]);

    const copy = { ...content, image: null };
    const bare = {
      withImage: await toPdf("Board summary: River Clinic", content),
      noImage: await toPdf("Board summary: River Clinic", copy),
      slides: await toPdf("Board summary: River Clinic", content, "slides"),
    };
    expect(bare.withImage.length).toBeGreaterThan(bare.noImage.length);
    const portrait = await PDFDocument.load(bare.withImage);
    const deck = await PDFDocument.load(bare.slides);
    expect(portrait.getPage(0).getWidth()).toBeLessThan(portrait.getPage(0).getHeight());
    expect(deck.getPage(0).getWidth()).toBeGreaterThan(deck.getPage(0).getHeight());
    expect(pdfPlain(bare.withImage)).toContain("NEEDS ATTENTION NOW");
    expect(pdfPlain(bare.slides)).toContain("Essential Eight progress");
  });

  it("says the self-assessment has not been done when no check is stored", async () => {
    const tenant = await freshTenant();
    const content = await withScope(systemScope(tenant.id), (tx) => buildReport(tx, tenant.id, "board_summary", { end, span: "month" }));
    expect(content.light).toBe("steady");
    expect(content.image).toBeNull();
    expect(new Date(content.period.start).getTime()).toBe(end.getTime() - 30 * 86_400_000);
    const text = boardProse(content.sections);
    expect(readingAgeYears(text)).toBeLessThanOrEqual(12);
    expect(text).toContain("No check is on file");
    expect(text).toContain("The board should name who will answer the Essential Eight questions.");
    expect(content.sections.some((section) => section.heading === "Note from your group")).toBe(false);
  });

  it("emails the board contact once per period and skips a phone-only contact", async () => {
    const tenant = await freshTenant();
    await adminDb().insert(onboardingDrafts).values({
      ownerUserId: "board-owner",
      status: "complete",
      step: "plan",
      tenantId: tenant.id,
      contacts: {
        primary: person("email", "pat@example.invalid"),
        afterHours: person("phone", "0400000000"),
        board: person("email", "board@example.invalid"),
        summaryEmail: "summary@example.invalid",
      },
    });
    const now = new Date("2026-06-15T00:00:00.000Z");
    const first = await deliverBoardSummary(tenant.id, now);
    const second = await deliverBoardSummary(tenant.id, now);
    expect(first.sent).toBe(true);
    if (first.sent) expect(first.destination).toBe("board@example.invalid");
    expect(second).toEqual({ sent: false, reason: "already" });
    const rows = await adminDb().select().from(notificationDeliveries).where(eq(notificationDeliveries.tenantId, tenant.id));
    expect(rows.map((row) => row.destination)).toEqual(["board@example.invalid"]);
    expect(rows[0]?.status).toBe("sent");
    expect(rows[0]?.providerRef).toBe("fixture-email");
    const saved = await adminDb().select().from(reports).where(and(eq(reports.tenantId, tenant.id), eq(reports.kind, "board_summary")));
    expect(saved).toHaveLength(1);
    expect(readingAgeYears(boardProse(saved[0]!.content.sections))).toBeLessThanOrEqual(12);

    const phone = await freshTenant();
    await adminDb().insert(onboardingDrafts).values({
      ownerUserId: "board-owner",
      status: "complete",
      step: "plan",
      tenantId: phone.id,
      contacts: {
        primary: person("email", "pat@example.invalid"),
        afterHours: person("phone", "0400000000"),
        board: person("phone", "0400000001"),
        summaryEmail: "summary@example.invalid",
      },
    });
    expect(await deliverBoardSummary(phone.id, now)).toEqual({ sent: false, reason: "no-board-email" });
    const phoneMail = await adminDb().select().from(notificationDeliveries).where(eq(notificationDeliveries.tenantId, phone.id));
    expect(phoneMail).toHaveLength(0);
  });
});
