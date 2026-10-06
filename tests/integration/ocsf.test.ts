/**
 * Ingest writes validated OCSF records beside each alert. Fresh tenant only.
 */
import { randomUUID } from "node:crypto";
import { eq } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { adminDb } from "@/db/client";
import { alerts, tenants } from "@/db/schema";
import { DEFAULT_TENANT_SETTINGS } from "@/db/schema/platform";
import { NORMALIZATION_VERSION } from "@/lib/ocsf/schema";
import { validateOcsf } from "@/lib/ocsf/validate";
import { ingestAlert } from "@/lib/pipeline/ingest";
import { normaliseSyslog } from "@/lib/syslog/parse";
import { SYSLOG_LINES } from "../fixtures/syslog";

let tenantId = "";

beforeAll(async () => {
  const [t] = await adminDb().insert(tenants).values({ name: "OCSF Proof", slug: `ocsf-${randomUUID().slice(0, 8)}`, kind: "customer", sectors: ["SMB"], deploymentMode: "shared", settings: DEFAULT_TENANT_SETTINGS }).returning();
  tenantId = t!.id;
});

afterAll(async () => {
  if (tenantId) await adminDb().delete(tenants).where(eq(tenants.id, tenantId));
});

describe("OCSF on ingest", () => {
  it("stores a Detection Finding and the firewall's Network Activity for a syslog alert", async () => {
    const line = SYSLOG_LINES.fortinet;
    const alert = normaliseSyslog({ id: randomUUID(), line, byteLen: line.length, ingestedAt: new Date() }, tenantId)!;
    const res = await ingestAlert({ tenantId, integrationId: null, source: "syslog", alert, intel: null });
    const [row] = await adminDb().select().from(alerts).where(eq(alerts.id, res.alertId));
    expect(row!.normalizationVersion).toBe(NORMALIZATION_VERSION);
    expect(validateOcsf(row!.ocsf!)).toEqual({ ok: true });
    expect(validateOcsf(row!.ocsfSourceEvent!)).toEqual({ ok: true });
    expect(row!.ocsf).toMatchObject({ class_uid: 2004, risk_score: res.riskScore, metadata: { tenant_uid: tenantId, original_event_uid: alert.externalId, log_name: "syslog", logged_time: row!.ingestedAt.getTime() } });
    expect(row!.ocsfSourceEvent).toMatchObject({ class_uid: 4001, src_endpoint: { ip: "203.0.113.10" }, disposition_id: 2 });
    // Raw stays where it was: the OCSF record references it, it does not copy it.
    expect(row!.raw).toMatchObject({ line });
    expect(JSON.stringify(row!.ocsf)).not.toContain(line);
  });
});
