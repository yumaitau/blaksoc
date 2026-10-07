/**
 * Service identities and /api/v1 against the seeded demo database. Calls the route handlers
 * directly, so the bearer path, services, RLS and audit run exactly as in production.
 */
import { and, desc, eq, inArray } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { GET as getAlertRoute } from "@/app/api/v1/alerts/[id]/route";
import { GET as listAlertsRoute } from "@/app/api/v1/alerts/route";
import { GET as listAssetsRoute } from "@/app/api/v1/assets/route";
import { POST as addNoteRoute } from "@/app/api/v1/incidents/[id]/notes/route";
import { GET as getIncidentRoute } from "@/app/api/v1/incidents/[id]/route";
import { GET as listIncidentsRoute } from "@/app/api/v1/incidents/route";
import { POST as tokenRoute } from "@/app/api/v1/oauth/token/route";
import { adminDb } from "@/db/client";
import { alerts, auditLog, incidentNotes, incidents, partnerConsents, roleAssignments, serviceIdentities, serviceTokens, tenants, user } from "@/db/schema";
import { DEFAULT_TENANT_SETTINGS } from "@/db/schema/platform";
import { hashSecret } from "@/lib/api/tokens";
import { can, resolveAccess, type AccessContext } from "@/lib/auth/access";
import { redis } from "@/lib/redis";
import { AccessDenied } from "@/lib/services/common";
import {
  createServiceIdentity, issueServiceToken, listServiceIdentities, revokeServiceIdentity, rotateServiceSecret, setServiceIdentityEnabled,
} from "@/lib/services/service-identities";

const BASE = "http://localhost/api/v1";

async function ctxFor(email: string): Promise<AccessContext> {
  const [u] = await adminDb().select().from(user).where(eq(user.email, email));
  if (!u) throw new Error(`seed user ${email} missing — run pnpm db:seed with DEMO_MODE=true`);
  return resolveAccess({ userId: u.id, name: u.name, email: u.email, isBreakGlass: u.isBreakGlass });
}

async function token(clientId: string, clientSecret: string) {
  const res = await tokenRoute(new Request(`${BASE}/oauth/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", authorization: `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString("base64")}` },
    body: "grant_type=client_credentials",
  }));
  return { status: res.status, body: (await res.json()) as { access_token?: string; scope?: string; expires_in?: number; error?: string } };
}

const bearer = (t: string, init: RequestInit = {}) => ({ ...init, headers: { ...(init.headers ?? {}), authorization: `Bearer ${t}` } });
const params = (id: string) => ({ params: Promise.resolve({ id }) });

let wattle: string, murray: string;
let admin: AccessContext, wattleAdmin: AccessContext;
let reader: { id: string; clientSecret: string };
let writer: { id: string; clientSecret: string };
let murrayIdentity: { id: string; clientSecret: string };
let readToken: string, writeToken: string;
const created: string[] = [];

beforeAll(async () => {
  const ts = await adminDb().select().from(tenants);
  wattle = ts.find((t) => t.slug === "wattle-health")!.id;
  murray = ts.find((t) => t.slug === "murray-water")!.id;
  admin = await ctxFor("breakglass@blaksoc.local");
  wattleAdmin = await ctxFor("wattle.admin@demo.blaksoc.local");
  reader = await createServiceIdentity(wattleAdmin, { name: "test reader", tenantId: wattle, scopes: ["alert:read", "incident:read", "asset:read"] });
  writer = await createServiceIdentity(admin, { name: "test writer", tenantId: wattle, scopes: ["incident:read", "incident:write"] });
  murrayIdentity = await createServiceIdentity(admin, { name: "test murray", tenantId: murray, scopes: ["alert:read"] });
  created.push(reader.id, writer.id, murrayIdentity.id);
  readToken = (await token(reader.id, reader.clientSecret)).body.access_token!;
  writeToken = (await token(writer.id, writer.clientSecret)).body.access_token!;
});

afterAll(async () => {
  // Audit rows stay (append-only); the identities and their tokens go.
  if (created.length) await adminDb().delete(serviceIdentities).where(inArray(serviceIdentities.id, created));
  await redis().quit();
});

describe("token endpoint", () => {
  it("issues a short-lived bearer token carrying the identity's scopes, stored only as a hash", async () => {
    const { status, body } = await token(reader.id, reader.clientSecret);
    expect(status).toBe(200);
    expect(body.expires_in).toBeLessThanOrEqual(900);
    expect(body.scope!.split(" ").sort()).toEqual(["alert:read", "asset:read", "incident:read"]);
    const [row] = await adminDb().select().from(serviceTokens).where(eq(serviceTokens.tokenHash, hashSecret(body.access_token!)));
    expect(row?.identityId).toBe(reader.id);
    const [identity] = await adminDb().select().from(serviceIdentities).where(eq(serviceIdentities.id, reader.id));
    expect(identity!.secretHash).toBe(hashSecret(reader.clientSecret));
  });

  it("rejects a wrong secret and audits the attempt", async () => {
    const { status, body } = await token(reader.id, writer.clientSecret);
    expect(status).toBe(401);
    expect(body.error).toBe("invalid_client");
    const [row] = await adminDb().select().from(auditLog).where(and(eq(auditLog.actorId, reader.id), eq(auditLog.action, "api.token_denied"))).orderBy(desc(auditLog.id)).limit(1);
    expect(row?.actorKind).toBe("service");
  });

  it("rejects requests without credentials or with another grant type", async () => {
    const res = await tokenRoute(new Request(`${BASE}/oauth/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: "grant_type=password" }));
    expect(res.status).toBe(400);
    expect((await tokenRoute(new Request(`${BASE}/oauth/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: "grant_type=client_credentials" }))).status).toBe(401);
  });
});

describe("tenant isolation through the API", () => {
  it("lists only the identity's tenant", async () => {
    const res = await listAlertsRoute(new Request(`${BASE}/alerts?limit=500`, bearer(readToken)));
    expect(res.status).toBe(200);
    const body = (await res.json()) as { data: { tenantId: string }[]; total: number };
    expect(body.data.length).toBeGreaterThan(0);
    expect(new Set(body.data.map((a) => a.tenantId))).toEqual(new Set([wattle]));

    const assets = (await (await listAssetsRoute(new Request(`${BASE}/assets`, bearer(readToken)))).json()) as { data: { tenantId: string }[] };
    expect(assets.data.length).toBeGreaterThan(0);
    expect(assets.data.every((a) => a.tenantId === wattle)).toBe(true);

    const incs = (await (await listIncidentsRoute(new Request(`${BASE}/incidents`, bearer(readToken)))).json()) as { data: { tenantId: string }[] };
    expect(incs.data.every((i) => i.tenantId === wattle)).toBe(true);
  });

  it("refuses another tenant by filter and hides it by id", async () => {
    expect((await listAlertsRoute(new Request(`${BASE}/alerts?tenantId=${murray}`, bearer(readToken)))).status).toBe(403);
    const [other] = await adminDb().select({ id: alerts.id }).from(alerts).where(eq(alerts.tenantId, murray)).limit(1);
    expect((await getAlertRoute(new Request(`${BASE}/alerts/${other!.id}`, bearer(readToken)), params(other!.id))).status).toBe(404);
    const [own] = await adminDb().select({ id: alerts.id }).from(alerts).where(eq(alerts.tenantId, wattle)).limit(1);
    const res = await getAlertRoute(new Request(`${BASE}/alerts/${own!.id}`, bearer(readToken)), params(own!.id));
    expect(res.status).toBe(200);
    expect(((await res.json()) as { tenantId: string }).tenantId).toBe(wattle);
  });

  it("cannot write to another tenant's incident", async () => {
    const [other] = await adminDb().select({ id: incidents.id }).from(incidents).where(eq(incidents.tenantId, murray)).limit(1);
    expect(other).toBeDefined();
    expect((await getIncidentRoute(new Request(`${BASE}/incidents/${other!.id}`, bearer(writeToken)), params(other!.id))).status).toBe(404);
    const res = await addNoteRoute(new Request(`${BASE}/incidents/${other!.id}/notes`, bearer(writeToken, { method: "POST", body: JSON.stringify({ body: "cross-tenant", visibility: "customer" }) })), params(other!.id));
    expect(res.status).toBe(403);
    expect(await adminDb().select().from(incidentNotes).where(and(eq(incidentNotes.incidentId, other!.id), eq(incidentNotes.body, "cross-tenant")))).toHaveLength(0);
  });

  it("enforces scopes: a read-only identity cannot add notes", async () => {
    const [own] = await adminDb().select({ id: incidents.id }).from(incidents).where(eq(incidents.tenantId, wattle)).limit(1);
    const res = await addNoteRoute(new Request(`${BASE}/incidents/${own!.id}/notes`, bearer(readToken, { method: "POST", body: JSON.stringify({ body: "no scope" }) })), params(own!.id));
    expect(res.status).toBe(403);
    expect(((await res.json()) as { error: string }).error).toBe("insufficient_scope");
  });
});

describe("audit", () => {
  it("writes the note as the service identity and audits the call and the change", async () => {
    const [own] = await adminDb().select({ id: incidents.id }).from(incidents).where(eq(incidents.tenantId, wattle)).limit(1);
    const res = await addNoteRoute(new Request(`${BASE}/incidents/${own!.id}/notes`, bearer(writeToken, { method: "POST", body: JSON.stringify({ body: "from the API", visibility: "customer" }) })), params(own!.id));
    expect(res.status).toBe(201);
    const note = (await res.json()) as { id: string; authorName: string | null };
    expect(note.authorName).toBeNull();
    const [stored] = await adminDb().select().from(incidentNotes).where(eq(incidentNotes.id, note.id));
    expect(stored!.authorId).toBeNull();

    const rows = await adminDb().select().from(auditLog).where(eq(auditLog.actorId, writer.id)).orderBy(desc(auditLog.id)).limit(5);
    const change = rows.find((r) => r.action === "incident.note");
    const call = rows.find((r) => r.action === "api.request" && r.targetId === "POST /incidents/{id}/notes" && (r.detail as { status: number }).status === 201);
    expect(change).toMatchObject({ actorKind: "service", tenantId: wattle, targetId: own!.id });
    expect(call).toMatchObject({ actorKind: "service", tenantId: wattle });
  });

  it("audits read calls, including refused ones", async () => {
    const rows = await adminDb().select().from(auditLog).where(and(eq(auditLog.actorId, reader.id), eq(auditLog.action, "api.request")));
    const statuses = rows.map((r) => `${r.targetId} ${(r.detail as { status: number }).status}`);
    expect(statuses).toEqual(expect.arrayContaining(["GET /alerts 200", "GET /alerts 403", "GET /alerts/{id} 404", "GET /assets 200"]));
    expect(rows.every((r) => r.actorKind === "service" && r.tenantId === wattle)).toBe(true);
  });
});

describe("scope ceiling and management", () => {
  it("cannot grant scopes the creator lacks, or bind to a tenant or platform it does not manage", async () => {
    await expect(createServiceIdentity(wattleAdmin, { name: "x", tenantId: wattle, scopes: ["incident:write"] })).rejects.toBeInstanceOf(AccessDenied);
    await expect(createServiceIdentity(wattleAdmin, { name: "x", tenantId: murray, scopes: ["alert:read"] })).rejects.toBeInstanceOf(AccessDenied);
    await expect(createServiceIdentity(wattleAdmin, { name: "x", tenantId: null, scopes: ["alert:read"] })).rejects.toBeInstanceOf(AccessDenied);
    await expect(createServiceIdentity(admin, { name: "x", tenantId: null, scopes: ["portal:read"] })).rejects.toBeInstanceOf(AccessDenied);
  });

  it("a tenant admin sees and manages only its own tenant's identities and cannot rotate one above its grants", async () => {
    const ids = (await listServiceIdentities(wattleAdmin)).map((r) => r.id);
    expect(ids).toEqual(expect.arrayContaining([reader.id, writer.id]));
    expect(ids).not.toContain(murrayIdentity.id);
    await expect(rotateServiceSecret(wattleAdmin, murrayIdentity.id)).rejects.toBeInstanceOf(AccessDenied);
    // The writer holds incident:write, which a customer admin does not: rotating would hand it over.
    await expect(rotateServiceSecret(wattleAdmin, writer.id)).rejects.toBeInstanceOf(AccessDenied);
  });
});

describe("revocation and expiry", () => {
  it("rejects an expired token", async () => {
    const old = await issueServiceToken({ clientId: reader.id, clientSecret: reader.clientSecret, now: new Date(Date.now() - 16 * 60_000) });
    expect((await listAlertsRoute(new Request(`${BASE}/alerts`, bearer(old!.accessToken)))).status).toBe(401);
  });

  it("rotation stops the old secret and its tokens", async () => {
    const before = (await token(murrayIdentity.id, murrayIdentity.clientSecret)).body.access_token!;
    const { clientSecret } = await rotateServiceSecret(admin, murrayIdentity.id);
    expect((await listAlertsRoute(new Request(`${BASE}/alerts`, bearer(before)))).status).toBe(401);
    expect((await token(murrayIdentity.id, murrayIdentity.clientSecret)).status).toBe(401);
    const fresh = (await token(murrayIdentity.id, clientSecret)).body.access_token!;
    expect((await listAlertsRoute(new Request(`${BASE}/alerts`, bearer(fresh)))).status).toBe(200);
    murrayIdentity = { id: murrayIdentity.id, clientSecret };
  });

  it("disabling and revoking stop outstanding tokens and new ones", async () => {
    const t = (await token(reader.id, reader.clientSecret)).body.access_token!;
    await setServiceIdentityEnabled(wattleAdmin, reader.id, false);
    expect((await listAlertsRoute(new Request(`${BASE}/alerts`, bearer(t)))).status).toBe(401);
    expect((await token(reader.id, reader.clientSecret)).status).toBe(401);
    await setServiceIdentityEnabled(wattleAdmin, reader.id, true);
    const again = (await token(reader.id, reader.clientSecret)).body.access_token!;
    expect((await listAlertsRoute(new Request(`${BASE}/alerts`, bearer(again)))).status).toBe(200);

    await revokeServiceIdentity(wattleAdmin, reader.id);
    expect((await listAlertsRoute(new Request(`${BASE}/alerts`, bearer(again)))).status).toBe(401);
    expect((await token(reader.id, reader.clientSecret)).status).toBe(401);
    await expect(setServiceIdentityEnabled(wattleAdmin, reader.id, true)).rejects.toThrow(/revoked/);
  });
});

describe("partner-held access", () => {
  const stamp = `svc${Date.now().toString(36)}`;
  const userId = `${stamp}-partner-admin`;
  let partner: string, customer: string;

  beforeAll(async () => {
    const [p] = await adminDb().insert(tenants).values({ name: "Svc Partner", slug: `${stamp}-p`, kind: "partner", sectors: ["SMB"], deploymentMode: "shared", settings: DEFAULT_TENANT_SETTINGS }).returning();
    const [c] = await adminDb().insert(tenants).values({ name: "Svc Customer", slug: `${stamp}-c`, kind: "customer", parentId: p!.id, sectors: ["SMB"], deploymentMode: "shared", settings: DEFAULT_TENANT_SETTINGS }).returning();
    partner = p!.id;
    customer = c!.id;
    await adminDb().insert(partnerConsents).values({ customerTenantId: customer, partnerTenantId: partner, consentedBy: "test", statement: "test consent" });
    await adminDb().insert(user).values({ id: userId, name: userId, email: `${userId}@example.invalid`, emailVerified: true });
    await adminDb().insert(roleAssignments).values({ userId, roleKey: "partner_admin", tenantId: partner });
  });

  afterAll(async () => {
    await adminDb().delete(serviceIdentities).where(inArray(serviceIdentities.tenantId, [partner, customer]));
    await adminDb().delete(tenants).where(eq(tenants.id, customer));
    await adminDb().delete(tenants).where(eq(tenants.id, partner));
    await adminDb().delete(user).where(eq(user.id, userId));
  });

  it("cannot mint a customer credential that would outlive the customer's consent", async () => {
    const ctx = await ctxFor(`${userId}@example.invalid`);
    // The partner does manage the customer while consent stands...
    expect(can(ctx, "user:manage", customer)).toBe(true);
    // ...but a client secret bound to the customer would keep working after consent is revoked.
    await expect(createServiceIdentity(ctx, { name: "partner bot", tenantId: customer, scopes: ["alert:read"] })).rejects.toBeInstanceOf(AccessDenied);
    const own = await createServiceIdentity(ctx, { name: "partner bot", tenantId: partner, scopes: ["alert:read"] });
    expect(own.clientSecret).toBeTruthy();
  });
});

describe("token issue racing a rotation", () => {
  it("does not issue a token for a secret rotated after it was checked", async () => {
    const id = await createServiceIdentity(admin, { name: "race", tenantId: wattle, scopes: ["alert:read"] });
    created.push(id.id);
    // Simulate the rotate committing between the secret check and the insert: change the stored
    // hash under the issuer by rotating while the old secret is presented.
    const [before] = await adminDb().select().from(serviceIdentities).where(eq(serviceIdentities.id, id.id));
    const rotated = rotateServiceSecret(admin, id.id);
    const issued = issueServiceToken({ clientId: id.id, clientSecret: id.clientSecret });
    const [, token_] = await Promise.all([rotated, issued]);
    const [after] = await adminDb().select().from(serviceIdentities).where(eq(serviceIdentities.id, id.id));
    expect(after!.secretHash).not.toBe(before!.secretHash);
    // Whichever order they ran in, no token from the old secret survives the rotation.
    const live = await adminDb().select().from(serviceTokens).where(eq(serviceTokens.identityId, id.id));
    if (token_) expect(live.some((t) => t.tokenHash === hashSecret(token_.accessToken))).toBe(false);
    expect(live).toHaveLength(0);
  });
});
