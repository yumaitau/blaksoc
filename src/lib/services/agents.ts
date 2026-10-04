import { randomBytes, randomUUID } from "node:crypto";
import { and, eq, notInArray } from "drizzle-orm";
import { adminDb } from "@/db/client";
import { assets, assetSources, coverageTasks, enrolmentTokens, integrations, sites, tenants } from "@/db/schema";
import { type AccessContext } from "@/lib/auth/access";
import { audit } from "@/lib/audit";
import { agentGroup, DOWNLOAD_TTL_MS, isBandwidthProfile, openDownload, profileFor, renderInstaller, signDownload, type InstallerPlatform } from "@/lib/agents/download";
import { dailyUploadBytes, PROFILES, type BandwidthProfile } from "@/lib/agents/profile";
import { decryptSecret, encryptSecret, sha256 } from "@/lib/crypto";
import { env } from "@/lib/env";
import { actor, inTenant } from "./common";

const ENROL_MS = 14 * 86_400_000;
const INVENTORY = new Set(["m365", "entra", "google-workspace"]);
/** Endpoint agents that count as coverage. */
const AGENTS = new Set(["wazuh", "tawny"]);
const MANAGER = "wazuh.blaksoc.local";

export class AgentError extends Error {
  constructor(readonly code: "missing" | "revoked" | "expired" | "link") {
    super(code);
  }
}

function managerAddress(): string {
  return process.env.WAZUH_MANAGER?.trim() || MANAGER;
}

export async function issueEnrolment(ctx: AccessContext, tenantId: string, siteId: string) {
  return inTenant(ctx, "user:manage", tenantId, async (tx) => {
    const [site] = await tx.select().from(sites).where(and(eq(sites.id, siteId), eq(sites.tenantId, tenantId)));
    const [tenant] = await tx.select().from(tenants).where(eq(tenants.id, tenantId));
    if (!site || !tenant) throw new AgentError("missing");
    const id = randomUUID();
    const token = randomBytes(24).toString("base64url");
    const expiresAt = new Date(Date.now() + ENROL_MS);
    await tx.insert(enrolmentTokens).values({
      id,
      tenantId,
      siteId,
      tokenHash: sha256(token),
      tokenCiphertext: encryptSecret(token, `enrolment:${id}`),
      expiresAt,
    });
    await audit(tx, { ...actor(ctx), tenantId, action: "agent.enrol", targetType: "enrolment", targetId: id, detail: { siteId } });
    return { id, token, expiresAt, group: agentGroup(tenant.slug) };
  });
}

export async function revokeEnrolment(ctx: AccessContext, tenantId: string, enrolmentId: string) {
  return inTenant(ctx, "user:manage", tenantId, async (tx) => {
    const [row] = await tx.select().from(enrolmentTokens).where(and(eq(enrolmentTokens.id, enrolmentId), eq(enrolmentTokens.tenantId, tenantId)));
    if (!row) throw new AgentError("missing");
    await tx.update(enrolmentTokens).set({ revokedAt: new Date(), tokenCiphertext: null }).where(eq(enrolmentTokens.id, row.id));
    await audit(tx, { ...actor(ctx), tenantId, action: "agent.revoke", targetType: "enrolment", targetId: row.id });
  });
}

export async function setSiteLink(ctx: AccessContext, tenantId: string, siteId: string, link: string) {
  if (!isBandwidthProfile(link)) throw new AgentError("link");
  return inTenant(ctx, "user:manage", tenantId, async (tx) => {
    const [site] = await tx.select().from(sites).where(and(eq(sites.id, siteId), eq(sites.tenantId, tenantId)));
    if (!site) throw new AgentError("missing");
    await tx.update(sites).set({ bandwidthProfile: link }).where(eq(sites.id, site.id));
    await audit(tx, { ...actor(ctx), tenantId, action: "agent.profile", targetType: "site", targetId: site.id, detail: { link } });
  });
}

/** Registration check. A revoked or expired token does not join a group. */
export async function claimEnrolment(rawToken: string, now = Date.now()) {
  const [row] = await adminDb().select().from(enrolmentTokens).where(eq(enrolmentTokens.tokenHash, sha256(rawToken)));
  if (!row || row.revokedAt || row.expiresAt.getTime() <= now) return null;
  const [tenant] = await adminDb().select().from(tenants).where(eq(tenants.id, row.tenantId));
  if (!tenant) return null;
  return { tenantId: row.tenantId, siteId: row.siteId, group: agentGroup(tenant.slug) };
}

export function downloadLink(enrolmentId: string, platform: InstallerPlatform, now = Date.now()): string {
  return signDownload({ enrolmentId, platform, exp: now + DOWNLOAD_TTL_MS }, env().BLAKSOC_ENCRYPTION_KEY);
}

export async function serveInstaller(ctx: AccessContext, token: string, now = Date.now()) {
  const opened = openDownload(token, env().BLAKSOC_ENCRYPTION_KEY, now);
  if (!opened) throw new AgentError("expired");
  const tenantId = await enrolmentTenant(opened.enrolmentId);
  if (!tenantId) throw new AgentError("missing");
  return inTenant(ctx, "user:manage", tenantId, async (tx) => {
    const [row] = await tx.select().from(enrolmentTokens).where(eq(enrolmentTokens.id, opened.enrolmentId));
    if (!row || !row.tokenCiphertext) throw new AgentError(row ? "revoked" : "missing");
    if (row.revokedAt || row.expiresAt.getTime() <= now) throw new AgentError(row.revokedAt ? "revoked" : "expired");
    const [site] = row.siteId ? await tx.select().from(sites).where(eq(sites.id, row.siteId)) : [];
    const [tenant] = await tx.select().from(tenants).where(eq(tenants.id, row.tenantId));
    if (!tenant) throw new AgentError("missing");
    const secret = decryptSecret(row.tokenCiphertext, `enrolment:${row.id}`);
    return renderInstaller(opened.platform, {
      manager: managerAddress(),
      group: agentGroup(tenant.slug),
      token: secret,
      profile: profileFor(site?.bandwidthProfile),
    });
  });
}

async function enrolmentTenant(id: string): Promise<string | null> {
  const [row] = await adminDb().select({ tenantId: enrolmentTokens.tenantId }).from(enrolmentTokens).where(eq(enrolmentTokens.id, id));
  return row?.tenantId ?? null;
}

function hostKey(hostname: string | null, name: string): string {
  return (hostname || name).toLowerCase().split(".")[0] || name.toLowerCase();
}

export async function syncCoverage(ctx: AccessContext, tenantId: string) {
  return inTenant(ctx, "asset:read", tenantId, async (tx) => {
    const rows = await tx
      .select({ assetId: assets.id, hostname: assets.hostname, name: assets.name, provider: integrations.provider })
      .from(assets)
      .leftJoin(assetSources, eq(assetSources.assetId, assets.id))
      .leftJoin(integrations, eq(integrations.id, assetSources.integrationId))
      .where(and(eq(assets.tenantId, tenantId), eq(assets.kind, "endpoint")));
    const byAsset = new Map<string, { hostname: string; providers: Set<string> }>();
    for (const row of rows) {
      const current = byAsset.get(row.assetId) ?? { hostname: hostKey(row.hostname, row.name), providers: new Set<string>() };
      if (row.provider) current.providers.add(row.provider);
      byAsset.set(row.assetId, current);
    }
    const enrolled = new Set<string>();
    for (const item of byAsset.values()) {
      if ([...item.providers].some((provider) => AGENTS.has(provider))) enrolled.add(item.hostname);
    }
    const gaps: { assetId: string; hostname: string }[] = [];
    for (const [assetId, item] of byAsset) {
      const inventory = [...item.providers].some((provider) => INVENTORY.has(provider));
      if (inventory && !enrolled.has(item.hostname)) gaps.push({ assetId, hostname: item.hostname });
    }
    for (const gap of gaps) {
      await tx
        .insert(coverageTasks)
        .values({ tenantId, assetId: gap.assetId, hostname: gap.hostname, status: "open" })
        .onConflictDoUpdate({
          target: [coverageTasks.tenantId, coverageTasks.assetId],
          set: { hostname: gap.hostname, status: "open", resolvedAt: null },
        });
    }
    const openIds = gaps.map((gap) => gap.assetId);
    const doneWhere = openIds.length
      ? and(eq(coverageTasks.tenantId, tenantId), eq(coverageTasks.status, "open"), notInArray(coverageTasks.assetId, openIds))
      : and(eq(coverageTasks.tenantId, tenantId), eq(coverageTasks.status, "open"));
    await tx.update(coverageTasks).set({ status: "done", resolvedAt: new Date() }).where(doneWhere);
    return { open: gaps.length };
  });
}

export async function agentBoard(ctx: AccessContext, tenantId: string) {
  await syncCoverage(ctx, tenantId);
  const now = Date.now();
  return inTenant(ctx, "asset:read", tenantId, async (tx) => {
    const place = await tx.select().from(sites).where(eq(sites.tenantId, tenantId));
    const tokens = await tx
      .select({
        id: enrolmentTokens.id,
        siteId: enrolmentTokens.siteId,
        createdAt: enrolmentTokens.createdAt,
        expiresAt: enrolmentTokens.expiresAt,
        revokedAt: enrolmentTokens.revokedAt,
      })
      .from(enrolmentTokens)
      .where(eq(enrolmentTokens.tenantId, tenantId));
    const tasks = await tx.select().from(coverageTasks).where(and(eq(coverageTasks.tenantId, tenantId), eq(coverageTasks.status, "open")));
    return {
      sites: place,
      tokens,
      tasks,
      lowBytes: dailyUploadBytes(PROFILES.low),
      now,
    };
  });
}

export function linkLabel(link: BandwidthProfile): string {
  return link === "low" ? "Slow or satellite" : "Normal";
}
