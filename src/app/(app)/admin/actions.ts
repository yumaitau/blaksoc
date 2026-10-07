"use server";
import { revalidatePath } from "next/cache";
import { headers } from "next/headers";
import type { TenantSettings } from "@/db/schema";
import { withAccess } from "@/lib/actions";
import {
  assignRole,
  createCustomRole,
  createTenant,
  registerSsoProvider,
  revokeRole,
  setUserDisabled,
  updateTenantSettings,
  verifyAudit,
  type SsoRegistration,
} from "@/lib/services/admin";
import { createServiceIdentity, revokeServiceIdentity, rotateServiceSecret, setServiceIdentityEnabled } from "@/lib/services/service-identities";

const done = <T,>(v: T) => {
  revalidatePath("/admin");
  return v;
};

export async function createTenantAction(input: { name: string; slug: string; sectors: string[]; deploymentMode: "shared" | "dedicated" }) {
  return withAccess(async (ctx) => {
    if (!input.name.trim()) throw new Error("Name is required.");
    const t = await createTenant(ctx, { name: input.name.trim(), slug: input.slug.trim(), sectors: input.sectors, deploymentMode: input.deploymentMode === "dedicated" ? "dedicated" : "shared" });
    return done({ id: t.id });
  });
}

const TLP = ["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"] as const;
const minutes = (n: number) => {
  if (!Number.isInteger(n) || n < 1 || n > 60 * 24 * 30) throw new Error("SLA minutes must be whole numbers between 1 and 43,200.");
  return n;
};

export async function updateTenantSettingsAction(tenantId: string, s: TenantSettings, includeAutoContainment: boolean) {
  return withAccess(async (ctx) => {
    if (!TLP.includes(s.sharing.maxTlp)) throw new Error("Unknown TLP level.");
    if (!["anonymised", "named", "none"].includes(s.sharing.attribution)) throw new Error("Unknown attribution mode.");
    const patch: Partial<TenantSettings> = {
      sharing: { createSightings: !!s.sharing.createSightings, attribution: s.sharing.attribution, maxTlp: s.sharing.maxTlp },
      ai: { enabled: !!s.ai.enabled, allowedProviders: s.ai.allowedProviders.map((p) => p.trim()).filter(Boolean), allowRawEvents: !!s.ai.allowRawEvents, redactPii: !!s.ai.redactPii },
      slaMinutes: { critical: minutes(s.slaMinutes.critical), high: minutes(s.slaMinutes.high), medium: minutes(s.slaMinutes.medium), low: minutes(s.slaMinutes.low) },
      // Omitted unless the caller may change it; the service rejects it otherwise.
      ...(includeAutoContainment ? { autoContainment: !!s.autoContainment } : {}),
    };
    await updateTenantSettings(ctx, tenantId, patch);
    return done(undefined);
  });
}

export async function assignRoleAction(input: { userId: string; roleKey: string; tenantId: string | null }) {
  return withAccess(async (ctx) => done(await assignRole(ctx, input)));
}

export async function revokeRoleAction(assignmentId: string) {
  return withAccess(async (ctx) => done(await revokeRole(ctx, assignmentId)));
}

export async function setUserDisabledAction(userId: string, disabled: boolean) {
  return withAccess(async (ctx) => done(await setUserDisabled(ctx, userId, disabled)));
}

export async function createRoleAction(input: { key: string; name: string; scope: "platform" | "tenant"; permissions: string[]; description?: string }) {
  return withAccess(async (ctx) => {
    if (!/^[a-z0-9_]{2,40}$/.test(input.key)) throw new Error("Key must be 2–40 lowercase letters, digits or underscores.");
    if (!input.name.trim()) throw new Error("Name is required.");
    if (!input.permissions.length) throw new Error("Choose at least one permission.");
    await createCustomRole(ctx, { ...input, name: input.name.trim(), scope: input.scope === "platform" ? "platform" : "tenant", description: input.description?.trim() || undefined });
    return done(undefined);
  });
}

export async function registerSsoAction(input: SsoRegistration) {
  return withAccess(async (ctx) => {
    const required = input.protocol === "oidc" ? [input.issuer, input.clientId, input.clientSecret, input.domain, input.providerId] : [input.issuer, input.entryPoint, input.cert, input.domain, input.providerId];
    if (required.some((v) => !v?.trim())) throw new Error("Fill in every field.");
    await registerSsoProvider(ctx, input, await headers());
    return done(undefined);
  });
}

export async function verifyAuditAction() {
  return withAccess(async (ctx) => verifyAudit(ctx));
}

export async function createServiceIdentityAction(input: { name: string; tenantId: string | null; scopes: string[] }) {
  return withAccess(async (ctx) => done(await createServiceIdentity(ctx, input)));
}

export async function rotateServiceSecretAction(id: string) {
  return withAccess(async (ctx) => done(await rotateServiceSecret(ctx, id)));
}

export async function setServiceIdentityEnabledAction(id: string, enabled: boolean) {
  return withAccess(async (ctx) => done(await setServiceIdentityEnabled(ctx, id, enabled)));
}

export async function revokeServiceIdentityAction(id: string) {
  return withAccess(async (ctx) => done(await revokeServiceIdentity(ctx, id)));
}
