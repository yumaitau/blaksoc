import { and, eq, isNull, or } from "drizzle-orm";
import type { DbOrTx } from "@/db/client";
import { dataGovernance, integrations, MOST_PROTECTIVE } from "@/db/schema";
import { checkGovernedRegion } from "@/lib/governance/policy";
import { decryptSecret } from "@/lib/crypto";
import type { IntelProvider } from "@/lib/intel/types";
import type { SecurityEventProvider } from "@/lib/providers/types";
import { connectorDef, type ConnectorInstance } from "./registry";
import type { Notifier } from "./notify";

export type IntegrationRow = typeof integrations.$inferSelect;

/** AAD binds a ciphertext to its integration row so secrets cannot be swapped between rows. */
export const secretAad = (integrationId: string) => `integration:${integrationId}`;

export function instantiate(row: IntegrationRow): ConnectorInstance {
  const def = connectorDef(row.provider);
  if (!def?.create) throw new Error(`connector ${row.provider} is not available`);
  const secrets = row.secretCiphertext ? (JSON.parse(decryptSecret(row.secretCiphertext, secretAad(row.id))) as Record<string, string>) : {};
  return def.create(def.config.parse(row.config), def.secrets.parse(secrets));
}

export function eventProvider(row: IntegrationRow): SecurityEventProvider {
  const inst = instantiate(row);
  if (inst.kind !== "events") throw new Error(`${row.provider} is not an event provider`);
  return inst.provider;
}

/**
 * The OpenCTI (or fixture) instance serving a tenant: tenant-owned first, then platform-owned.
 * Under the tenant's residency lock, a connector declaring a region outside Australia is not used.
 */
export async function intelProviderFor(tx: DbOrTx, tenantId: string | null): Promise<{ row: IntegrationRow; provider: IntelProvider } | null> {
  const rows = await tx
    .select()
    .from(integrations)
    .where(and(eq(integrations.category, "threat_intel"), eq(integrations.enabled, true), tenantId ? or(eq(integrations.tenantId, tenantId), isNull(integrations.tenantId)) : isNull(integrations.tenantId)));
  const ordered = rows.sort((a, b) => (a.tenantId ? -1 : 0) - (b.tenantId ? -1 : 0));
  let allowed = ordered;
  if (tenantId) {
    const [gov] = await tx.select({ profile: dataGovernance.profile }).from(dataGovernance).where(eq(dataGovernance.tenantId, tenantId));
    const profile = gov?.profile ?? MOST_PROTECTIVE;
    // A rejected tenant connector falls through to an allowed platform connector.
    allowed = ordered.filter((r) => checkGovernedRegion(profile, (r.config as Record<string, unknown>).region).allowed);
  }
  const row = allowed[0];
  if (!row) return null;
  const inst = instantiate(row);
  return inst.kind === "intel" ? { row, provider: inst.provider } : null;
}

export function notifier(row: IntegrationRow): Notifier | null {
  const inst = instantiate(row);
  return inst.kind === "notify" ? inst.provider : null;
}
