import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { env } from "@/lib/env";
import { graphRequest, graphValues, liveGraphTransport, type GraphTransport } from "@/lib/providers/m365/graph";
import type { M365Consent } from "./types";

const STATE_TTL_MS = 30 * 60_000;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export type ConsentState = { draftId: string; userId: string; exp: number; nonce: string };

export class ConsentError extends Error {
  constructor(readonly reason: string) {
    super(reason);
    this.name = "ConsentError";
  }
}

export function consentConfigured(): boolean {
  const e = env();
  return !!(e.M365_CONNECTOR_CLIENT_ID && e.M365_CONNECTOR_CLIENT_SECRET);
}

export function connectorCredentials(): { clientId: string; clientSecret: string } {
  const e = env();
  if (!e.M365_CONNECTOR_CLIENT_ID || !e.M365_CONNECTOR_CLIENT_SECRET) throw new ConsentError("connector app not configured");
  return { clientId: e.M365_CONNECTOR_CLIENT_ID, clientSecret: e.M365_CONNECTOR_CLIENT_SECRET };
}

function mac(payload: string): string {
  return createHmac("sha256", `m365-consent:${env().BETTER_AUTH_SECRET}`).update(payload).digest("base64url");
}

/** State binds the redirect to one draft, one analyst, and a short window. */
export function signState(draftId: string, userId: string, now = Date.now()): string {
  const payload = Buffer.from(JSON.stringify({ draftId, userId, exp: now + STATE_TTL_MS, nonce: randomBytes(8).toString("hex") } satisfies ConsentState)).toString("base64url");
  return `${payload}.${mac(payload)}`;
}

export function verifyState(state: string, userId: string, now = Date.now()): ConsentState {
  const [payload, sig] = state.split(".");
  if (!payload || !sig) throw new ConsentError("malformed state");
  const want = Buffer.from(mac(payload));
  const got = Buffer.from(sig);
  if (want.length !== got.length || !timingSafeEqual(want, got)) throw new ConsentError("bad state signature");
  const parsed = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as ConsentState;
  if (parsed.userId !== userId) throw new ConsentError("state belongs to another user");
  if (parsed.exp < now) throw new ConsentError("state expired");
  return parsed;
}

export function adminConsentUrl(state: string): string {
  const url = new URL("https://login.microsoftonline.com/organizations/v2.0/adminconsent");
  url.searchParams.set("client_id", connectorCredentials().clientId);
  url.searchParams.set("scope", "https://graph.microsoft.com/.default");
  url.searchParams.set("redirect_uri", `${env().APP_URL}/onboarding/m365/callback`);
  url.searchParams.set("state", state);
  return url.toString();
}

/** Reads the redirect query. Microsoft sends `tenant` and `admin_consent=True`, or `error`. */
export function parseCallback(query: URLSearchParams): { azureTenantId: string; state: string } {
  const state = query.get("state") ?? "";
  const error = query.get("error");
  if (error) throw new ConsentError(`${error}: ${(query.get("error_description") ?? "").slice(0, 200)}`);
  const tenant = query.get("tenant") ?? "";
  if (query.get("admin_consent")?.toLowerCase() !== "true") throw new ConsentError("admin consent not granted");
  if (!UUID.test(tenant)) throw new ConsentError("tenant id missing");
  return { azureTenantId: tenant.toLowerCase(), state };
}

/**
 * Proves consent works: a client-credentials token for the customer tenant reads the organisation and licences.
 * New consent can take a short while to apply, so token failures are retried.
 */
export async function verifyConsent(
  azureTenantId: string,
  opts: { transport?: GraphTransport; sleep?: (ms: number) => Promise<void>; attempts?: number; now?: Date } = {},
): Promise<M365Consent> {
  const transport = opts.transport ?? liveGraphTransport({ azureTenantId, ...connectorCredentials() });
  const sleep = opts.sleep ?? ((ms: number) => new Promise((r) => setTimeout(r, ms)));
  const attempts = opts.attempts ?? 3;
  let last: unknown;
  for (let i = 0; i < attempts; i++) {
    try {
      const org = await graphRequest(transport, "GET", "/organization", { query: { $select: "id,displayName" }, sleep });
      if (org.status !== 200) throw new ConsentError(`organization read returned ${org.status}`);
      const record = graphValues(org.body)[0];
      if (!record || String(record.id).toLowerCase() !== azureTenantId) throw new ConsentError("organization id does not match the consenting tenant");
      const skus = await graphRequest(transport, "GET", "/subscribedSkus", { query: { $select: "skuPartNumber" }, sleep });
      const parts = skus.status === 200 ? graphValues(skus.body).map((s) => String(s.skuPartNumber ?? "")).filter(Boolean) : [];
      return {
        azureTenantId,
        organisation: typeof record.displayName === "string" ? record.displayName : null,
        grantedAt: (opts.now ?? new Date()).toISOString(),
        skus: parts,
      };
    } catch (err) {
      last = err;
      if (err instanceof ConsentError && !/returned 40[13]/.test(err.message)) throw err;
      if (i < attempts - 1) await sleep(5_000);
    }
  }
  throw last instanceof ConsentError ? last : new ConsentError(last instanceof Error ? last.message : "consent check failed");
}
