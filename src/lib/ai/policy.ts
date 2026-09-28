import type { AiPolicy } from "@/db/schema";
import type { AIProvider } from "./types";

export type PolicyDecision = { allowed: true; reason: string } | { allowed: false; reason: string };

/**
 * Gate every model call. Tenant data reaches a model only if the tenant enabled AI, the
 * provider is on the tenant's allow-list (when set), and — under AU residency — the
 * provider declares Australian processing.
 */
export function checkAiPolicy(policy: AiPolicy, provider: AIProvider, residency: "AU" | "ANY"): PolicyDecision {
  if (!policy.enabled) return { allowed: false, reason: "AI assistance is disabled for this tenant" };
  if (policy.allowedProviders.length && !policy.allowedProviders.includes(provider.id)) {
    return { allowed: false, reason: `provider ${provider.id} is not approved for this tenant` };
  }
  if (residency === "AU" && provider.residency.country !== "AU") {
    return { allowed: false, reason: `platform requires Australian data residency; ${provider.id} processes in ${provider.residency.region}` };
  }
  return { allowed: true, reason: `${provider.id} (${provider.residency.region}${provider.residency.selfHosted ? ", self-hosted" : ""})` };
}

const EMAIL = /\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b/g;
const AU_PHONE = /(?<!\d)(?:\+?61|0)[2-478](?:[ -]?\d){8}(?!\d)/g;
const TFN = /\b\d{3} ?\d{3} ?\d{3}\b/g;
const MEDICARE = /\b\d{4} ?\d{5} ?\d\b/g;

/** Mask personal data in free text before it leaves the platform. Keeps email domains (useful for triage). */
export function redactPii(text: string): string {
  return text
    .replace(EMAIL, (_m, domain: string) => `[email]@${domain}`)
    .replace(MEDICARE, "[medicare]")
    .replace(AU_PHONE, "[phone]")
    .replace(TFN, "[tfn]");
}
