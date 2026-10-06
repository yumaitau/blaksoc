import type { AiCapability, GovernanceProfile, SharingPolicy } from "@/db/schema";
import type { AIProvider } from "@/lib/ai/types";
import { AU_ARCHIVE_REGIONS } from "@/lib/syslog/retain";

export type GovernanceDecision = { allowed: true; reason: string } | { allowed: false; reason: string };

const TLP_ORDER = ["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"] as const;

/** AI use for one capability. Runs in addition to the tenant AI settings and the platform residency flag. */
export function checkGovernedAi(profile: GovernanceProfile, capability: AiCapability, provider: Pick<AIProvider, "id" | "residency">): GovernanceDecision {
  if (!profile.ai[capability]) return { allowed: false, reason: `data stewards have not turned on AI for ${capability.replace("_", " ")}` };
  if (profile.residencyLock && provider.residency.country !== "AU") {
    return { allowed: false, reason: `residency lock: ${provider.id} processes in ${provider.residency.region}, outside Australia` };
  }
  return { allowed: true, reason: "allowed by data governance profile" };
}

export function isAuRegion(region: string): boolean {
  return (AU_ARCHIVE_REGIONS as readonly string[]).includes(region);
}

/** An intel connector with a declared region must be in Australia while the lock is on. Local fixtures declare none. */
export function checkGovernedRegion(profile: GovernanceProfile, region: unknown): GovernanceDecision {
  if (!profile.residencyLock || region === undefined) return { allowed: true, reason: "no region constraint" };
  if (typeof region === "string" && isAuRegion(region)) return { allowed: true, reason: `${region} is in Australia` };
  return { allowed: false, reason: `residency lock: region ${String(region)} is outside Australia` };
}

export type SightingDecision =
  | { allowed: true; attribution: "anonymised" | "named"; maxTlp: SharingPolicy["maxTlp"] }
  | { allowed: false; reason: string };

/**
 * A sighting needs both the tenant setting and steward consent. The narrower of the two wins:
 * named attribution needs named consent, and the TLP ceiling is the lower one.
 */
export function checkGovernedSighting(profile: GovernanceProfile, sharing: SharingPolicy): SightingDecision {
  if (!sharing.createSightings || sharing.attribution === "none") return { allowed: false, reason: "tenant sharing setting does not permit sightings" };
  const consent = profile.sightings;
  if (!consent) return { allowed: false, reason: "data stewards have not consented to sightings" };
  const attribution = sharing.attribution === "named" && consent.attribution === "named" ? "named" : "anonymised";
  const maxTlp = TLP_ORDER[Math.min(TLP_ORDER.indexOf(sharing.maxTlp), TLP_ORDER.indexOf(consent.maxTlp))]!;
  return { allowed: true, attribution, maxTlp };
}

/** Two-person rule once a tenant has two or more stewards. */
export function approvalsRequired(stewardCount: number): number {
  return stewardCount >= 2 ? 2 : 1;
}

/** Plain-language statement for the portal. Each sentence is true of the enforced profile. */
export function describeProfile(profile: GovernanceProfile): string[] {
  const out: string[] = [];
  out.push(profile.residencyLock
    ? "Your data stays in Australia. That covers storage, backups, log archives, AI, and threat intelligence lookups."
    : "The Australia-only lock is off. Storage and log archives still stay in Australia. AI and intelligence services may be overseas.");
  out.push(profile.sightings
    ? `Your data stewards agreed to share ${profile.sightings.attribution === "named" ? "named" : "anonymous"} threat sightings, marked no higher than ${profile.sightings.maxTlp}.`
    : "Nobody outside Yuma IT's SOC team can see your data. Nothing is shared as a threat sighting.");
  const on = (Object.keys(profile.ai) as AiCapability[]).filter((k) => profile.ai[k]);
  out.push(on.length
    ? `AI is on only for: ${on.map((k) => (k === "assistant" ? "the analyst assistant" : "alert summaries")).join(" and ")}.`
    : "AI is off for your data.");
  out.push("blakSOC does not use your data to train AI.");
  return out;
}

/** Field-level differences, for audit and steward notices. */
export function diffProfile(before: GovernanceProfile, after: GovernanceProfile): string[] {
  const out: string[] = [];
  if (before.residencyLock !== after.residencyLock) out.push(`Australia-only lock ${after.residencyLock ? "on" : "off"}`);
  const scope = (p: GovernanceProfile) => (p.sightings ? `${p.sightings.attribution} up to ${p.sightings.maxTlp}` : "none");
  if (scope(before) !== scope(after)) out.push(`sightings ${scope(before)} to ${scope(after)}`);
  for (const k of Object.keys(after.ai) as AiCapability[]) {
    if (before.ai[k] !== after.ai[k]) out.push(`AI ${k.replace("_", " ")} ${after.ai[k] ? "on" : "off"}`);
  }
  return out;
}
