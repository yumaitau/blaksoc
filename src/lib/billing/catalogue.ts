export const TIERS = ["essentials", "standard", "plus"] as const;
export type Tier = (typeof TIERS)[number];

export const CAPABILITIES = [
  "m365_monitoring",
  "google_monitoring",
  "bec_pack",
  "email_posture",
  "attack_surface",
  "credential_exposure",
  "monthly_report",
  "wazuh_endpoint",
  "vuln_prioritisation",
  "essential_eight",
  "business_hours_response",
  "velociraptor_dfir",
  "oncall_24x7",
  "tabletop",
  "board_reporting",
] as const;
export type Capability = (typeof CAPABILITIES)[number];

const TIER_RANK: Record<Tier, number> = { essentials: 0, standard: 1, plus: 2 };

/** Lowest tier that includes the capability. Higher tiers include everything below them. */
const MIN_TIER: Record<Capability, Tier> = {
  m365_monitoring: "essentials",
  google_monitoring: "essentials",
  bec_pack: "essentials",
  email_posture: "essentials",
  attack_surface: "essentials",
  credential_exposure: "essentials",
  monthly_report: "essentials",
  wazuh_endpoint: "standard",
  vuln_prioritisation: "standard",
  essential_eight: "standard",
  business_hours_response: "standard",
  velociraptor_dfir: "plus",
  oncall_24x7: "plus",
  tabletop: "plus",
  board_reporting: "plus",
};

/**
 * Providers whose collection is plan-gated. Unmapped providers (webhook, slack, opencti, ai)
 * are not paused by a downgrade.
 */
export const PROVIDER_CAPABILITY: Record<string, Capability> = {
  entra: "m365_monitoring",
  google: "google_monitoring",
  wazuh: "wazuh_endpoint",
  demo: "wazuh_endpoint",
  velociraptor: "velociraptor_dfir",
};

export const TIER_LABEL: Record<Tier, string> = { essentials: "Essentials", standard: "Standard", plus: "Plus" };

/** Indicative monthly price ex GST, in cents. Not signed off by the advisory group. */
export const LIST_PRICE_CENTS: Record<Tier, number> = { essentials: 45_000, standard: 90_000, plus: 180_000 };

/** Applied when nonprofit is set and no explicit discount_bps was given. */
export const NONPROFIT_DISCOUNT_BPS = 2000;

export function asTier(value: string): Tier {
  return (TIERS as readonly string[]).includes(value) ? (value as Tier) : "essentials";
}

export function tierAllows(tier: Tier, capability: Capability): boolean {
  return TIER_RANK[tier] >= TIER_RANK[MIN_TIER[capability]];
}

export class EntitlementError extends Error {
  readonly capability: Capability;
  readonly tier: Tier;
  constructor(capability: Capability, tier: Tier) {
    super(`${capability} is not included in the ${tier} plan`);
    this.name = "EntitlementError";
    this.capability = capability;
    this.tier = tier;
  }
}

/** Server-side gate. Callers with a loaded tier use this; requireCapability loads the row first. */
export function assertEntitled(tier: Tier, capability: Capability): void {
  if (!tierAllows(tier, capability)) throw new EntitlementError(capability, tier);
}

export function collectionAllowed(tier: Tier, provider: string): boolean {
  const capability = PROVIDER_CAPABILITY[provider];
  if (!capability) return true;
  return tierAllows(tier, capability);
}

/** Tenant links a worker may still collect for. Shared integrations stay enabled; skipped tenants are dropped here. */
export function collectingTenantIds(provider: string, links: readonly { tenantId: string }[], tierOf: (tenantId: string) => Tier): string[] {
  return links.filter((l) => collectionAllowed(tierOf(l.tenantId), provider)).map((l) => l.tenantId);
}
