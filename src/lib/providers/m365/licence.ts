/**
 * Which M365 signals exist for a tenant's subscribed SKUs.
 * Part numbers follow Microsoft's SKU list (Business Basic, Business Premium, E3, E5, Entra ID P2).
 */

export type LicenceSignal = { id: string; label: string; skus: string[] };

export const LICENCE_SIGNALS: LicenceSignal[] = [
  { id: "signins", label: "Entra sign-in logs", skus: [] },
  { id: "directory_audit", label: "Directory audit logs", skus: [] },
  { id: "unified_audit", label: "Unified audit log (mailbox rules, forwarding, send)", skus: [] },
  { id: "mfa_methods", label: "MFA method changes", skus: [] },
  { id: "oauth_consent", label: "OAuth consent grants", skus: [] },
  {
    id: "risk_detections",
    label: "Identity Protection risky sign-ins",
    skus: ["AAD_PREMIUM_P2", "EMSPREMIUM", "SPE_E5", "ENTERPRISEPREMIUM", "IDENTITY_THREAT_PROTECTION"],
  },
  {
    id: "intune_devices",
    label: "Intune managed devices",
    skus: ["SPB", "SPE_E3", "SPE_E5", "ENTERPRISEPACK", "ENTERPRISEPREMIUM", "INTUNE_A"],
  },
];

export type CoverageGap = { id: string; label: string; available: boolean; reason: string };

export function coverageGaps(skus: string[]): CoverageGap[] {
  const have = new Set(skus.map((s) => s.toUpperCase()));
  return LICENCE_SIGNALS.map((sig) => {
    const available = sig.skus.length === 0 || sig.skus.some((s) => have.has(s.toUpperCase()));
    return {
      id: sig.id,
      label: sig.label,
      available,
      reason: available ? "included in subscribed licences" : `needs one of: ${sig.skus.join(", ")}`,
    };
  });
}
