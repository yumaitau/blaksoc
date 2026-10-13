import { STRATEGIES, type StrategyId } from "@/lib/essential-eight/requirements";
import { ISM_CONTROLS } from "./ism-catalogue";

/**
 * Compliance references carried on alerts. Detectors name Essential Eight strategies in their own
 * vocabulary (Wedgetail: `restrict_admin_privileges`, sometimes `:ML2` suffixed); blakSOC stores its own
 * strategy ids so alerts line up with customer assessments.
 */
const E8_ALIASES: Record<string, StrategyId> = {
  application_control: "application_control",
  patch_applications: "patch_applications",
  office_macros: "office_macros",
  restrict_microsoft_office_macros: "office_macros",
  configure_microsoft_office_macro_settings: "office_macros",
  user_application_hardening: "user_app_hardening",
  user_app_hardening: "user_app_hardening",
  restrict_admin_privileges: "restrict_admin",
  restrict_administrative_privileges: "restrict_admin",
  restrict_admin: "restrict_admin",
  patch_operating_systems: "patch_os",
  patch_os: "patch_os",
  multi_factor_authentication: "mfa",
  mfa: "mfa",
  regular_backups: "regular_backups",
};

export function e8Strategy(ref: string): StrategyId | null {
  const key = ref.trim().toLowerCase().replace(/:ml[0-3]$/, "").replace(/[\s-]+/g, "_");
  return E8_ALIASES[key] ?? null;
}

export function ismControl(ref: string): string | null {
  const match = /^ISM-?(\d{4})$/i.exec(ref.trim());
  return match ? `ISM-${match[1]}` : null;
}

/** Unknown references are dropped rather than stored as free text. */
export function e8Strategies(refs: readonly unknown[] | undefined): StrategyId[] {
  return [...new Set((refs ?? []).flatMap((r) => (typeof r === "string" ? [e8Strategy(r)] : [])).filter((s): s is StrategyId => !!s))];
}

export function ismControls(refs: readonly unknown[] | undefined): string[] {
  return [...new Set((refs ?? []).flatMap((r) => (typeof r === "string" ? [ismControl(r)] : [])).filter((s): s is string => !!s))].sort();
}

const LABELS = new Map(STRATEGIES.map((s) => [s.id, s.label] as const));
export const e8Label = (id: string): string => LABELS.get(id as StrategyId) ?? id;
export const isE8Strategy = (id: string): id is StrategyId => LABELS.has(id as StrategyId);

/** ASD statement text, when the control is in the bundled snapshot. */
export function ismText(id: string): string | null {
  return ISM_CONTROLS[id]?.text ?? null;
}
