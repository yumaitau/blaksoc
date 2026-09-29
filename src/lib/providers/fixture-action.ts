import type { ResponseActionResult } from "@/lib/providers/types";

/** In-memory fixture state. Key is provider, scope, family, target. Isolate/release share a family, and so do block/unblock. */
const held = new Set<string>();

export function clearFixtureActions(): void {
  held.clear();
}

/** Live mode must fail before any network call. */
export function refuseLive(mode: "fixture" | "live", name: string): void {
  if (mode === "live") throw new Error(`live ${name} is not called from this build`);
}

function slot(kind: string, scope: string, family: string, target: string): string {
  return `${kind}:${scope}:${family}:${target}`;
}

export function holdAction(kind: string, scope: string, family: string, target: string, label: string): ResponseActionResult {
  const key = slot(kind, scope, family, target);
  if (held.has(key)) return { ok: true, message: `already ${label}`, providerRef: key };
  held.add(key);
  return { ok: true, message: `${label} ${target}`, providerRef: key };
}

export function releaseAction(kind: string, scope: string, family: string, target: string): ResponseActionResult {
  const key = slot(kind, scope, family, target);
  if (!held.has(key)) return { ok: true, message: "already released", providerRef: key };
  held.delete(key);
  return { ok: true, message: `released ${target}`, providerRef: key };
}
