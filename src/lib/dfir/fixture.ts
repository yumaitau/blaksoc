import { sha256 } from "@/lib/crypto";
import type { ProviderHealth } from "@/lib/providers/types";
import { type ArtifactSet } from "./sets";

export type FixtureAsset = { id: string; hostname: string | null; name: string; ips?: string[] };

/** Live gRPC is out of this build. Callers pass fixture config or this throws before any network. */
export function assertFixtureMode(mode: unknown): void {
  if (mode === "live") throw new Error("live Velociraptor is not called from this build");
}

/** Health for the Velociraptor connector. Fixture mode is healthy and says so; live is not built. */
export function velociraptorHealth(mode: unknown): ProviderHealth {
  if (mode === "live") return { ok: false, latencyMs: 0, detail: { mode: "live" }, error: "live Velociraptor is not called from this build" };
  return { ok: true, latencyMs: 0, detail: { mode: "fixture", note: "collections return fixture artefacts" } };
}

/** Deterministic artefact body. The SHA-256 of this string is what custody records. */
export function artifactBody(set: ArtifactSet, asset: FixtureAsset): string {
  return ["velociraptor fixture", `artifact=${set}`, `client=${asset.hostname ?? asset.name}`, `asset=${asset.id}`].join("\n");
}

export function artifactDigest(set: ArtifactSet, asset: FixtureAsset): string {
  return sha256(artifactBody(set, asset));
}

export function storageUri(collectionId: string, assetId: string, set: ArtifactSet): string {
  return `fixture://velociraptor/${collectionId}/${assetId}/${set}`;
}

/** Case-insensitive match against hostname, name, and addresses. The indicator value is supplied by the caller. */
export function huntMatch(asset: FixtureAsset, ioc: string): boolean {
  const needle = ioc.trim().toLowerCase();
  if (!needle) return false;
  const hay = [asset.hostname, asset.name, ...(asset.ips ?? [])].filter(Boolean).join(" ").toLowerCase();
  return hay.includes(needle);
}

export function renderCustody(
  ref: number,
  rows: { name: string; kind: string; sha256: string | null; collectedBy: string | null; collectedAt: Date; storageUri: string | null }[],
): string {
  const lines = ["Chain of custody", `Incident ${ref}`];
  for (const row of rows) {
    lines.push(`${row.name} | ${row.kind} | sha256 ${row.sha256 ?? "missing"} | by ${row.collectedBy ?? "unknown"} | at ${row.collectedAt.toISOString()} | ${row.storageUri ?? ""}`);
  }
  if (!rows.length) lines.push("No evidence recorded.");
  return lines.join("\n");
}
