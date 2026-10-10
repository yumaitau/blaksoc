import "server-only";
import { createHash } from "node:crypto";
import { env } from "@/lib/env";
import { collectRadar, type RadarSnapshot, unconfiguredRadar } from "./snapshot";

const TTL_MS = 60_000;

let cached: { fingerprint: string; at: number; snap: RadarSnapshot } | null = null;

function fingerprint(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

/** Shared for a minute across dashboard loads. A total failure is not cached. The token is not stored. */
export async function loadRadar(): Promise<RadarSnapshot> {
  const token = env().CLOUDFLARE_RADAR_TOKEN?.trim() ?? "";
  if (!token) return unconfiguredRadar();
  const fp = fingerprint(token);
  const now = Date.now();
  if (cached && cached.fingerprint === fp && now - cached.at < TTL_MS) return cached.snap;
  const snap = await collectRadar(token, (url, init) => fetch(url, init));
  const any = snap.l7.error == null || snap.l3.error == null || snap.bots.error == null || snap.outages.error == null;
  if (any) cached = { fingerprint: fp, at: now, snap };
  return snap;
}
