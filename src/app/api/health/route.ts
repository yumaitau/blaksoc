import { sql } from "drizzle-orm";
import { db } from "@/db/client";
import { redis } from "@/lib/redis";

export const dynamic = "force-dynamic";

/** Readiness: Postgres and Redis reachable. Reveals no tenant data. Liveness is /api/health/live. */
export async function GET() {
  const checks: Record<string, boolean> = {};
  try {
    await db().execute(sql`select 1`);
    checks.postgres = true;
  } catch {
    checks.postgres = false;
  }
  try {
    checks.redis = (await redis().ping()) === "PONG";
  } catch {
    checks.redis = false;
  }
  const ok = Object.values(checks).every(Boolean);
  return Response.json({ ok, checks }, { status: ok ? 200 : 503 });
}
