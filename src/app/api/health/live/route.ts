export const dynamic = "force-dynamic";

/** Liveness: the process is serving requests. Dependencies are checked by /api/health (readiness). */
export function GET() {
  return Response.json({ ok: true });
}
