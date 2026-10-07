import { openApiDocument } from "@/lib/api/openapi";

/** Public: the contract, not data. Built from the route schemas; docs/openapi.json is the committed copy. */
export function GET() {
  return Response.json(openApiDocument(), { headers: { "cache-control": "public, max-age=300" } });
}
