import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { OPERATIONS, openApiDocument, openApiJson } from "@/lib/api/openapi";
import { PERMISSIONS } from "@/lib/auth/permissions";

const V1 = path.join(process.cwd(), "src/app/api/v1");

/** Route files under /api/v1 as OpenAPI paths, e.g. incidents/[id]/notes → /incidents/{id}/notes. */
function routePaths(dir = V1): string[] {
  return readdirSync(dir).flatMap((name) => {
    const full = path.join(dir, name);
    if (statSync(full).isDirectory()) return routePaths(full);
    if (name !== "route.ts") return [];
    return [`/${path.relative(V1, dir).replace(/\[(\w+)\]/g, "{$1}")}`];
  });
}

describe("OpenAPI document", () => {
  it("matches the committed docs/openapi.json (run pnpm openapi)", () => {
    expect(readFileSync(path.join(process.cwd(), "docs/openapi.json"), "utf8")).toBe(openApiJson());
  });

  it("documents every /api/v1 route except the document itself", () => {
    const documented = new Set(OPERATIONS.map((o) => o.path));
    expect(routePaths().filter((p) => p !== "/openapi.json").sort()).toEqual([...documented].sort());
  });

  it("is OpenAPI 3.1 with scopes drawn from the permission list", () => {
    const doc = openApiDocument();
    expect(doc.openapi).toBe("3.1.0");
    const scopes = Object.keys(doc.components.securitySchemes.oauth2.flows.clientCredentials.scopes);
    expect(scopes).toEqual([...PERMISSIONS]);
    for (const op of OPERATIONS) if (op.scope) expect(PERMISSIONS).toContain(op.scope);
  });

  it("resolves every component reference", () => {
    const doc = openApiDocument();
    const refs = [...JSON.stringify(doc).matchAll(/"\$ref":"#\/components\/schemas\/(\w+)"/g)].map((m) => m[1]!);
    expect(refs.length).toBeGreaterThan(0);
    for (const r of refs) expect(doc.components.schemas).toHaveProperty(r);
  });
});
