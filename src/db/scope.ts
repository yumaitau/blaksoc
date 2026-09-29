import { sql } from "drizzle-orm";
import { db, type Tx } from "./client";

export type DbScope = {
  tenantIds: readonly string[];
  /** Direct role grants. Omitted means none. Do not copy tenantIds here. */
  grantIds?: readonly string[];
  platform: boolean;
};

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Runs fn in a transaction whose RLS scope is limited to the given tenants.
 * set_config(..., true) is transaction-local, so scope never leaks across pooled connections.
 */
export async function withScope<T>(scope: DbScope, fn: (tx: Tx) => Promise<T>): Promise<T> {
  const grantIds = scope.grantIds ?? [];
  for (const id of [...scope.tenantIds, ...grantIds]) {
    if (!UUID.test(id)) throw new Error("invalid tenant id in scope");
  }
  return db().transaction(async (tx) => {
    await tx.execute(
      sql`select set_config('app.tenant_ids', ${scope.tenantIds.join(",")}, true), set_config('app.grant_ids', ${grantIds.join(",")}, true), set_config('app.platform', ${scope.platform ? "on" : "off"}, true)`,
    );
    return fn(tx);
  });
}
