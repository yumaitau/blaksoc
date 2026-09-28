import { drizzle, type PostgresJsDatabase } from "drizzle-orm/postgres-js";
import postgres from "postgres";
import { env } from "@/lib/env";
import * as schema from "./schema";

export type Database = PostgresJsDatabase<typeof schema>;
export type Tx = Parameters<Parameters<Database["transaction"]>[0]>[0];
export type DbOrTx = Database | Tx;

const globalForDb = globalThis as unknown as { __blaksocDb?: Database; __blaksocAdminDb?: Database };

/** RLS-enforced connection (role blaksoc_app). Use via withScope() for tenant data. */
export function db(): Database {
  if (!globalForDb.__blaksocDb) {
    globalForDb.__blaksocDb = drizzle(postgres(env().DATABASE_URL, { max: 20, prepare: false }), { schema });
  }
  return globalForDb.__blaksocDb;
}

/** Owner connection. Migrations, seed and verified system jobs only — bypasses RLS. */
export function adminDb(): Database {
  if (!globalForDb.__blaksocAdminDb) {
    globalForDb.__blaksocAdminDb = drizzle(postgres(env().DATABASE_ADMIN_URL, { max: 4, prepare: false }), { schema });
  }
  return globalForDb.__blaksocAdminDb;
}

export { schema };
