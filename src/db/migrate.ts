import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { migrate } from "drizzle-orm/postgres-js/migrator";
import postgres from "postgres";
import { drizzle } from "drizzle-orm/postgres-js";
import { env } from "@/lib/env";
import { urlPasswordMismatch } from "./url-password";

async function main() {
  // Fail before touching roles if web or worker could not log in with what we are about to set.
  const e = env();
  const problems = [
    urlPasswordMismatch("DATABASE_URL", e.DATABASE_URL, "blaksoc_app", e.BLAKSOC_APP_DB_PASSWORD),
    urlPasswordMismatch("DATABASE_SYSTEM_URL", e.DATABASE_SYSTEM_URL, "blaksoc_system", e.BLAKSOC_SYSTEM_DB_PASSWORD),
  ].filter(Boolean);
  if (problems.length) throw new Error(problems.join("\n"));

  const client = postgres(e.DATABASE_ADMIN_URL, { max: 1, onnotice: () => {} });
  await migrate(drizzle(client), { migrationsFolder: path.join(process.cwd(), "drizzle") });

  const dir = path.join(process.cwd(), "src/db/sql");
  for (const file of readdirSync(dir).filter((f) => f.endsWith(".sql")).sort()) {
    await client.unsafe(readFileSync(path.join(dir, file), "utf8"));
    console.log(`applied ${file}`);
  }
  // Passwords come from the environment, never from committed SQL.
  const quote = (value: string) => `'${value.replaceAll("'", "''")}'`;
  await client.unsafe(`ALTER ROLE blaksoc_app PASSWORD ${quote(env().BLAKSOC_APP_DB_PASSWORD)}`);
  await client.unsafe(`ALTER ROLE blaksoc_system PASSWORD ${quote(env().BLAKSOC_SYSTEM_DB_PASSWORD)}`);
  await client.end();
  console.log("migrations complete");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
