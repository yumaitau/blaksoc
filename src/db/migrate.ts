import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { migrate } from "drizzle-orm/postgres-js/migrator";
import postgres from "postgres";
import { drizzle } from "drizzle-orm/postgres-js";
import { env } from "@/lib/env";

async function main() {
  const client = postgres(env().DATABASE_ADMIN_URL, { max: 1, onnotice: () => {} });
  await migrate(drizzle(client), { migrationsFolder: path.join(process.cwd(), "drizzle") });

  const dir = path.join(process.cwd(), "src/db/sql");
  for (const file of readdirSync(dir).filter((f) => f.endsWith(".sql")).sort()) {
    await client.unsafe(readFileSync(path.join(dir, file), "utf8"));
    console.log(`applied ${file}`);
  }
  // Password comes from the environment, never from committed SQL.
  await client.unsafe(`ALTER ROLE blaksoc_app PASSWORD '${env().BLAKSOC_APP_DB_PASSWORD.replaceAll("'", "''")}'`);
  await client.end();
  console.log("migrations complete");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
