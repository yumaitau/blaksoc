import { backfillAllTenants, backfillGraph } from "@/lib/graph/backfill";

/** Builds the entity graph from stored assets and alerts. Idempotent. Usage: graph-backfill [tenantId] */
async function main() {
  const tenantId = process.argv[2];
  if (tenantId) console.log(await backfillGraph(tenantId));
  else await backfillAllTenants();
  process.exit(0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
