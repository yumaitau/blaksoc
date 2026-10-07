import { writeFileSync } from "node:fs";
import { openApiJson } from "@/lib/api/openapi";

// Regenerates the committed copy. tests/unit/openapi.test.ts fails when it is stale.
writeFileSync("docs/openapi.json", openApiJson());
process.stdout.write("wrote docs/openapi.json\n");
