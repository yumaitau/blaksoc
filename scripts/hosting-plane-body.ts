import { writeFileSync } from "node:fs";
import { openctiIndicatorRequest, searchBulkBody } from "@/lib/hosting/plane-load";

const [mode, region, countRaw, dest, index] = process.argv.slice(2);
const count = Number(countRaw);
if (!region || !Number.isInteger(count) || !dest) {
  throw new Error("usage: hosting-plane-body.ts search|opencti <region> <count> <file> [index]");
}

if (mode === "search") {
  if (!index) throw new Error("search mode needs an index name");
  writeFileSync(dest, searchBulkBody(region, count, index));
} else if (mode === "opencti") {
  const lines: string[] = [];
  for (let n = 0; n < count; n++) lines.push(openctiIndicatorRequest(region, n, "2026-09-29T00:00:00.000Z"));
  writeFileSync(dest, `${lines.join("\n")}\n`);
} else {
  throw new Error("mode must be search or opencti");
}
