import { readFileSync } from "node:fs";
import { assertSearchNodeInAustralia, firstSearchNodeAttributes } from "@/lib/hosting/profile";

const file = process.argv[2];
if (!file) throw new Error("usage: hosting-region-check.ts <nodes.json>");
const region = assertSearchNodeInAustralia(firstSearchNodeAttributes(JSON.parse(readFileSync(file, "utf8"))));
process.stdout.write(`${region}\n`);
