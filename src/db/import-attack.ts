import { adminDb } from "./client";
import { attackTechniques } from "./schema";

/** Imports the full MITRE ATT&CK Enterprise matrix from MITRE's STIX 2.1 bundle. */
const URL = process.env.ATTACK_BUNDLE_URL ?? "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json";

type AttackPattern = {
  type: string;
  name: string;
  description?: string;
  revoked?: boolean;
  x_mitre_deprecated?: boolean;
  kill_chain_phases?: { kill_chain_name: string; phase_name: string }[];
  external_references?: { source_name: string; external_id?: string }[];
};

async function main() {
  console.log(`fetching ${URL}`);
  const bundle = (await (await fetch(URL, { signal: AbortSignal.timeout(120_000) })).json()) as { objects: AttackPattern[] };
  let n = 0;
  for (const o of bundle.objects) {
    if (o.type !== "attack-pattern" || o.revoked || o.x_mitre_deprecated) continue;
    const id = o.external_references?.find((r) => r.source_name === "mitre-attack")?.external_id;
    if (!id) continue;
    const tactics = (o.kill_chain_phases ?? []).filter((k) => k.kill_chain_name === "mitre-attack").map((k) => k.phase_name);
    await adminDb()
      .insert(attackTechniques)
      .values({ id, name: o.name, tactics, parentId: id.includes(".") ? id.split(".")[0]! : null, description: o.description?.slice(0, 4000) ?? null })
      .onConflictDoUpdate({ target: attackTechniques.id, set: { name: o.name, tactics, description: o.description?.slice(0, 4000) ?? null } });
    n++;
  }
  console.log(`imported ${n} techniques`);
  process.exit(0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
