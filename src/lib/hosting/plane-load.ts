import { assertAuRegion } from "@/lib/syslog/retain";

/** Same tenant counts as the file-archive k6 run. Each tenant is 20 documents. */
export const PLANE_LOAD_TENANTS = [10, 50, 200] as const;
export const PLANE_LOAD_PER_TENANT = 20;

/** OpenSearch bulk body. `assertAuRegion` runs before any byte is built. */
export function searchBulkBody(region: string, count: number, index: string): string {
  assertAuRegion(region);
  if (!Number.isInteger(count) || count < 1) throw new Error("load count");
  if (!index || /[\n\r]/.test(index)) throw new Error("load index");
  const lines: string[] = [];
  for (let n = 0; n < count; n++) {
    lines.push(JSON.stringify({ index: { _index: index, _id: String(n) } }));
    lines.push(JSON.stringify({ region, n, body: "a".repeat(180) }));
  }
  return `${lines.join("\n")}\n`;
}

/**
 * One OpenCTI GraphQL `indicatorAdd` body. The region is part of the stored name.
 * `assertAuRegion` runs before the JSON is built.
 */
export function openctiIndicatorRequest(region: string, n: number, validFrom: string): string {
  assertAuRegion(region);
  if (!Number.isInteger(n) || n < 0) throw new Error("load count");
  if (!validFrom || /[\n\r]/.test(validFrom)) throw new Error("load time");
  return JSON.stringify({
    query: "mutation Add($input: IndicatorAddInput!) { indicatorAdd(input: $input) { id } }",
    variables: {
      input: {
        name: `blaksoc-load-${region}-${n}`,
        pattern: `[domain-name:value = 'load-${n}.invalid']`,
        pattern_type: "stix",
        x_opencti_main_observable_type: "Domain-Name",
        valid_from: validFrom,
      },
    },
  });
}
