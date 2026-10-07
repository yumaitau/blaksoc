import { z } from "zod";
import { OCSF_CLASSES, SEVERITY_ID, type OcsfEvent } from "./schema";

/**
 * Structural checks for the OCSF events blakSOC writes: required attributes per class (OCSF 1.9.0,
 * no profiles), the "at least one of" constraints on the objects used, and the derived ids
 * (type_uid = class_uid * 100 + activity_id, category matches class). Unknown attributes pass:
 * this guards what blakSOC promises, not the whole OCSF schema.
 */

const atLeastOne = (keys: string[]) => (o: Record<string, unknown>) => keys.some((k) => o[k] !== undefined && o[k] !== null && o[k] !== "");

const product = z.looseObject({ name: z.string().optional(), uid: z.string().optional(), vendor_name: z.string().optional() }).refine(atLeastOne(["name", "uid"]), "product needs name or uid");
const metadata = z.looseObject({ version: z.string().min(1), product });
const observable = z.looseObject({ type_id: z.number().int(), name: z.string().optional(), value: z.string().optional() });
const user = z.looseObject({}).refine(atLeastOne(["account", "name", "uid"]), "user needs account, name or uid");
const endpoint = z.looseObject({}).refine(atLeastOne(["ip", "uid", "name", "hostname", "svc_name", "instance_uid", "interface_uid", "interface_name", "domain"]), "endpoint needs an identifier");
const device = z.looseObject({ type_id: z.number().int() }).refine(atLeastOne(["ip", "uid", "name", "hostname", "instance_uid", "interface_uid", "interface_name"]), "device needs an identifier");
const named = z.looseObject({}).refine(atLeastOne(["name", "uid"]), "needs name or uid");
const attack = z.looseObject({ technique: named.optional(), sub_technique: named.optional(), tactic: named.optional() }).refine(atLeastOne(["tactic", "technique", "sub_technique"]), "attack needs tactic, technique or sub_technique");
const analytic = z.looseObject({ type_id: z.number().int() }).refine(atLeastOne(["name", "uid"]), "analytic needs name or uid");
const findingInfo = z.looseObject({ uid: z.string().min(1), analytic: analytic.optional(), attacks: z.array(attack).optional() });
const vulnerability = z.looseObject({
  cve: z.looseObject({ uid: z.string().min(1), cvss: z.array(z.looseObject({ version: z.string(), base_score: z.number() })).optional() }).optional(),
  affected_packages: z.array(z.looseObject({ name: z.string(), version: z.string() })).optional(),
});

const severityIds = new Set<number>(Object.values(SEVERITY_ID));

const base = z.looseObject({
  class_uid: z.number().int(),
  category_uid: z.number().int(),
  activity_id: z.number().int(),
  type_uid: z.number().int(),
  severity_id: z.number().int().refine((n) => severityIds.has(n), "unknown severity_id"),
  time: z.number().int().positive(),
  metadata,
  observables: z.array(observable).optional(),
});

const byClass: Record<number, z.ZodType> = {
  [OCSF_CLASSES.base_event.class_uid]: base.extend({ device: device.optional(), user: user.optional(), src_endpoint: endpoint.optional(), dst_endpoint: endpoint.optional() }),
  [OCSF_CLASSES.detection_finding.class_uid]: base.extend({ finding_info: findingInfo, evidences: z.array(z.looseObject({ device: device.optional(), user: user.optional(), src_endpoint: endpoint.optional(), dst_endpoint: endpoint.optional() })).optional() }),
  [OCSF_CLASSES.vulnerability_finding.class_uid]: base.extend({ finding_info: findingInfo, vulnerabilities: z.array(vulnerability).min(1) }),
  [OCSF_CLASSES.authentication.class_uid]: base.extend({ user, src_endpoint: endpoint.optional() }),
  [OCSF_CLASSES.network_activity.class_uid]: base.extend({ src_endpoint: endpoint.optional(), dst_endpoint: endpoint.optional(), device: device.optional(), connection_info: z.looseObject({ direction_id: z.number().int() }).optional() }),
};

export type OcsfValidation = { ok: true } | { ok: false; errors: string[] };

export function validateOcsf(event: OcsfEvent | Record<string, unknown>): OcsfValidation {
  const e = event as Record<string, unknown>;
  const schema = byClass[e.class_uid as number];
  if (!schema) return { ok: false, errors: [`unsupported class_uid ${String(e.class_uid)}`] };
  const errors: string[] = [];
  const parsed = schema.safeParse(e);
  if (!parsed.success) errors.push(...parsed.error.issues.map((i) => `${i.path.join(".") || "(event)"}: ${i.message}`));
  const cls = Object.values(OCSF_CLASSES).find((c) => c.class_uid === e.class_uid)!;
  if (e.category_uid !== cls.category_uid) errors.push(`category_uid must be ${cls.category_uid} for class ${cls.class_uid}`);
  if (typeof e.activity_id === "number" && e.type_uid !== cls.class_uid * 100 + e.activity_id) errors.push(`type_uid must be class_uid * 100 + activity_id (${cls.class_uid * 100 + e.activity_id})`);
  return errors.length ? { ok: false, errors } : { ok: true };
}
