"use server";
import { revalidatePath } from "next/cache";
import { z } from "zod";
import { withAccess } from "@/lib/actions";
import { SEVERITIES } from "@/lib/services/alerts";
import { ARTIFACT_SETS } from "@/lib/dfir/sets";
import { custodyExport, requestCollection, startHunt } from "@/lib/services/dfir";
import { addAnalystTimelineEvent, addEvidence, addNote, addTask, INCIDENT_STATUSES, toggleTask, updateIncident } from "@/lib/services/incidents";

const id = z.guid();
const longText = z.string().trim().max(20_000).transform((v) => v || null);

function refresh(incidentId: string) {
  revalidatePath(`/soc/incidents/${incidentId}`);
  revalidatePath("/soc/incidents");
}

const casePatch = z.object({
  status: z.enum(INCIDENT_STATUSES),
  severity: z.enum(SEVERITIES),
  ownerId: z.string().min(1).nullable(),
  description: longText,
  containment: longText,
  remediation: longText,
  rootCause: longText,
  lessonsLearned: longText,
}).partial();

/** Callers send only changed fields, so e.g. editing notes on a closed case doesn't need incident:close. */
export async function saveIncidentCase(incidentId: string, input: z.input<typeof casePatch>) {
  return withAccess(async (ctx) => {
    await updateIncident(ctx, id.parse(incidentId), casePatch.parse(input));
    refresh(incidentId);
  });
}

export async function addIncidentNote(incidentId: string, body: string, visibility: "internal" | "customer") {
  return withAccess(async (ctx) => {
    await addNote(ctx, id.parse(incidentId), z.string().trim().min(1).max(20_000).parse(body), z.enum(["internal", "customer"]).parse(visibility));
    refresh(incidentId);
  });
}

const timelineEvent = z.object({
  occurredAt: z.iso.datetime({ offset: true }),
  title: z.string().trim().min(1).max(300),
  detail: z.string().trim().max(5000).optional(),
});

export async function addIncidentTimelineEvent(incidentId: string, input: z.input<typeof timelineEvent>) {
  return withAccess(async (ctx) => {
    const e = timelineEvent.parse(input);
    await addAnalystTimelineEvent(ctx, id.parse(incidentId), { occurredAt: new Date(e.occurredAt), title: e.title, detail: e.detail || undefined });
    refresh(incidentId);
  });
}

export async function addIncidentTask(incidentId: string, title: string) {
  return withAccess(async (ctx) => {
    await addTask(ctx, id.parse(incidentId), z.string().trim().min(1).max(300).parse(title));
    refresh(incidentId);
  });
}

export async function setIncidentTaskDone(incidentId: string, taskId: string, done: boolean) {
  return withAccess(async (ctx) => {
    await toggleTask(ctx, id.parse(taskId), done);
    refresh(incidentId);
  });
}

const evidenceInput = z.object({
  name: z.string().trim().min(1).max(300),
  kind: z.string().trim().min(1).max(60),
  sha256: z.string().trim().toLowerCase().regex(/^([0-9a-f]{64})?$/, "sha256 must be 64 hex characters").optional(),
  storageUri: z.string().trim().max(2000).optional(),
  description: z.string().trim().max(5000).optional(),
});

export async function addIncidentEvidence(incidentId: string, input: z.input<typeof evidenceInput>) {
  return withAccess(async (ctx) => {
    const e = evidenceInput.parse(input);
    await addEvidence(ctx, id.parse(incidentId), {
      name: e.name,
      kind: e.kind,
      sha256: e.sha256 || undefined,
      storageUri: e.storageUri || undefined,
      description: e.description || undefined,
    });
    refresh(incidentId);
  });
}

const collectionInput = z.object({
  assetIds: z.array(z.guid()).min(1).max(50),
  artifactSets: z.array(z.enum(ARTIFACT_SETS)).min(1),
  lowBandwidth: z.boolean(),
});

export async function requestIncidentCollection(incidentId: string, input: z.input<typeof collectionInput>) {
  return withAccess(async (ctx) => {
    await requestCollection(ctx, id.parse(incidentId), collectionInput.parse(input));
    refresh(incidentId);
    revalidatePath("/soc/approvals");
  });
}

export async function startIncidentHunt(incidentId: string, ioc: string) {
  return withAccess(async (ctx) => {
    const hunt = await startHunt(ctx, id.parse(incidentId), z.string().trim().min(1).max(200).parse(ioc));
    refresh(incidentId);
    return { matches: hunt.matchedAssetIds.length };
  });
}

export async function exportIncidentCustody(incidentId: string) {
  return withAccess(async (ctx) => ({ text: await custodyExport(ctx, id.parse(incidentId)) }));
}
