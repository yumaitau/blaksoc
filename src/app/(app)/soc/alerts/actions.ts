"use server";
import { revalidatePath } from "next/cache";
import { z } from "zod";
import { withAccess } from "@/lib/actions";
import { ALERT_STATUSES, saveView, updateAlerts } from "@/lib/services/alerts";
import { addAlertsToIncident, createIncidentFromAlerts } from "@/lib/services/incidents";
import { RESPONSE_ACTIONS, type ResponseActionKey } from "@/lib/soar/actions";
import { requestFromUser } from "@/lib/soar/response";

const alertIds = z.array(z.guid()).min(1).max(500);
const status = z.enum(ALERT_STATUSES);

function refresh(ids: string[]) {
  revalidatePath("/soc/alerts");
  if (ids.length === 1) revalidatePath(`/soc/alerts/${ids[0]}`);
}

export async function setAlertStatus(ids: string[], next: string) {
  return withAccess(async (ctx) => {
    const n = await updateAlerts(ctx, alertIds.parse(ids), { status: status.parse(next) });
    refresh(ids);
    return n;
  });
}

export async function assignAlertsToMe(ids: string[]) {
  return withAccess(async (ctx) => {
    const n = await updateAlerts(ctx, alertIds.parse(ids), { assigneeId: ctx.principal.userId });
    refresh(ids);
    return n;
  });
}

/** `tenantIds` are the selected rows' tenants; the service re-checks every alert against the one tenant used. */
export async function createIncidentFromSelection(ids: string[], tenantIds: string[]) {
  return withAccess(async (ctx) => {
    const tenants = [...new Set(tenantIds)];
    if (tenants.length !== 1) throw new Error("An incident belongs to one customer. Select alerts from a single customer.");
    const incident = await createIncidentFromAlerts(ctx, { tenantId: z.guid().parse(tenants[0]), alertIds: alertIds.parse(ids) });
    refresh(ids);
    revalidatePath("/soc/incidents");
    return { id: incident.id };
  });
}

export async function addSelectionToIncident(incidentId: string, ids: string[]) {
  return withAccess(async (ctx) => {
    await addAlertsToIncident(ctx, z.guid().parse(incidentId), alertIds.parse(ids));
    refresh(ids);
    revalidatePath(`/soc/incidents/${incidentId}`);
    return { id: incidentId };
  });
}

const viewInput = z.object({
  name: z.string().trim().min(1).max(80),
  filters: z.record(z.string(), z.string().max(500)),
  shared: z.boolean(),
});

export async function saveAlertView(input: z.input<typeof viewInput>) {
  return withAccess(async (ctx) => {
    const v = viewInput.parse(input);
    await saveView(ctx, "/soc/alerts", v.name, v.filters, v.shared);
    revalidatePath("/soc/alerts");
  });
}

const responseInput = z.object({
  tenantId: z.guid(),
  alertId: z.guid(),
  action: z.enum(Object.keys(RESPONSE_ACTIONS) as [ResponseActionKey, ...ResponseActionKey[]]),
  reason: z.string().trim().min(5).max(2000),
  target: z.object({
    assetId: z.guid().optional(),
    ip: z.string().trim().max(100).optional(),
    identity: z.string().trim().max(200).optional(),
    observable: z.string().trim().max(500).optional(),
    process: z.string().trim().max(500).optional(),
  }),
});

export async function requestAlertResponse(input: z.input<typeof responseInput>) {
  return withAccess(async (ctx) => {
    const v = responseInput.parse(input);
    // Blank optional fields arrive as ""; drop them so the target describes only what was given.
    const target = Object.fromEntries(Object.entries(v.target).filter(([, x]) => x)) as typeof v.target;
    const res = await requestFromUser(ctx, { tenantId: v.tenantId, alertId: v.alertId, action: v.action, reason: v.reason, target });
    revalidatePath(`/soc/alerts/${v.alertId}`);
    revalidatePath("/soc/approvals");
    return { needsApproval: res.needsApproval };
  });
}
