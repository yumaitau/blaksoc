"use server";
import { revalidatePath } from "next/cache";
import { withAccess } from "@/lib/actions";
import { REPORT_KINDS, type ReportKind } from "@/lib/reports/generate";
import { generateReport } from "@/lib/services/reports";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export async function generateReportAction(input: { tenantId: string; kind: string; incidentId?: string }) {
  return withAccess(async (ctx) => {
    if (!(input.kind in REPORT_KINDS)) throw new Error("Unknown report kind.");
    const incidentId = input.incidentId?.trim() || undefined;
    if (input.kind === "incident" && !incidentId) throw new Error("Choose the incident to report on.");
    if (incidentId && !UUID.test(incidentId)) throw new Error("That incident id is not valid.");
    const r = await generateReport(ctx, input.tenantId, input.kind as ReportKind, { incidentId });
    revalidatePath("/reports");
    return { id: r.id };
  });
}
