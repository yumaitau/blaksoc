"use server";
import { revalidatePath } from "next/cache";
import { withAccess } from "@/lib/actions";
import { REPORT_KINDS, type ReportKind } from "@/lib/reports/generate";
import { BoardBriefError, setBoardBrief } from "@/lib/services/board";
import { generateReport } from "@/lib/services/reports";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export async function generateReportAction(input: {
  tenantId: string;
  kind: string;
  incidentId?: string;
  span?: string;
  preamble?: string;
  image?: { mime: string; data: string } | null;
}) {
  return withAccess(async (ctx) => {
    if (!(input.kind in REPORT_KINDS)) throw new Error("Unknown report kind.");
    const incidentId = input.incidentId?.trim() || undefined;
    if (input.kind === "incident" && !incidentId) throw new Error("Choose the incident to report on.");
    if (incidentId && !UUID.test(incidentId)) throw new Error("That incident id is not valid.");
    const span = input.span === "quarter" ? "quarter" : "month";
    if (input.kind === "board_summary") {
      try {
        await setBoardBrief(ctx, input.tenantId, {
          span,
          ...(input.preamble?.trim() ? { preamble: input.preamble } : {}),
          ...(input.image ? { image: input.image } : {}),
        });
      } catch (err) {
        if (err instanceof BoardBriefError && err.code === "preamble") throw new Error("The note must be 600 characters or less, with no emoji.");
        if (err instanceof BoardBriefError && err.code === "image") throw new Error("Use a PNG or JPEG image under 80 KB.");
        if (err instanceof BoardBriefError) throw new Error("Choose a 30 day or 90 day period.");
        throw err;
      }
    }
    const r = await generateReport(ctx, input.tenantId, input.kind as ReportKind, { incidentId, span });
    revalidatePath("/reports");
    return { id: r.id };
  });
}
