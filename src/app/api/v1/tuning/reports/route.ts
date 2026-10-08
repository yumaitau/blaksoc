import { json, jsonBody, requireScope, serviceCall, shape, tuningRate } from "@/lib/api/http";
import { HermesReportList, ReportCreate, ReportCreated, ReportListQuery } from "@/lib/api/schemas";
import { createReport, listReports, REPORT_MAX_BYTES } from "@/lib/services/hermes";

export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  return serviceCall(req, "/tuning/reports", async (ctx) => {
    requireScope(ctx, "tuning:report");
    const q = ReportListQuery.parse(Object.fromEntries(new URL(req.url).searchParams));
    await tuningRate(ctx, "read");
    return json(200, shape(HermesReportList, { reports: await listReports(ctx, q.limit) }));
  });
}

export async function POST(req: Request) {
  return serviceCall(req, "/tuning/reports", async (ctx) => {
    requireScope(ctx, "tuning:report");
    // Room for JSON escaping around a report at the cap; the markdown itself is measured by the service.
    const input = ReportCreate.parse(await jsonBody(req, REPORT_MAX_BYTES * 2 + 4096));
    await tuningRate(ctx, "report");
    const created = await createReport(ctx, { ...input, periodStart: new Date(input.periodStart), periodEnd: new Date(input.periodEnd) });
    return json(201, shape(ReportCreated, created));
  });
}
