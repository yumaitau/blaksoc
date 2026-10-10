import type { ReactNode } from "react";
import { redirect } from "next/navigation";
import { DashboardBoard } from "@/components/soc/dashboard-board";
import {
  AdvisoriesCard,
  AttackCard,
  ContainmentCard,
  CustomersCard,
  FatigueCard,
  HermesWeekCard,
  IncidentsCard,
  InfraCard,
  IntelCard,
  InvestigateCard,
  PostureCard,
  VulnsCard,
  WorkloadCard,
  hermesSummary,
} from "@/components/soc/dashboard-widgets";
import { RadarOutageCard, RadarPending, RadarSetup, RadarShareCard } from "@/components/soc/radar-cards";
import { ToolCards } from "@/components/soc/tool-cards";
import { requireAccess } from "@/lib/auth/session";
import { widgetTitle, type WidgetId } from "@/lib/dashboard/layout";
import { loadRadar } from "@/lib/radar/load";
import { fatigueMetrics, socDashboard } from "@/lib/services/dashboard";
import { readDashboardLayout } from "@/lib/services/dashboard-layout";
import { socTools } from "@/lib/services/soc-tools";
import { currentWorkspace } from "@/lib/workspace";

export const metadata = { title: "SOC dashboard" };

const RADAR_IDS = ["radar-l7", "radar-l3", "radar-outages", "radar-bots"] as const satisfies readonly WidgetId[];

/**
 * Same answers as before: what is happening, what matters, who is affected,
 * what to investigate next, and what has been done. The analyst chooses which
 * of those widgets are on the board, and where. Cloudflare Radar is one of them.
 */
export default async function SocDashboard() {
  const ctx = await requireAccess();
  if (!ctx.isPlatform) redirect("/portal");
  const ws = await currentWorkspace(ctx);
  const [d, tools, fatigue, hermes, layout] = await Promise.all([
    socDashboard(ctx, ws.tenantIds),
    socTools(ctx),
    fatigueMetrics(ctx, ws.tenantIds),
    hermesSummary(ctx, ws.tenantIds),
    readDashboardLayout(ctx),
  ]);
  const radar = await loadRadar();
  const scope = ws.tenant ? ws.tenant.name : "all customers";

  const slots: Partial<Record<WidgetId, ReactNode>> = {
    tools: <ToolCards tools={tools} />,
    posture: <PostureCard d={d} />,
    fatigue: <FatigueCard f={fatigue} />,
    investigate: <InvestigateCard d={d} />,
    customers: <CustomersCard d={d} />,
    incidents: <IncidentsCard d={d} />,
    containment: <ContainmentCard d={d} />,
    intel: <IntelCard d={d} />,
    infra: <InfraCard d={d} />,
    attack: <AttackCard d={d} />,
    workload: <WorkloadCard d={d} />,
    vulns: <VulnsCard d={d} />,
    advisories: <AdvisoriesCard d={d} />,
  };
  if (hermes) slots.hermes = <HermesWeekCard h={hermes} />;

  if (!radar.configured) {
    const first = layout.find((w) => !w.hidden && (RADAR_IDS as readonly string[]).includes(w.id));
    for (const id of RADAR_IDS) {
      slots[id] = first?.id === id ? <RadarSetup /> : <RadarPending title={widgetTitle(id)} />;
    }
  } else {
    slots["radar-l7"] = <RadarShareCard title="Application attacks" hint="Australia · last 24 hours · by industry. Cloudflare Radar, not a customer's traffic." href="https://radar.cloudflare.com/security-and-attacks" section={radar.l7} />;
    slots["radar-l3"] = <RadarShareCard title="Network attacks" hint="Australia · last 24 hours · by protocol. Cloudflare Radar, not a customer's traffic." href="https://radar.cloudflare.com/security-and-attacks" section={radar.l3} />;
    slots["radar-outages"] = <RadarOutageCard section={radar.outages} />;
    slots["radar-bots"] = <RadarShareCard title="Bot traffic" hint="Australia · last 24 hours · human versus automated HTTP. Cloudflare Radar." href="https://radar.cloudflare.com/traffic" section={radar.bots} />;
  }

  return <DashboardBoard scope={scope} initial={layout} slots={slots} />;
}
