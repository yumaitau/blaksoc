import { eq } from "drizzle-orm";
import type { Tx } from "@/db/client";
import { tenants } from "@/db/schema";

export class TrainingIsolationError extends Error {
  constructor(readonly code: "real" | "enable" = "real") {
    super(code === "enable" ? "training demo integration stays off the collector" : "training tenant cannot use a real integration");
    this.name = "TrainingIsolationError";
  }
}

export async function isTrainingTenant(tx: Tx, tenantId: string | null): Promise<boolean> {
  if (!tenantId) return false;
  const [row] = await tx.select({ settings: tenants.settings }).from(tenants).where(eq(tenants.id, tenantId));
  return row?.settings.training === true;
}

/** Reject a real provider on a training tenant. Returns whether that tenant is for training. */
export async function assertDemoOnly(tx: Tx, tenantId: string | null, provider: string): Promise<boolean> {
  const training = await isTrainingTenant(tx, tenantId);
  if (training && provider !== "demo") throw new TrainingIsolationError("real");
  return training;
}
