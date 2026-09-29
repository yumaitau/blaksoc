import { z } from "zod";
import type { ConnectorDefinition } from "@/lib/connectors/registry";
import { createM365Provider, ENTRA_REMOTE_PERMISSIONS, type M365Config } from "./provider";

const config = z.object({
  azureTenantId: z.string().min(1),
  /** `fixture` replays recorded Graph pages. Live tenants use client credentials. */
  mode: z.enum(["live", "fixture"]).default("live"),
  subscribedSkus: z.array(z.string()).default([]),
});

const secrets = z.object({
  clientId: z.string().min(1).optional(),
  clientSecret: z.string().min(1).optional(),
});

export const entraConnector: ConnectorDefinition = {
  provider: "entra",
  name: "Microsoft Entra ID",
  category: "identity",
  description: "Microsoft 365 and Entra ID: sign-ins, unified audit, identity protection where licensed, and approval-gated identity response.",
  status: "available",
  capabilities: ["events", "assets", "identity_response"],
  remotePermissions: ENTRA_REMOTE_PERMISSIONS,
  config,
  secrets,
  create: (c, s) => ({
    kind: "events",
    provider: createM365Provider(c as M365Config, { clientId: s.clientId, clientSecret: s.clientSecret }),
  }),
};
