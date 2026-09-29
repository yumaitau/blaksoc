import { z } from "zod";
import type { ConnectorDefinition } from "@/lib/connectors/registry";
import { createGoogleProvider, GOOGLE_REMOTE_PERMISSIONS, type GoogleConfig } from "./provider";

const config = z.object({
  customerId: z.string().min(1),
  domain: z.string().min(1),
  mode: z.enum(["fixture", "live"]).default("fixture"),
});

const secrets = z.object({
  clientEmail: z.string().email().optional(),
  privateKey: z.string().min(1).optional(),
});

export const googleWorkspaceConnector: ConnectorDefinition = {
  provider: "google-workspace",
  name: "Google Workspace",
  category: "identity",
  description: "Google Workspace login, admin, Drive, and token audit, plus users, ChromeOS, and mobile devices. Response actions stay behind approval.",
  status: "available",
  capabilities: ["events", "assets", "identity_response"],
  remotePermissions: GOOGLE_REMOTE_PERMISSIONS,
  config,
  secrets,
  create: (c, s) => ({
    kind: "events",
    provider: createGoogleProvider(c as GoogleConfig, { clientEmail: s.clientEmail, privateKey: s.privateKey }),
  }),
};
