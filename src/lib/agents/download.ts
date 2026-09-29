import { createHmac, timingSafeEqual } from "node:crypto";
import { type AgentProfile, type BandwidthProfile, PROFILES, renderProfileXml } from "./profile";

export const DOWNLOAD_TTL_MS = 15 * 60 * 1000;
export const PLATFORMS = ["win-msi", "mac-pkg", "linux-deb", "linux-rpm"] as const;
export type InstallerPlatform = (typeof PLATFORMS)[number];

const FILENAME: Record<InstallerPlatform, string> = {
  "win-msi": "blaksoc-agent-windows.ps1",
  "mac-pkg": "blaksoc-agent-macos.sh",
  "linux-deb": "blaksoc-agent-linux-deb.sh",
  "linux-rpm": "blaksoc-agent-linux-rpm.sh",
};

export function agentGroup(slug: string): string {
  const group = slug.toLowerCase().replace(/[^a-z0-9-]/g, "").replace(/^-+|-+$/g, "").slice(0, 64);
  return group || "tenant";
}

export function signDownload(parts: { enrolmentId: string; platform: InstallerPlatform; exp: number }, key: string): string {
  const body = `${parts.enrolmentId}.${parts.platform}.${parts.exp}`;
  const sig = createHmac("sha256", key).update(body).digest("base64url");
  return `${body}.${sig}`;
}

export function openDownload(token: string, key: string, now: number): { enrolmentId: string; platform: InstallerPlatform; exp: number } | null {
  const bits = token.split(".");
  if (bits.length !== 4) return null;
  const [enrolmentId, platform, expRaw, sig] = bits;
  if (!enrolmentId || !sig || !PLATFORMS.includes(platform as InstallerPlatform)) return null;
  const exp = Number(expRaw);
  if (!Number.isFinite(exp) || exp <= now) return null;
  const expected = createHmac("sha256", key).update(`${enrolmentId}.${platform}.${expRaw}`).digest("base64url");
  const left = Buffer.from(sig);
  const right = Buffer.from(expected);
  if (left.length !== right.length || !timingSafeEqual(left, right)) return null;
  return { enrolmentId, platform: platform as InstallerPlatform, exp };
}

export function renderInstaller(platform: InstallerPlatform, input: { manager: string; group: string; token: string; profile: AgentProfile }): { filename: string; body: string } {
  const xml = renderProfileXml(input.profile, input.manager, input.group);
  const common = [
    `# blakSOC agent installer (${platform})`,
    `# group ${input.group}`,
    `# registration password is the enrolment token`,
    `WAZUH_MANAGER=${input.manager}`,
    `WAZUH_AGENT_GROUP=${input.group}`,
    `WAZUH_REGISTRATION_PASSWORD=${input.token}`,
    "",
    xml,
  ];
  const command: Record<InstallerPlatform, string> = {
    "win-msi": `msiexec /i wazuh-agent.msi /q WAZUH_MANAGER=${input.manager} WAZUH_REGISTRATION_PASSWORD=${input.token} WAZUH_AGENT_GROUP=${input.group}`,
    "mac-pkg": `installer -pkg wazuh-agent.pkg -target / && echo WAZUH_MANAGER=${input.manager} WAZUH_AGENT_GROUP=${input.group}`,
    "linux-deb": `WAZUH_MANAGER=${input.manager} WAZUH_AGENT_GROUP=${input.group} WAZUH_REGISTRATION_PASSWORD=${input.token} dpkg -i wazuh-agent.deb`,
    "linux-rpm": `WAZUH_MANAGER=${input.manager} WAZUH_AGENT_GROUP=${input.group} WAZUH_REGISTRATION_PASSWORD=${input.token} rpm -i wazuh-agent.rpm`,
  };
  return { filename: FILENAME[platform], body: [...common, command[platform], ""].join("\n") };
}

export function profileFor(link: string | null | undefined): AgentProfile {
  return link === "low" ? PROFILES.low : PROFILES.standard;
}

export function isBandwidthProfile(value: string): value is BandwidthProfile {
  return value === "standard" || value === "low";
}
