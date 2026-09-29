import { readFileSync } from "node:fs";
import path from "node:path";

/** Recommended low-noise Sysmon filter and Wazuh agent config for SME endpoints. */
export function smeEndpointProfile(root = process.cwd()) {
  const dir = path.join(root, "deploy/wazuh");
  return {
    sysmon: readFileSync(path.join(dir, "sme-sysmon.xml"), "utf8"),
    wazuh: readFileSync(path.join(dir, "sme-agent.conf"), "utf8"),
  };
}
