export const BANDWIDTH_PROFILES = ["standard", "low"] as const;
export type BandwidthProfile = (typeof BANDWIDTH_PROFILES)[number];

export type AgentProfile = {
  id: BandwidthProfile;
  notifySeconds: number;
  syscheckSeconds: number;
  realtime: boolean;
  scaSeconds: number;
  syscollectorSeconds: number;
  eventsPerSecond: number;
  logLevel: number;
};

/** Same machine. The slow profile changes how often it talks, not a smaller inventory. */
export const PROFILES: Record<BandwidthProfile, AgentProfile> = {
  standard: {
    id: "standard",
    notifySeconds: 10,
    syscheckSeconds: 43_200,
    realtime: true,
    scaSeconds: 43_200,
    syscollectorSeconds: 3_600,
    eventsPerSecond: 50,
    logLevel: 1,
  },
  low: {
    id: "low",
    notifySeconds: 60,
    syscheckSeconds: 86_400,
    realtime: false,
    scaSeconds: 86_400,
    syscollectorSeconds: 86_400,
    eventsPerSecond: 5,
    logLevel: 0,
  },
};

const DAY = 86_400;
const INVENTORY_LINE = "pkg=linux-image version=6.8.0 vendor=Ubuntu arch=amd64 size=120000\n";
/** Upper end of a full software list. The measurer counts this buffer, it does not assume a byte total. */
export const INVENTORY_ROWS = 32_000;
const LOG_LINE = "type=syslog auth user=ada result=ok src=203.0.113.8\n";
const KEEPALIVE = Buffer.from("<notify><id>001</id><name>host</name><status>idle</status></notify>");
const FIM = Buffer.alloc(8 * 1024, "fim-idle-diff\n");
const SCA = Buffer.from(Array.from({ length: 80 }, (_, i) => `policy ${i} passed`).join("\n"));

function inventorySample(): Buffer {
  return Buffer.alloc(INVENTORY_LINE.length * INVENTORY_ROWS, INVENTORY_LINE);
}

function times(everySeconds: number): number {
  return Math.max(1, Math.floor(DAY / everySeconds));
}

/** Idle upload for one endpoint over 24 hours, in bytes. */
export function dailyUploadBytes(profile: AgentProfile): number {
  const logs = Buffer.alloc(LOG_LINE.length * (profile.logLevel === 0 ? 200 : 8_000), LOG_LINE);
  const scheduledFim = times(profile.syscheckSeconds) * FIM.length;
  const realtime = profile.realtime ? FIM.length * 24 : 0;
  return (
    times(profile.notifySeconds) * KEEPALIVE.length
    + scheduledFim
    + realtime
    + times(profile.scaSeconds) * SCA.length
    + times(profile.syscollectorSeconds) * inventorySample().length
    + logs.length
  );
}

export function renderProfileXml(profile: AgentProfile, manager: string, group: string): string {
  const realtime = profile.realtime ? "yes" : "no";
  return [
    "<ossec_config>",
    "  <client>",
    "    <server>",
    `      <address>${manager}</address>`,
    "    </server>",
    `    <notify_time>${profile.notifySeconds}</notify_time>`,
    "    <enrollment>",
    `      <groups>${group}</groups>`,
    "    </enrollment>",
    "  </client>",
    "  <client_buffer>",
    "    <disabled>no</disabled>",
    "    <queue_size>5000</queue_size>",
    `    <events_per_second>${profile.eventsPerSecond}</events_per_second>`,
    "  </client_buffer>",
    "  <syscheck>",
    "    <disabled>no</disabled>",
    `    <frequency>${profile.syscheckSeconds}</frequency>`,
    `    <realtime>${realtime}</realtime>`,
    "  </syscheck>",
    "  <sca>",
    "    <enabled>yes</enabled>",
    `    <interval>${profile.scaSeconds}s</interval>`,
    "  </sca>",
    '  <wodle name="syscollector">',
    "    <disabled>no</disabled>",
    `    <interval>${profile.syscollectorSeconds}s</interval>`,
    "  </wodle>",
    "  <logging>",
    `    <log_level>${profile.logLevel}</log_level>`,
    "  </logging>",
    "</ossec_config>",
    "",
  ].join("\n");
}
