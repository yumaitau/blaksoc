/** Response actions blakSOC can take against real systems. */
export const RESPONSE_ACTIONS = {
  isolate_endpoint: { label: "Isolate endpoint", destructive: true, target: "asset" },
  release_endpoint: { label: "Release endpoint from isolation", destructive: false, target: "asset" },
  block_ip: { label: "Block IP on endpoint firewall", destructive: true, target: "asset+ip" },
  kill_process: { label: "Kill process", destructive: true, target: "asset" },
  disable_identity: { label: "Disable identity", destructive: true, target: "identity" },
  revoke_sessions: { label: "Revoke identity sessions", destructive: true, target: "identity" },
  block_ioc: { label: "Block IOC at perimeter", destructive: true, target: "observable" },
} as const;

export type ResponseActionKey = keyof typeof RESPONSE_ACTIONS;

export function isResponseAction(a: string): a is ResponseActionKey {
  return a in RESPONSE_ACTIONS;
}
