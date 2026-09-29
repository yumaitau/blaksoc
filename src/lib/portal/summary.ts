const ACTION_LABEL: Record<string, string> = {
  isolate_endpoint: "isolated a device from the network",
  disable_identity: "disabled a user account",
  block_ioc: "blocked malicious infrastructure",
  unisolate_endpoint: "reconnected a device",
  enable_identity: "re-enabled a user account",
  reset_password: "reset a password",
};

export function actionPhrase(action: string): string {
  return ACTION_LABEL[action] ?? action.replaceAll("_", " ");
}

export function severityLabel(severity: string): string {
  if (!severity) return "Unknown";
  return severity.slice(0, 1).toUpperCase() + severity.slice(1);
}

export function statusLabel(status: string): string {
  return status.replaceAll("_", " ").toLowerCase();
}

/** Three sentences: what happened, what we did, what you need to do. */
export function incidentSentences(input: {
  title: string;
  severity: string;
  status: string;
  actions: string[];
}): [string, string, string] {
  const title = input.title.replace(/\s+/g, " ").trim() || "a security incident";
  const happened = `What happened: ${title} (severity ${input.severity}).`;
  const did = input.actions.length
    ? `What we did: ${input.actions.join("; ")}.`
    : `What we did: the SOC is treating this as ${statusLabel(input.status)}.`;
  const need =
    input.status === "CLOSED" || input.status === "RECOVERED"
      ? "What you need to do: nothing further, unless we contact you."
      : "What you need to do: read this update and press I've read this.";
  return [happened, did, need];
}
