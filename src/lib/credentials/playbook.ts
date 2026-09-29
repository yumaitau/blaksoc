export const CREDENTIAL_EXPOSURE_PLAYBOOK = {
  name: "Credential exposure",
  description: "A breach or infostealer feed matched a staff email. Ask a person to approve a password reset and a session revoke before either runs.",
  enabled: false,
  trigger: { event: "alert.created" as const, conditions: [{ field: "alert.category", op: "eq" as const, value: "credential_exposure" }] },
  steps: [
    { id: "incident", action: "incident.create", name: "Create incident", params: { title: "Credential exposure" } },
    { id: "gate", action: "approval.request", name: "Approval gate before reset", params: { summary: "Approve a password reset and a session revoke for this person?" } },
    { id: "reset", action: "reset_password", name: "Force password reset" },
    { id: "revoke", action: "revoke_sessions", name: "Revoke sessions" },
  ],
};
