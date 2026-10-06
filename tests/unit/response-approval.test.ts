import { describe, expect, it } from "vitest";
import { RESPONSE_ACTIONS } from "@/lib/soar/actions";
import { responseNeedsApproval } from "@/lib/soar/response";

describe("response approval gate", () => {
  it("holds every AI proposal for a human, destructive or not", () => {
    for (const [key, def] of Object.entries(RESPONSE_ACTIONS)) {
      for (const autoContainment of [true, false]) {
        expect(responseNeedsApproval({ destructive: def.destructive, requestedByKind: "ai", autoContainment }), key).toEqual({ needsApproval: true, autoAllowed: false });
      }
    }
  });

  it("holds destructive analyst requests and lets non-destructive ones run", () => {
    expect(responseNeedsApproval({ destructive: true, requestedByKind: "user", autoContainment: true }).needsApproval).toBe(true);
    expect(responseNeedsApproval({ destructive: false, requestedByKind: "user", autoContainment: false }).needsApproval).toBe(false);
  });

  it("lets playbooks skip the gate only under auto-containment", () => {
    expect(responseNeedsApproval({ destructive: true, requestedByKind: "playbook", autoContainment: false }).needsApproval).toBe(true);
    expect(responseNeedsApproval({ destructive: true, requestedByKind: "playbook", autoContainment: true })).toEqual({ needsApproval: false, autoAllowed: true });
  });
});
