import { describe, expect, it } from "vitest";
import type { AccessContext, Grant } from "@/lib/auth/access";
import { BUILTIN_ROLES, type Permission } from "@/lib/auth/permissions";
import { eventVisible } from "@/lib/events";

const grant = (key: string, tenantId: string | null): Grant => ({ roleKey: key, tenantId, permissions: new Set(BUILTIN_ROLES.find((r) => r.key === key)!.permissions as Permission[]) });
const ctx = (grants: Grant[], tenantIds: string[]): AccessContext => ({
  principal: { userId: "u", name: "T", email: "t@example.invalid", isBreakGlass: false },
  isPlatform: grants.some((g) => g.tenantId === null),
  grants,
  tenantIds,
  tenants: tenantIds.map((id) => ({ id, slug: id, name: id, kind: "customer" as const })),
});

describe("live event visibility", () => {
  const alert = { type: "alert.created" as const, tenantId: "a", id: "1", title: "t", severity: "high", riskScore: 50 };
  const incident = { type: "incident.updated" as const, tenantId: "a", id: "2" };

  it("shows alerts to platform analysts and incidents to the customer", () => {
    expect(eventVisible(ctx([grant("soc_analyst_l1", null)], ["a"]), alert)).toBe(true);
    expect(eventVisible(ctx([grant("customer_security", "a")], ["a"]), alert)).toBe(false);
    expect(eventVisible(ctx([grant("customer_security", "a")], ["a"]), incident)).toBe(true);
  });

  it("hides another tenant's events and everything once roles are gone", () => {
    expect(eventVisible(ctx([grant("customer_security", "b")], ["b"]), incident)).toBe(false);
    expect(eventVisible(ctx([], []), incident)).toBe(false);
  });
});
