import { describe, expect, it } from "vitest";
import { can, dbScope, type AccessContext } from "@/lib/auth/access";
import { BUILTIN_ROLES, type Permission } from "@/lib/auth/permissions";
import { LIST_PRICE_CENTS } from "@/lib/billing/catalogue";
import { PARTNER_REVENUE_SHARE_BPS, revenueShareCents, shareBaseCents } from "@/lib/services/partner";
import { cobrandLine } from "@/lib/tenancy/brand";

const adminPerms = new Set(BUILTIN_ROLES.find((role) => role.key === "partner_admin")!.permissions as Permission[]);

function partnerCtx(): AccessContext {
  return {
    principal: { userId: "u", name: "River Admin", email: "river@example.invalid", isBreakGlass: false },
    isPlatform: false,
    grants: [{ roleKey: "partner_admin", tenantId: "p", permissions: adminPerms }],
    tenantIds: ["p", "c"],
    tenants: [
      { id: "p", slug: "river", name: "River IT", kind: "partner", parentId: null, brandName: null, cobrand: null },
      { id: "c", slug: "creek", name: "Creek Clinic", kind: "customer", parentId: "p", brandName: null, cobrand: null },
    ],
  };
}

describe("partner co-brand and share", () => {
  it("keeps blakSOC in the co-brand line", () => {
    expect(cobrandLine("River IT", null)).toBe("River IT with blakSOC");
    expect(cobrandLine("River IT", "  River  ")).toBe("River with blakSOC");
    expect(cobrandLine("River IT", "   ")).toBe("River IT with blakSOC");
  });

  it("takes the share from the ex-GST amount", () => {
    const essentials = { tier: "essentials" as const, nonprofit: false, discountBps: 0 };
    expect(shareBaseCents(essentials, null)).toBe(LIST_PRICE_CENTS.essentials);
    expect(revenueShareCents(shareBaseCents(essentials, null))).toBe(9_000);
    expect(revenueShareCents(LIST_PRICE_CENTS.standard)).toBe(18_000);
    const nonprofit = shareBaseCents({ tier: "essentials", nonprofit: true, discountBps: 0 }, null);
    expect(nonprofit).toBe(36_000);
    expect(revenueShareCents(nonprofit)).toBe(7_200);
    expect(shareBaseCents({ tier: "plus", nonprofit: false, discountBps: 5_000 }, null)).toBe(90_000);
    expect(shareBaseCents(essentials, 0)).toBe(0);
    expect(PARTNER_REVENUE_SHARE_BPS).toBe(2_000);
  });

  it("applies the partner grant only to that partner's child", () => {
    const ctx = partnerCtx();
    expect(can(ctx, "alert:read", "c")).toBe(true);
    expect(can(ctx, "incident:write", "c")).toBe(true);
    expect(can(ctx, "response:approve", "c")).toBe(false);
    expect(can(ctx, "alert:read", "other")).toBe(false);
    const scope = dbScope(ctx, ["c", "other"]);
    expect(scope).toEqual({ tenantIds: ["c", "other"], grantIds: ["p"], platform: false });
  });
});
