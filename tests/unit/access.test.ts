import { describe, expect, it } from "vitest";
import { tenantRoleGrantDenial, type AccessContext, type Grant } from "@/lib/auth/access";
import { BUILTIN_ROLES, type Permission } from "@/lib/auth/permissions";

const role = (key: string) => {
  const r = BUILTIN_ROLES.find((x) => x.key === key)!;
  return { key: r.key, permissions: r.permissions };
};
const grant = (key: string, tenantId: string | null): Grant => ({ roleKey: key, tenantId, permissions: new Set(role(key).permissions as Permission[]) });

function ctx(grants: Grant[]): AccessContext {
  return {
    principal: { userId: "u", name: "Test", email: "t@example.invalid", isBreakGlass: false },
    isPlatform: grants.some((g) => g.tenantId === null),
    grants,
    tenantIds: ["c", "p", "k"],
    tenants: [
      { id: "c", slug: "c", name: "Customer", kind: "customer", parentId: null },
      { id: "p", slug: "p", name: "Partner", kind: "partner", parentId: null },
      { id: "k", slug: "k", name: "Partner customer", kind: "customer", parentId: "p" },
    ],
  };
}

const customer = { id: "c", kind: "customer" as const };
const partner = { id: "p", kind: "partner" as const };
const partnerChild = { id: "k", kind: "customer" as const };

describe("tenant role grant ceiling", () => {
  it("stops a customer admin raising anyone to partner admin", () => {
    expect(tenantRoleGrantDenial(ctx([grant("customer_admin", "c")]), role("partner_admin"), customer)).toMatch(/partner tenant/);
  });

  it("stops a customer admin granting permissions they lack", () => {
    const custom = { key: "custom_ops", permissions: ["portal:read", "settings:manage"] };
    expect(tenantRoleGrantDenial(ctx([grant("customer_admin", "c")]), custom, customer)).toMatch(/settings:manage/);
  });

  it("lets a customer admin grant roles within their own permissions", () => {
    const admin = ctx([grant("customer_admin", "c")]);
    for (const key of ["customer_admin", "customer_security", "customer_readonly", "data_steward"]) {
      expect(tenantRoleGrantDenial(admin, role(key), customer)).toBeNull();
    }
  });

  it("lets a partner admin staff its own tenancy but not grant partner roles on a customer", () => {
    const admin = ctx([grant("partner_admin", "p")]);
    expect(tenantRoleGrantDenial(admin, role("partner_analyst"), partner)).toBeNull();
    expect(tenantRoleGrantDenial(admin, role("partner_admin"), partnerChild)).toMatch(/partner tenant/);
  });

  it("lets platform user administrators grant any customer role", () => {
    const platform = ctx([grant("platform_admin", null)]);
    expect(tenantRoleGrantDenial(platform, role("customer_admin"), customer)).toBeNull();
    expect(tenantRoleGrantDenial(platform, role("partner_admin"), partner)).toBeNull();
  });

  it("refuses callers without user:manage on the tenant", () => {
    expect(tenantRoleGrantDenial(ctx([grant("soc_manager", null)]), role("customer_readonly"), customer)).toBe("missing user:manage");
  });
});
