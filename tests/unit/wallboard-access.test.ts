import { describe, expect, it } from "vitest";
import type { AccessContext } from "@/lib/auth/access";
import type { Permission } from "@/lib/auth/permissions";
import { canManageWallboardLinks, createWallboardLink, wallboardSnapshot } from "@/lib/services/wallboard";

const ctx = (permissions: Permission[], tenantId: string | null = null): AccessContext => ({
  principal: { userId: "test", name: "Test", email: "test@example.invalid", isBreakGlass: false },
  isPlatform: tenantId === null, grants: [{ roleKey: "test", tenantId, permissions: new Set(permissions) }], tenantIds: [], tenants: [],
});

describe("TV link management", () => {
  it("requires both dashboard access and platform management authority", () => {
    expect(canManageWallboardLinks(ctx(["dashboard:read", "response:approve"]))).toBe(true);
    expect(canManageWallboardLinks(ctx(["dashboard:read", "user:manage"]))).toBe(true);
    expect(canManageWallboardLinks(ctx(["dashboard:read"]))).toBe(false);
    expect(canManageWallboardLinks(ctx(["user:manage"]))).toBe(false);
    expect(canManageWallboardLinks(ctx(["dashboard:read", "user:manage"], "tenant"))).toBe(false);
    const service = ctx(["dashboard:read", "user:manage"]);
    service.principal.kind = "service";
    expect(canManageWallboardLinks(service)).toBe(false);
  });

  it("an explicit empty customer scope stays empty instead of expanding to all customers", async () => {
    const reader = ctx(["dashboard:read"]);
    const id = "00000000-0000-4000-8000-000000000001";
    reader.tenantIds = [id];
    reader.tenants = [{ id, name: "Customer", slug: "customer", kind: "customer" }];
    const snapshot = await wallboardSnapshot(reader, []);
    expect(snapshot.customerCount).toBe(0);
    expect(snapshot.counts.openAlerts).toBe(0);
    expect(snapshot.activity).toHaveLength(24);
    await expect(wallboardSnapshot(reader, ["00000000-0000-4000-8000-000000000002"])).rejects.toMatchObject({ name: "AccessDenied" });
  });

  it("rejects malformed runtime link input before touching the database", async () => {
    const manager = ctx(["dashboard:read", "user:manage"]);
    for (const input of [null, { name: null, tenantIds: [] }, { name: "TV", tenantIds: null }, { name: "TV", tenantIds: [null] }, { name: "TV", tenantIds: ["malformed"], expiresInDays: 7 }, { name: "TV", tenantIds: [], expiresInDays: "7" }]) {
      await expect(createWallboardLink(manager, input as unknown as Parameters<typeof createWallboardLink>[1])).rejects.toBeInstanceOf(Error);
    }
  });
});
