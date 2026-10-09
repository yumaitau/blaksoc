import { beforeEach, describe, expect, it, vi } from "vitest";
import { AccessDenied } from "@/lib/auth/access";

const mocks = vi.hoisted(() => ({ signed: vi.fn(), snapshot: vi.fn(), access: vi.fn(), workspace: vi.fn() }));
vi.mock("@/lib/services/wallboard", () => ({ signedWallboardSnapshot: mocks.signed, wallboardSnapshot: mocks.snapshot }));
vi.mock("@/lib/auth/session", () => ({ currentAccess: mocks.access }));
vi.mock("@/lib/workspace", () => ({ currentWorkspace: mocks.workspace }));

import { GET } from "@/app/api/wallboard/route";

beforeEach(() => vi.resetAllMocks());
const get = (query = "") => GET(new Request(`https://soc.example/api/wallboard${query}`));

describe("wallboard API boundary", () => {
  it("uses only the signed scope and never redirects an invalid token to sign-in", async () => {
    mocks.signed.mockResolvedValue(null);
    const refused = await get("?token=invalid&tenantIds=other");
    expect(refused.status).toBe(401);
    expect(refused.headers.get("location")).toBeNull();
    expect(mocks.access).not.toHaveBeenCalled();
    expect(mocks.signed).toHaveBeenCalledWith("invalid");
    expect((await get("?token=")).status).toBe(401);
    expect((await get("?token=a&token=b")).status).toBe(401);
  });

  it("returns current signed data with private no-store and no-referrer headers", async () => {
    mocks.signed.mockResolvedValue({ generatedAt: "now" });
    const response = await get("?token=valid");
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ generatedAt: "now" });
    expect(response.headers.get("cache-control")).toContain("no-store");
    expect(response.headers.get("referrer-policy")).toBe("no-referrer");
  });

  it("uses a signed-in user's current workspace unless explicit scope is supplied", async () => {
    const ctx = { principal: { userId: "test" }, tenants: [{ id: "workspace", kind: "customer" }] };
    mocks.access.mockResolvedValue(ctx);
    mocks.workspace.mockResolvedValue({ tenantIds: ["workspace"] });
    mocks.snapshot.mockResolvedValue({ counts: {} });
    expect((await get()).status).toBe(200);
    expect(mocks.snapshot).toHaveBeenCalledWith(ctx, ["workspace"]);
    expect((await get("?tenantIds=chosen,other")).status).toBe(200);
    expect(mocks.snapshot).toHaveBeenCalledWith(ctx, ["chosen", "other"]);
    expect((await get("?tenantIds=")).status).toBe(403);
    expect((await get("?tenantIds=a&tenantIds=b")).status).toBe(403);
  });

  it("reports anonymous, forbidden and unavailable states without exposing errors", async () => {
    mocks.access.mockResolvedValue(null);
    expect((await get()).status).toBe(401);
    mocks.access.mockResolvedValue({ tenants: [{ id: "scope", kind: "customer" }] });
    mocks.workspace.mockResolvedValue({ tenantIds: ["scope"] });
    mocks.snapshot.mockRejectedValue(new AccessDenied());
    expect((await get()).status).toBe(403);
    mocks.signed.mockRejectedValue(new Error("PRIVATE DATABASE FAILURE"));
    const response = await get("?token=valid");
    expect(response.status).toBe(503);
    expect(await response.text()).not.toContain("PRIVATE DATABASE");
  });
});
