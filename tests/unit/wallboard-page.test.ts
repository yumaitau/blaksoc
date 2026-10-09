import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({ access: vi.fn(), assertCan: vi.fn(), workspace: vi.fn() }));
vi.mock("@/lib/auth/session", () => ({ requireAccess: mocks.access }));
vi.mock("@/lib/auth/access", () => ({ assertCan: mocks.assertCan }));
vi.mock("@/lib/workspace", () => ({ currentWorkspace: mocks.workspace }));
vi.mock("@/components/wallboard/wallboard", () => ({ Wallboard: () => null }));

import WallboardPage from "@/app/wallboard/page";

beforeEach(() => {
  vi.resetAllMocks();
  mocks.access.mockResolvedValue({ tenants: [{ id: "customer-a", kind: "customer" }, { id: "platform", kind: "mssp" }] });
  mocks.workspace.mockResolvedValue({ tenantIds: ["customer-a", "platform"] });
});

const page = (params: Record<string, string | string[] | undefined> = {}) => WallboardPage({ searchParams: Promise.resolve(params) });
const queryOf = (element: Awaited<ReturnType<typeof page>>) => new URL(element.props.endpoint, "https://soc.example").searchParams;

describe("wallboard page access and scope", () => {
  it("opens a supplied signed URL without requiring a session", async () => {
    const element = await page({ token: "signed-link", tenantIds: "other" });
    expect(queryOf(element).get("token")).toBe("signed-link");
    expect(queryOf(element).has("tenantIds")).toBe(false);
    expect(mocks.access).not.toHaveBeenCalled();
  });

  it("passes malformed signed credentials for rejection without falling back to a session", async () => {
    for (const token of ["", ["one", "two"]]) {
      expect(queryOf(await page({ token })).get("token")).toBe("");
    }
    expect(mocks.access).not.toHaveBeenCalled();
  });

  it("pins a signed-in display to the current customer's workspace", async () => {
    const element = await page();
    expect(queryOf(element).get("tenantIds")).toBe("customer-a");
    expect(mocks.assertCan).toHaveBeenCalledWith(await mocks.access.mock.results[0]!.value, "dashboard:read");
  });

  it("preserves explicit scopes including empty and duplicate scopes for API validation", async () => {
    expect(queryOf(await page({ tenantIds: "customer-b" })).get("tenantIds")).toBe("customer-b");
    expect(queryOf(await page({ tenantIds: "" })).get("tenantIds")).toBe("");
    expect(queryOf(await page({ tenantIds: ["a", "b"] })).getAll("tenantIds")).toEqual(["a", "b"]);
    expect(mocks.workspace).not.toHaveBeenCalled();
  });

  it("remounts the display when its credential or scope changes", async () => {
    const first = await page({ token: "first" });
    const second = await page({ token: "second" });
    expect(first.key).toBe(first.props.endpoint);
    expect(second.key).toBe(second.props.endpoint);
    expect(first.key).not.toBe(second.key);
  });
});
