import { describe, expect, it } from "vitest";
import { e8Label, e8Strategies, e8Strategy, ismControl, ismControls, ismText } from "@/lib/compliance/refs";
import { normaliseWedgetail } from "@/lib/providers/wedgetail";
import { WEDGETAIL_CREATED } from "../fixtures/wedgetail";

describe("compliance references", () => {
  it("maps every Wedgetail Essential Eight key, maturity suffix and hyphen form to blakSOC strategies", () => {
    expect(e8Strategy("application_control")).toBe("application_control");
    expect(e8Strategy("patch_applications")).toBe("patch_applications");
    expect(e8Strategy("office_macros")).toBe("office_macros");
    expect(e8Strategy("user_application_hardening")).toBe("user_app_hardening");
    expect(e8Strategy("restrict_admin_privileges")).toBe("restrict_admin");
    expect(e8Strategy("patch_operating_systems")).toBe("patch_os");
    expect(e8Strategy("multi_factor_authentication")).toBe("mfa");
    expect(e8Strategy("regular_backups")).toBe("regular_backups");
    expect(e8Strategy("restrict_admin_privileges:ML2")).toBe("restrict_admin");
    expect(e8Strategy("Multi-Factor Authentication")).toBe("mfa");
    expect(e8Strategy("antivirus")).toBeNull();
    expect(e8Strategies(["mfa", "multi_factor_authentication", "nope", 3])).toEqual(["mfa"]);
    expect(e8Label("restrict_admin")).toBe("Restrict administrative privileges");
  });

  it("normalises ISM control ids and drops anything else", () => {
    expect(ismControl("ISM-1509")).toBe("ISM-1509");
    expect(ismControl("ism1509")).toBe("ISM-1509");
    expect(ismControl("ISM-150")).toBeNull();
    expect(ismControls(["ISM-1683", "ism-1509", "ISM-1683", "1509; drop table", null])).toEqual(["ISM-1509", "ISM-1683"]);
    expect(ismText("ISM-1509")).toMatch(/privileged/i);
    expect(ismText("ISM-9999")).toBeNull();
  });

  it("carries Wedgetail references on the normalised alert for ingest", () => {
    const alert = normaliseWedgetail(WEDGETAIL_CREATED as never);
    expect(alert.ismControls).toEqual(["ISM-1509"]);
    expect(alert.e8Strategies).toEqual(["multi-factor-authentication"]);
    expect(e8Strategies(alert.e8Strategies)).toEqual(["mfa"]);
  });
});
