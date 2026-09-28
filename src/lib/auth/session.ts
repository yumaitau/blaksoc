import "server-only";
import { headers } from "next/headers";
import { redirect } from "next/navigation";
import { cache } from "react";
import { env } from "@/lib/env";
import { resolveAccess, type AccessContext } from "./access";
import { auth } from "./auth";

export type SessionState =
  | { state: "anonymous" }
  | { state: "mfa_enrolment_required"; userId: string }
  | { state: "ok"; access: AccessContext };

export const getSessionState = cache(async (): Promise<SessionState> => {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session) return { state: "anonymous" };
  const u = session.user as typeof session.user & { isBreakGlass?: boolean; disabled?: boolean; twoFactorEnabled?: boolean };
  if (u.disabled) return { state: "anonymous" };
  if (u.isBreakGlass && !u.twoFactorEnabled && env().BREAK_GLASS_REQUIRE_MFA === "true") {
    return { state: "mfa_enrolment_required", userId: u.id };
  }
  const access = await resolveAccess({ userId: u.id, name: u.name, email: u.email, isBreakGlass: !!u.isBreakGlass });
  return { state: "ok", access };
});

/** For pages: redirect when unauthenticated. */
export async function requireAccess(): Promise<AccessContext> {
  const s = await getSessionState();
  if (s.state === "anonymous") redirect("/login");
  if (s.state === "mfa_enrolment_required") redirect("/account/mfa");
  return s.access;
}

/** For route handlers / actions: null instead of redirect. */
export async function currentAccess(): Promise<AccessContext | null> {
  const s = await getSessionState();
  return s.state === "ok" ? s.access : null;
}
