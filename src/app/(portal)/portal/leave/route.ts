import { headers } from "next/headers";
import { NextResponse } from "next/server";
import { auth } from "@/lib/auth/auth";
import { env } from "@/lib/env";

export async function POST() {
  const h = new Headers(await headers());
  h.set("content-type", "application/json");
  const url = new URL("/api/auth/sign-out", env().APP_URL);
  const res = await auth.handler(new Request(url, { method: "POST", headers: h, body: "{}" }));
  const out = NextResponse.redirect(new URL("/login", env().APP_URL), 303);
  for (const cookie of res.headers.getSetCookie()) out.headers.append("set-cookie", cookie);
  return out;
}
