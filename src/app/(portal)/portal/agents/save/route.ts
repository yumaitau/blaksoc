import { NextResponse } from "next/server";
import { PLATFORMS } from "@/lib/agents/download";
import { AccessDenied } from "@/lib/auth/access";
import { currentAccess } from "@/lib/auth/session";
import { env } from "@/lib/env";
import { AgentError, downloadLink, issueEnrolment, revokeEnrolment, setSiteLink } from "@/lib/services/agents";
import { currentWorkspace } from "@/lib/workspace";

const LABEL: Record<(typeof PLATFORMS)[number], string> = {
  "win-msi": "Windows installer",
  "mac-pkg": "Mac installer",
  "linux-deb": "Debian installer",
  "linux-rpm": "Red Hat installer",
};

function go(path: string) {
  return NextResponse.redirect(new URL(path, env().APP_URL), 303);
}

function issued(token: string, enrolmentId: string) {
  const links = PLATFORMS.map((platform) => {
    const href = `/portal/agents/file?token=${downloadLink(enrolmentId, platform)}`;
    return `<li><a href="${href}">${LABEL[platform]}</a></li>`;
  }).join("");
  const html = `<!doctype html><html><head><meta charset="utf-8"><title>Installer token</title></head><body>
<main>
<h1>Copy this token</h1>
<p>This page will not show it again.</p>
<pre>${token}</pre>
<ul>${links}</ul>
<p><a href="/portal/agents">Back to agents</a></p>
</main>
</body></html>`;
  return new NextResponse(html, { status: 200, headers: { "content-type": "text/html; charset=utf-8" } });
}

export async function POST(req: Request) {
  const access = await currentAccess();
  if (!access) return go("/login");
  const ws = await currentWorkspace(access);
  const tenant = ws.tenant ?? access.tenants.find((item) => item.kind === "customer");
  if (!tenant) return go("/portal/agents?error=denied");
  const form = await req.formData();
  const intent = String(form.get("intent") ?? "");
  try {
    if (intent === "link") {
      await setSiteLink(access, tenant.id, String(form.get("siteId") ?? ""), String(form.get("link") ?? ""));
    } else if (intent === "issue") {
      const created = await issueEnrolment(access, tenant.id, String(form.get("siteId") ?? ""));
      return issued(created.token, created.id);
    } else if (intent === "revoke") {
      await revokeEnrolment(access, tenant.id, String(form.get("enrolmentId") ?? ""));
    } else {
      return go("/portal/agents?error=generic");
    }
  } catch (err) {
    if (err instanceof AccessDenied) return go("/portal/agents?error=denied");
    if (err instanceof AgentError) return go(`/portal/agents?error=${err.code}`);
    return go("/portal/agents?error=generic");
  }
  return go("/portal/agents?ok=1");
}
