import { can } from "@/lib/auth/access";
import { requireAccess } from "@/lib/auth/session";
import { agentGroup, PLATFORMS } from "@/lib/agents/download";
import { GUIDE } from "@/lib/agents/guide";
import { agentBoard, downloadLink, linkLabel } from "@/lib/services/agents";
import { currentWorkspace } from "@/lib/workspace";

export const metadata = { title: "Agents" };

const inputCls = "mt-1 w-full min-h-11 rounded-md border border-border bg-transparent px-3 text-base";

const PLATFORM_LABEL: Record<(typeof PLATFORMS)[number], string> = {
  "win-msi": "Windows",
  "mac-pkg": "Mac",
  "linux-deb": "Debian",
  "linux-rpm": "Red Hat",
};

const ERRORS: Record<string, string> = {
  missing: "That place or token is not on this organisation.",
  revoked: "That token is already revoked.",
  expired: "That link has expired.",
  link: "Pick a normal or slow link.",
  denied: "Your role cannot change agent installers.",
  generic: "That did not save. Try again.",
};

function megabytes(bytes: number): string {
  return (bytes / (1024 * 1024)).toFixed(1);
}

export default async function AgentsPage({ searchParams }: { searchParams: Promise<{ error?: string; ok?: string }> }) {
  const ctx = await requireAccess();
  const sp = await searchParams;
  const ws = await currentWorkspace(ctx);
  const candidates = ctx.tenants.filter((tenant) => tenant.kind === "customer" && can(ctx, "asset:read", tenant.id));
  const tenant = candidates.find((item) => item.id === ws.tenant?.id) ?? candidates[0];
  if (!tenant) {
    return (
      <div>
        <h1 className="text-xl font-semibold">Agents</h1>
        <p className="mt-2 text-sm text-muted">Your role cannot view computers.</p>
      </div>
    );
  }
  const board = await agentBoard(ctx, tenant.id);
  const allow = can(ctx, "user:manage", tenant.id);
  const now = board.now;
  const error = sp.error ? ERRORS[sp.error] ?? ERRORS.generic : null;
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold">Agents</h1>
        <p className="mt-2 text-sm">Idle upload on a slow link: {megabytes(board.lowBytes)} MB a day.</p>
        <p className="mt-1 text-sm text-muted">{GUIDE.measure}</p>
      </div>
      {error ? <p className="text-sm" role="alert">{error}</p> : null}
      {sp.ok ? <p className="text-sm">Saved.</p> : null}

      <section className="space-y-3" aria-labelledby="places">
        <h2 id="places" className="text-base font-semibold">Places</h2>
        {board.sites.length === 0 ? <p className="text-sm text-muted">No places yet. They are added during setup.</p> : null}
        {board.sites.map((site) => (
          <form key={site.id} className="space-y-2 border-b border-border pb-3" action="/portal/agents/save" method="post">
            <p className="text-sm font-medium">{site.name}</p>
            <p className="text-sm text-muted">Group {agentGroup(tenant.slug)}. Link: {linkLabel(site.bandwidthProfile === "low" ? "low" : "standard")}.</p>
            {allow ? (
              <>
                <input type="hidden" name="siteId" value={site.id} />
                <label className="block text-sm">Link speed
                  <select className={inputCls} name="link" defaultValue={site.bandwidthProfile}>
                    <option value="standard">Normal link</option>
                    <option value="low">Slow or satellite link</option>
                  </select>
                </label>
                <button className="inline-flex min-h-11 items-center rounded-md border border-border px-3 text-sm" type="submit" name="intent" value="link">Save link</button>
                <button className="inline-flex min-h-11 items-center rounded-md border border-border px-3 text-sm" type="submit" name="intent" value="issue">Create installer token</button>
              </>
            ) : null}
          </form>
        ))}
      </section>

      <section className="space-y-3" aria-labelledby="tokens">
        <h2 id="tokens" className="text-base font-semibold">Installer tokens</h2>
        {board.tokens.length === 0 ? <p className="text-sm text-muted">No tokens yet.</p> : null}
        {board.tokens.map((row) => {
          const dead = row.revokedAt || row.expiresAt.getTime() <= now;
          const place = board.sites.find((site) => site.id === row.siteId);
          return (
            <div key={row.id} className="space-y-2 border-b border-border pb-3">
              <p className="text-sm">{place?.name ?? "Place"} · {dead ? "Not active" : "Active"}</p>
              {!dead && allow ? (
                <ul className="space-y-1 text-sm">
                  {PLATFORMS.map((platform) => (
                    <li key={platform}>
                      <a className="inline-flex min-h-11 items-center underline" href={`/portal/agents/file?token=${downloadLink(row.id, platform, now)}`}>{PLATFORM_LABEL[platform]} installer</a>
                    </li>
                  ))}
                </ul>
              ) : null}
              {!dead && allow ? (
                <form action="/portal/agents/save" method="post">
                  <input type="hidden" name="enrolmentId" value={row.id} />
                  <button className="inline-flex min-h-11 items-center rounded-md border border-border px-3 text-sm" type="submit" name="intent" value="revoke">Revoke token</button>
                </form>
              ) : null}
            </div>
          );
        })}
      </section>

      <section aria-labelledby="tasks">
        <h2 id="tasks" className="text-base font-semibold">Tasks</h2>
        {board.tasks.length === 0 ? <p className="mt-2 text-sm text-muted">No missing computers.</p> : (
          <ul className="mt-2 space-y-1 text-sm">
            {board.tasks.map((task) => <li key={task.id}>{task.hostname} has no sensor yet.</li>)}
          </ul>
        )}
      </section>

      <section aria-labelledby="guide">
        <h2 id="guide" className="text-base font-semibold">{GUIDE.title}</h2>
        <p className="mt-2 text-sm">{GUIDE.lead}</p>
        <ol className="mt-2 list-decimal space-y-2 pl-5 text-sm">
          {GUIDE.steps.map((step) => <li key={step}>{step}</li>)}
        </ol>
        <p className="mt-2 text-sm text-muted">{GUIDE.revoke}</p>
      </section>
    </div>
  );
}
