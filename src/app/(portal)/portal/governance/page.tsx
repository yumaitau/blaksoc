import { requireAccess } from "@/lib/auth/session";
import { diffProfile } from "@/lib/governance/policy";
import { governanceView } from "@/lib/services/governance";
import { currentWorkspace } from "@/lib/workspace";

export const metadata = { title: "Data rules" };

const inputCls = "mt-1 w-full min-h-11 rounded-md border border-border bg-transparent px-3 text-base";
const buttonCls = "inline-flex min-h-11 items-center rounded-md border border-border px-3";

const ERRORS: Record<string, string> = {
  invalid: "Fill in every choice and give a reason.",
  unchanged: "That is the same as the rules in force now.",
  closed: "That change is already decided.",
  self: "Another steward must approve a change you asked for.",
  twice: "You already approved that change.",
  denied: "Only a data steward for this organisation can change these rules.",
  generic: "That did not save. Try again.",
};

const OK: Record<string, string> = {
  applied: "The new rules are in force. Every steward was told.",
  waiting: "Saved. A second steward must approve it before it takes effect.",
  rejected: "The change was rejected. Every steward was told.",
  saved: "Saved.",
};

const TLPS = ["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"] as const;

export default async function GovernancePage({ searchParams }: { searchParams: Promise<{ error?: string; ok?: string }> }) {
  const ctx = await requireAccess();
  const sp = await searchParams;
  const ws = await currentWorkspace(ctx);
  const tenant = ctx.tenants.find((item) => item.id === ws.tenant?.id && item.kind === "customer") ?? ctx.tenants.find((item) => item.kind === "customer");
  if (!tenant) {
    return (
      <div>
        <h1 className="text-xl font-semibold">Data rules</h1>
        <p className="mt-2 text-sm text-muted">No organisation to show.</p>
      </div>
    );
  }
  const view = await governanceView(ctx, tenant.id);
  const p = view.profile;
  const pending = view.changes.filter((c) => c.status === "pending");
  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-xl font-semibold">Data rules</h1>
        <p className="mt-2 text-sm">These rules are checked by blakSOC every time your data could leave the platform.</p>
        {sp.error ? <p className="mt-2 text-sm" role="alert">{ERRORS[sp.error] ?? ERRORS.generic}</p> : null}
        {sp.ok ? <p className="mt-2 text-sm">{OK[sp.ok] ?? OK.saved}</p> : null}
      </header>

      <section className="space-y-2">
        <h2 className="text-lg font-semibold">In force now</h2>
        <ul className="list-disc space-y-1 pl-5 text-base">
          {view.sentences.map((line) => <li key={line}>{line}</li>)}
        </ul>
        <p className="text-sm text-muted">
          {view.stewards === 0 ? "This organisation has no data stewards yet. Ask Yuma IT to add one." : `${view.stewards} data steward${view.stewards === 1 ? "" : "s"}. ${view.stewards >= 2 ? "Two stewards must agree to any change." : "One steward can make a change."}`}
        </p>
        <p className="text-sm text-muted">The Indigenous advisory group has not reviewed these rules yet.</p>
      </section>

      {pending.length ? (
        <section className="space-y-3 border-t border-border pt-4">
          <h2 className="text-lg font-semibold">Waiting for a second steward</h2>
          {pending.map((c) => (
            <div key={c.id} className="space-y-2">
              <p className="text-base">{diffProfile(c.before, c.after).join("; ")}.</p>
              <p className="text-sm text-muted">Reason: {c.reason}</p>
              {view.steward ? (
                <div className="flex flex-wrap gap-2">
                  <form action="/portal/governance/save" method="post">
                    <input type="hidden" name="intent" value="approve" />
                    <input type="hidden" name="changeId" value={c.id} />
                    <button className={buttonCls} type="submit">Approve</button>
                  </form>
                  <form action="/portal/governance/save" method="post">
                    <input type="hidden" name="intent" value="reject" />
                    <input type="hidden" name="changeId" value={c.id} />
                    <button className={buttonCls} type="submit">Reject</button>
                  </form>
                </div>
              ) : null}
            </div>
          ))}
        </section>
      ) : null}

      {view.steward ? (
        <form className="space-y-3 border-t border-border pt-4" action="/portal/governance/save" method="post">
          <input type="hidden" name="intent" value="propose" />
          <h2 className="text-lg font-semibold">Ask for a change</h2>
          <label className="flex min-h-11 items-center gap-2 text-base">
            <input type="checkbox" name="residencyLock" defaultChecked={p.residencyLock} /> Keep all data in Australia
          </label>
          <label className="flex min-h-11 items-center gap-2 text-base">
            <input type="checkbox" name="aiAssistant" defaultChecked={p.ai.assistant} /> Let the SOC analyst assistant use AI on our data
          </label>
          <label className="flex min-h-11 items-center gap-2 text-base">
            <input type="checkbox" name="aiTriage" defaultChecked={p.ai.triage_summary} /> Let AI write alert summaries
          </label>
          <label className="block text-sm" htmlFor="gov-sightings">Threat sightings</label>
          <select className={inputCls} id="gov-sightings" name="sightings" defaultValue={p.sightings?.attribution ?? "none"}>
            <option value="none">Share nothing</option>
            <option value="anonymised">Share without our name</option>
            <option value="named">Share with our name</option>
          </select>
          <label className="block text-sm" htmlFor="gov-tlp">Highest marking for anything shared</label>
          <select className={inputCls} id="gov-tlp" name="maxTlp" defaultValue={p.sightings?.maxTlp ?? "TLP:GREEN"}>
            {TLPS.map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
          <label className="block text-sm" htmlFor="gov-reason">Why</label>
          <textarea className={inputCls} id="gov-reason" name="reason" rows={2} required maxLength={500} />
          <button className={buttonCls} type="submit">Ask for this change</button>
        </form>
      ) : null}

      {view.changes.length ? (
        <section className="space-y-2 border-t border-border pt-4">
          <h2 className="text-lg font-semibold">History</h2>
          <ul className="space-y-1 text-sm">
            {view.changes.map((c) => (
              <li key={c.id}>{c.createdAt.toISOString().slice(0, 16).replace("T", " ")} {c.status}: {diffProfile(c.before, c.after).join("; ")}</li>
            ))}
          </ul>
        </section>
      ) : null}
    </div>
  );
}
