import { ActionForm } from "@/components/soc/action-form";
import { can } from "@/lib/auth/access";
import { requireAccess } from "@/lib/auth/session";
import { AWARENESS_LESSONS, AWARENESS_REVIEW } from "@/lib/awareness/lessons";
import { latestCampaign, listCoaching } from "@/lib/services/awareness";
import { currentWorkspace } from "@/lib/workspace";
import { schedulePractice } from "./actions";

export const metadata = { title: "Awareness" };

const inputCls = "mt-1 w-full min-h-11 rounded-md border border-border bg-transparent px-3 text-base";

export default async function AwarenessPage() {
  const ctx = await requireAccess();
  const ws = await currentWorkspace(ctx);
  const candidates = ctx.tenants.filter((tenant) => tenant.kind === "customer" && can(ctx, "user:manage", tenant.id));
  const tenant = candidates.find((item) => item.id === ws.tenant?.id) ?? candidates[0];
  if (!tenant) {
    return (
      <div>
        <h1 className="text-xl font-semibold">Awareness</h1>
        <p className="mt-2 text-sm text-muted">Your role cannot schedule a practice send.</p>
      </div>
    );
  }
  const latest = await latestCampaign(ctx, tenant.id);
  const coaching = await listCoaching(ctx, tenant.id);
  const when = latest ? `${latest.scheduledAt.toISOString().slice(0, 16).replace("T", " ")} UTC` : null;

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-xl font-semibold">Awareness</h1>
        <p className="mt-2 text-sm">You choose if a practice send runs, and when. Nothing is sent from this page.</p>
        <p className="mt-2 text-sm text-muted">{AWARENESS_REVIEW}</p>
      </header>
      <p className="text-sm">{when ? `Scheduled: ${when}.` : "No practice send scheduled."}</p>
      <ActionForm action={schedulePractice} success="Practice send scheduled" className="space-y-3">
        <input type="hidden" name="tenantId" value={tenant.id} />
        <label className="flex min-h-11 items-center gap-2 text-sm">
          <input className="size-4" type="checkbox" name="consented" value="yes" />
          I consent to a practice send for this group
        </label>
        <label className="block text-sm">When
          <input className={inputCls} type="datetime-local" name="scheduledAt" required />
        </label>
        <button className="inline-flex min-h-11 items-center rounded-md bg-accent px-4 font-medium text-accent-fg" type="submit">Save schedule</button>
      </ActionForm>
      <section className="space-y-3">
        <h2 className="text-base font-medium">Lessons</h2>
        {AWARENESS_LESSONS.map((lesson) => (
          <article key={lesson.id} className="rounded-lg border border-border p-3">
            <h3 className="font-medium">{lesson.title}</h3>
            <p className="mt-1 text-sm text-muted">{lesson.body}</p>
          </article>
        ))}
      </section>
      <section className="space-y-2">
        <h2 className="text-base font-medium">Coaching</h2>
        <p className="text-sm">{coaching.length ? `Coaching: ${coaching.map((row) => row.person).join(", ")}` : "No coaching task yet."}</p>
      </section>
    </div>
  );
}
