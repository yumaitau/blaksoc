import { can } from "@/lib/auth/access";
import { requireAccess } from "@/lib/auth/session";
import { DISCLAIMER, MODEL_NOTE, questionGroups } from "@/lib/essential-eight/requirements";
import { latestEssentialEight } from "@/lib/services/essential-eight";
import { currentWorkspace } from "@/lib/workspace";

export const metadata = { title: "Essential Eight" };

const inputCls = "mt-1 w-full min-h-11 rounded-md border border-border bg-transparent px-3 text-base";

const ERRORS: Record<string, string> = {
  incomplete: "Answer every question.",
  owner: "Name the person who owns the plan.",
  cadence: "Choose how often you will run this again.",
  denied: "Your role cannot run this self-assessment.",
  generic: "That did not save. Try again.",
};

export default async function EssentialEightPage({ searchParams }: { searchParams: Promise<{ error?: string }> }) {
  const ctx = await requireAccess();
  const sp = await searchParams;
  const ws = await currentWorkspace(ctx);
  const candidates = ctx.tenants.filter((tenant) => tenant.kind === "customer" && can(ctx, "report:generate", tenant.id));
  const tenant = candidates.find((item) => item.id === ws.tenant?.id) ?? candidates[0];
  if (!tenant) {
    return (
      <div>
        <h1 className="text-xl font-semibold">Essential Eight</h1>
        <p className="mt-2 text-sm text-muted">Your role cannot run this self-assessment.</p>
      </div>
    );
  }
  const latest = await latestEssentialEight(ctx, tenant.id);
  const groups = questionGroups();
  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-xl font-semibold">Essential Eight</h1>
        <p className="mt-2 text-sm">{DISCLAIMER}</p>
        <p className="mt-2 text-sm text-muted">{MODEL_NOTE}</p>
      </header>
      {sp.error ? <p className="text-sm text-muted">{ERRORS[sp.error] ?? ERRORS.generic}</p> : null}
      {latest ? (
        <section className="space-y-4">
          <h2 className="text-base font-semibold">Latest indicative result</h2>
          <p className="text-sm text-muted">
            Assessed {latest.result.assessedAt.slice(0, 10)}. Next due {latest.result.nextDue.slice(0, 10)}. Owner {latest.result.owner}.
          </p>
          <p className="text-sm">
            <a className="inline-flex min-h-11 items-center underline" href={`/portal/essential-eight/pdf?tenant=${tenant.id}&id=${latest.id}`}>Download the remediation plan (PDF)</a>
          </p>
          {latest.result.ratings.map((rating) => (
            <section key={rating.strategy} className="space-y-2">
              <h3 className="text-base font-semibold">{rating.label}: ML{rating.level}</h3>
              <p className="text-sm text-muted">{rating.telemetry}</p>
              <p className="text-sm text-muted">Change since last time: {latest.result.trend[rating.strategy]}.</p>
              <ul className="space-y-2">
                {rating.lines.map((line) => (
                  <li key={line.id} className="text-sm">
                    <span>ML{line.minLevel}. {line.text}</span>
                    <span className="block text-muted">Answer: {line.answer}. Met: {line.met ? "yes" : "no"}. Evidence: {line.evidence.detail}</span>
                  </li>
                ))}
              </ul>
            </section>
          ))}
          <h3 className="text-base font-semibold">Remediation tasks</h3>
          {latest.result.remediation.length === 0 ? <p className="text-sm text-muted">No gaps at the level that failed.</p> : (
            <ul className="space-y-2">
              {latest.result.remediation.map((item) => (
                <li key={item.requirementId} className="text-sm">{item.title} Owner {item.owner}. Due {item.dueAt.slice(0, 10)}. Priority {item.priority}.</li>
              ))}
            </ul>
          )}
        </section>
      ) : <p className="text-sm text-muted">No self-assessment yet.</p>}
      <form className="space-y-6" action="/portal/essential-eight/save" method="post">
        <input type="hidden" name="tenantId" value={tenant.id} />
        <label className="block text-sm">
          Who owns the remediation plan?
          <input className={inputCls} name="owner" required maxLength={200} />
        </label>
        <label className="block text-sm">
          How often will you run this again?
          <select className={inputCls} name="cadenceDays" defaultValue="90">
            <option value="90">Every 90 days</option>
            <option value="180">Every 180 days</option>
            <option value="365">Every 365 days</option>
          </select>
        </label>
        {groups.map((group) => (
          <section key={group.id} className="space-y-3">
            <h2 className="text-base font-semibold">{group.title}</h2>
            <p className="text-sm text-muted">{group.note}</p>
            {group.questions.map((question) => (
              <fieldset key={question.answerId} className="space-y-1 border-t border-border pt-3">
                <legend className="text-sm">{question.text}</legend>
                <p className="text-sm text-muted">Needed for ML{question.minLevel}.</p>
                <label className="mr-4 inline-flex min-h-11 items-center gap-2 text-sm">
                  <input type="radio" name={question.answerId} value="yes" required /> Yes
                </label>
                <label className="inline-flex min-h-11 items-center gap-2 text-sm">
                  <input type="radio" name={question.answerId} value="no" required /> No
                </label>
              </fieldset>
            ))}
          </section>
        ))}
        <button className="inline-flex min-h-11 items-center rounded-md border border-border px-4 text-sm" type="submit">Save self-assessment</button>
      </form>
    </div>
  );
}
