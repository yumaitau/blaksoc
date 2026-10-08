import { ActionForm } from "@/components/soc/action-form";
import { can } from "@/lib/auth/access";
import { requireAccess } from "@/lib/auth/session";
import { IR_SCENARIOS } from "@/lib/ir/scenarios";
import { latestIrPlan, listRecordedExercises } from "@/lib/services/ir";
import { currentWorkspace } from "@/lib/workspace";
import { finishExercise, savePlan } from "./actions";

export const metadata = { title: "Response plan" };

const inputCls = "mt-1 w-full min-h-11 rounded-md border border-border bg-transparent px-3 text-base";

export default async function ResponsePlanPage() {
  const ctx = await requireAccess();
  const ws = await currentWorkspace(ctx);
  const candidates = ctx.tenants.filter((tenant) => tenant.kind === "customer" && can(ctx, "report:generate", tenant.id));
  const tenant = candidates.find((item) => item.id === ws.tenant?.id) ?? candidates[0];
  if (!tenant) {
    return (
      <div>
        <h1 className="text-xl font-semibold">Response plan</h1>
        <p className="mt-2 text-sm text-muted">Your role cannot write this plan.</p>
      </div>
    );
  }
  const latest = await latestIrPlan(ctx, tenant.id);
  const recorded = await listRecordedExercises(ctx, tenant.id);

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-xl font-semibold">Response plan</h1>
        <p className="mt-2 text-sm">Write the people and numbers your group would call. Export a version when it changes.</p>
        <p className="mt-2 text-sm text-muted">This plan has not been reviewed by an advisory group.</p>
      </header>
      <p className="text-sm">Current version: {latest ? latest.version : "none"}.</p>
      {latest ? (
        <p className="text-sm">
          <a className="underline" href={`/portal/ir/export?tenant=${tenant.id}&version=${latest.version}&format=pdf`}>Download PDF</a>
          {" and "}
          <a className="underline" href={`/portal/ir/export?tenant=${tenant.id}&version=${latest.version}&format=docx`}>Download Word</a>
        </p>
      ) : null}
      <ActionForm action={savePlan} success="Response plan saved as a new version" className="space-y-3">
        <input type="hidden" name="tenantId" value={tenant.id} />
        <label className="block text-sm">Who speaks to community
          <input className={inputCls} name="culturalProtocol" defaultValue={latest?.culturalProtocol ?? ""} />
        </label>
        <label className="block text-sm">Bank
          <input className={inputCls} name="bank" defaultValue={latest?.bank ?? ""} />
        </label>
        <label className="block text-sm">Insurer
          <input className={inputCls} name="insurer" defaultValue={latest?.insurer ?? ""} />
        </label>
        <label className="block text-sm">IT provider
          <input className={inputCls} name="itProvider" defaultValue={latest?.itProvider ?? ""} />
        </label>
        <button className="inline-flex min-h-11 items-center rounded-md bg-accent px-4 font-medium text-accent-fg" type="submit">Save version</button>
      </ActionForm>
      <section className="space-y-3">
        <h2 className="text-base font-medium">Tabletop exercises</h2>
        <p className="text-sm">{recorded.length ? `Recorded: ${recorded.join(", ")}` : "No exercise recorded yet."}</p>
        {IR_SCENARIOS.map((scenario) => (
          <article key={scenario.id} className="rounded-lg border border-border p-3">
            <h3 className="font-medium">{scenario.title}</h3>
            <p className="mt-1 text-sm text-muted">{scenario.summary}</p>
            <ol className="mt-2 list-decimal space-y-1 pl-5 text-sm">
              {scenario.injects.map((inject) => <li key={inject.minute}>{inject.minute} min. {inject.text}</li>)}
            </ol>
            <ul className="mt-2 list-disc space-y-1 pl-5 text-sm">
              {scenario.prompts.map((prompt) => <li key={prompt}>{prompt}</li>)}
            </ul>
            <ActionForm action={finishExercise} success={`${scenario.title} recorded`} reset className="mt-3 space-y-2">
              <input type="hidden" name="tenantId" value={tenant.id} />
              <input type="hidden" name="scenarioId" value={scenario.id} />
              <label className="block text-sm">What you learned
                <input className={inputCls} name="lessons" />
              </label>
              <button className="inline-flex min-h-11 items-center rounded-md bg-accent px-4 font-medium text-accent-fg" type="submit">Record exercise</button>
            </ActionForm>
          </article>
        ))}
      </section>
    </div>
  );
}
