import { APPLICABILITY_QUESTIONS, DRAFT_KINDS, DRAFT_LABELS, NOT_ADVICE, NOT_REVIEWED, REFERRALS, REFERRAL_LABELS } from "@/lib/obligations/model";
import type { getObligation } from "@/lib/services/obligations";

const inputCls = "mt-1 w-full min-h-11 rounded-md border border-border bg-transparent px-3 text-base";

const ERRORS: Record<string, string> = {
  incomplete: "Answer every applicability question and enter a real start date.",
  rationale: "Write the reason. Keep it under 4000 characters.",
  decision: "Choose a decision.",
  referral: "Choose a referral.",
  policy: "The insurer referral needs a policy number, 80 characters or fewer.",
  draft: "Choose which draft to save.",
  missing: "Start the assessment clock first.",
  exists: "An assessment clock is already running for this incident.",
  generic: "That did not save. Try again.",
};

type View = NonNullable<Awaited<ReturnType<typeof getObligation>>>;

export function ObligationsPanel({ incidentId, view, canWrite, error }: { incidentId: string; view: View | null; canWrite: boolean; error?: string }) {
  const action = `/portal/incidents/${incidentId}/obligations/save`;
  return (
    <section className="space-y-4 border-t border-border pt-4" aria-labelledby="obligations">
      <h2 id="obligations" className="text-base font-semibold">Reporting duties</h2>
      <p className="text-sm">This tracks a 30-day assessment clock. It does not notify the OAIC, the people affected, or anyone else. {NOT_ADVICE}</p>
      <p className="text-sm text-muted">{NOT_REVIEWED} The clock ends 30 days after midnight UTC on the start date you enter. The Privacy Act expects an assessment within 30 calendar days after the day the organisation becomes aware of grounds to suspect an eligible data breach. Check that date with a lawyer if you are unsure.</p>
      {error ? <p className="text-sm text-muted">{ERRORS[error] ?? ERRORS.generic}</p> : null}
      {!view ? <p className="text-sm text-muted">No assessment clock yet.</p> : (
        <div className="space-y-3">
          <p className="text-sm">Started {view.case.startedAt.toISOString().slice(0, 10)}. Due {view.case.dueAt.toISOString().slice(0, 10)}. Legal review: {view.case.legalReview ? "requested" : "not requested"}.</p>
          <p className="text-sm">
            <a className="inline-flex min-h-11 items-center underline" href={`/portal/incidents/${incidentId}/obligations/pdf`}>Download the evidence pack (PDF)</a>
          </p>
          <ul className="space-y-1 text-sm">
            {APPLICABILITY_QUESTIONS.map((question) => (
              <li key={question.key}>{question.label} {view.case.applicability[question.key]}.</li>
            ))}
          </ul>
          <p className="text-sm">Serious harm: {view.case.seriousHarm ?? "not recorded"}.{view.case.seriousHarmBy ? ` ${view.case.seriousHarmBy} at ${view.case.seriousHarmAt?.toISOString().slice(0, 16)}.` : ""}</p>
          {view.case.seriousHarmRationale ? <p className="text-sm text-muted">{view.case.seriousHarmRationale}</p> : null}
          <p className="text-sm">Decision: {view.case.decision ?? "not recorded"}.{view.case.decisionBy ? ` ${view.case.decisionBy} at ${view.case.decisionAt?.toISOString().slice(0, 16)}.` : ""}</p>
          {view.case.decisionRationale ? <p className="text-sm text-muted">{view.case.decisionRationale}</p> : null}
          <h3 className="text-sm font-semibold">Referrals</h3>
          <ul className="space-y-1 text-sm">
            {REFERRALS.map((key) => {
              const mark = view.case.referrals[key];
              return <li key={key}>{REFERRAL_LABELS[key]}: {mark ? `marked by ${mark.byName} at ${mark.at.slice(0, 16)}${mark.policyNumber ? `, policy ${mark.policyNumber}` : ""}.` : "not marked."}</li>;
            })}
          </ul>
          <h3 className="text-sm font-semibold">Clock reminders</h3>
          {view.reminders.length === 0 ? <p className="text-sm text-muted">No reminder sent yet. Reminders use the escalation steps for this severity.</p> : (
            <ul className="space-y-1 text-sm">
              {view.reminders.map((row) => <li key={`${row.key}-${row.at}`}>Day {row.key}: {row.status} by {row.channel} to {row.destination} at {row.at.slice(0, 16)}.</li>)}
            </ul>
          )}
          <h3 className="text-sm font-semibold">Drafts</h3>
          {view.drafts.length === 0 ? <p className="text-sm text-muted">No drafts. Saving a draft does not send it.</p> : view.drafts.map((draft) => (
            <article key={draft.id} className="space-y-1">
              <h4 className="text-sm font-semibold">{DRAFT_LABELS[draft.kind as keyof typeof DRAFT_LABELS] ?? draft.kind}. Not sent. {draft.authorName} at {draft.createdAt.toISOString().slice(0, 16)}.</h4>
              <pre className="whitespace-pre-wrap text-sm">{draft.body}</pre>
            </article>
          ))}
          <h3 className="text-sm font-semibold">Decisions on the timeline</h3>
          <ul className="space-y-1 text-sm">
            {view.events.map((event) => <li key={event.id}>{event.occurredAt.toISOString().slice(0, 16)} {event.title}. {event.detail}</li>)}
          </ul>
        </div>
      )}
      {canWrite && !view ? (
        <form className="space-y-3" action={action} method="post">
          <input type="hidden" name="intent" value="start" />
          <label className="block text-sm">Day you became aware
            <input className={inputCls} name="startedAt" type="date" required />
          </label>
          {APPLICABILITY_QUESTIONS.map((question) => (
            <label key={question.key} className="block text-sm">{question.label}
              <select className={inputCls} name={question.key} required defaultValue="">
                <option value="" disabled>Choose</option>
                <option value="yes">Yes</option>
                <option value="no">No</option>
                <option value="unsure">Unsure</option>
              </select>
            </label>
          ))}
          <label className="block text-sm">Cyber insurer policy number, if you have one
            <input className={inputCls} name="insurerPolicy" maxLength={80} />
          </label>
          <button className="inline-flex min-h-11 items-center rounded-md border border-border px-4 text-sm" type="submit">Start the 30-day clock</button>
        </form>
      ) : null}
      {canWrite && view ? (
        <div className="space-y-6">
          <form className="space-y-3" action={action} method="post">
            <input type="hidden" name="intent" value="harm" />
            <label className="block text-sm">Is serious harm likely?
              <select className={inputCls} name="seriousHarm" required defaultValue={view.case.seriousHarm ?? "unsure"}>
                <option value="yes">Yes</option>
                <option value="no">No</option>
                <option value="unsure">Unsure</option>
              </select>
            </label>
            <label className="block text-sm">Why?
              <textarea className={inputCls} name="rationale" required maxLength={4000} defaultValue={view.case.seriousHarmRationale ?? ""} />
            </label>
            <button className="inline-flex min-h-11 items-center rounded-md border border-border px-4 text-sm" type="submit">Save serious-harm note</button>
          </form>
          <form className="space-y-3" action={action} method="post">
            <input type="hidden" name="intent" value="decision" />
            <label className="block text-sm">Decision
              <select className={inputCls} name="decision" required defaultValue={view.case.decision ?? "assessing"}>
                <option value="assessing">Still assessing</option>
                <option value="eligible">Eligible data breach</option>
                <option value="not_eligible">Not an eligible data breach</option>
              </select>
            </label>
            <label className="block text-sm">Reason
              <textarea className={inputCls} name="rationale" required maxLength={4000} defaultValue={view.case.decisionRationale ?? ""} />
            </label>
            <button className="inline-flex min-h-11 items-center rounded-md border border-border px-4 text-sm" type="submit">Save decision</button>
          </form>
          <form className="space-y-3" action={action} method="post">
            <input type="hidden" name="intent" value="referral" />
            <label className="block text-sm">Referral
              <select className={inputCls} name="key" required defaultValue="reportcyber">
                {REFERRALS.map((key) => <option key={key} value={key}>{REFERRAL_LABELS[key]}</option>)}
              </select>
            </label>
            <label className="block text-sm">Policy number, required for the insurer
              <input className={inputCls} name="policyNumber" maxLength={80} defaultValue={view.case.insurerPolicy ?? ""} />
            </label>
            <button className="inline-flex min-h-11 items-center rounded-md border border-border px-4 text-sm" type="submit">Mark referral</button>
          </form>
          <form className="space-y-3" action={action} method="post">
            <input type="hidden" name="intent" value="draft" />
            <label className="block text-sm">Draft
              <select className={inputCls} name="kind" required defaultValue="oaic">
                {DRAFT_KINDS.map((kind) => <option key={kind} value={kind}>{DRAFT_LABELS[kind]}</option>)}
              </select>
            </label>
            <button className="inline-flex min-h-11 items-center rounded-md border border-border px-4 text-sm" type="submit">Save draft</button>
          </form>
          <form action={action} method="post">
            <input type="hidden" name="intent" value="legal" />
            <input type="hidden" name="requested" value={view.case.legalReview ? "no" : "yes"} />
            <button className="inline-flex min-h-11 items-center rounded-md border border-border px-4 text-sm" type="submit">{view.case.legalReview ? "Clear legal-review flag" : "Request legal review"}</button>
          </form>
        </div>
      ) : null}
      {!canWrite ? <p className="text-sm text-muted">A customer administrator can update this assessment.</p> : null}
    </section>
  );
}
